// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serialport::{DataBits, FlowControl, Parity, StopBits};
use slog::{debug, info, o, trace, Drain, Level, Logger};
use slog_async::AsyncGuard;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use zerocopy::FromBytes;

use attest_data::{
    messages::{HostToRotCommand, RotToHost},
    Log,
};
use host_sp_messages::{Header, HostToSp, SpToHost, MAGIC, MAX_MESSAGE_SIZE};
use ipcc_data::BootSpHeader;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Prings the current SP status
    Status,
    /// Reads a host phase2 image
    ReadImage {
        #[clap(long, value_parser = parse_hash)]
        hash: [u8; 32],
    },
    /// Prints the certificate chain from the RoT
    GetCerts,
    /// Prints the measurement log from the RoT
    GetLog,
    /// Reads a value from the active APOB slot (if available)
    ApobRead {
        #[clap(long)]
        offset: u64,
        #[clap(long, short = 'N')]
        size: u64,
    },
    /// Writes a file to APOB flash
    ApobWrite {
        #[clap(long, short)]
        file: PathBuf,
    },
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the serial port
    #[clap(long, env)]
    port: PathBuf,

    /// Log level
    #[clap(value_enum, short, long, default_value_t = LogLevel::Info)]
    log_level: LogLevel,

    /// Write logs to a file instead of stderr.
    #[clap(long)]
    logfile: Option<PathBuf>,

    /// Tweak FTDI timeouts for faster communication
    #[clap(long)]
    ftdi_tweak: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl From<LogLevel> for Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => Level::Trace,
            LogLevel::Debug => Level::Debug,
            LogLevel::Info => Level::Info,
            LogLevel::Warning => Level::Warning,
            LogLevel::Error => Level::Error,
            LogLevel::Critical => Level::Critical,
        }
    }
}

fn build_logger(
    level: Level,
    path: Option<&Path>,
) -> Result<(Logger, AsyncGuard)> {
    fn make_drain<D: slog_term::Decorator + Send + 'static>(
        level: Level,
        decorator: D,
    ) -> (slog::Fuse<slog_async::Async>, AsyncGuard) {
        let drain = slog_term::FullFormat::new(decorator)
            .build()
            .filter_level(level)
            .fuse();
        let (drain, guard) = slog_async::Async::new(drain).build_with_guard();
        (drain.fuse(), guard)
    }

    let (drain, guard) = if let Some(path) = path {
        let file = std::fs::File::create(path).with_context(|| {
            format!("failed to create logfile {}", path.display())
        })?;
        make_drain(level, slog_term::PlainDecorator::new(file))
    } else {
        make_drain(level, slog_term::TermDecorator::new().build())
    };

    Ok((Logger::root(drain, o!()), guard))
}

fn parse_hash(s: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(s).with_context(|| format!("Invalid hex string: {s}"))?;
    if bytes.len() != 32 {
        bail!(
            "expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        );
    }
    Ok(bytes.try_into().unwrap())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (log, _guard) =
        build_logger(args.log_level.into(), args.logfile.as_deref())?;

    if args.ftdi_tweak {
        let mut device = ftdi::find_by_vid_pid(0x0403, 0x6001)
            .interface(ftdi::Interface::A)
            .open()?;
        let prev = device.latency_timer()?;
        device.set_latency_timer(1)?;
        info!(log, "set latency timer {prev} -> 1");
    }

    let mut worker = Worker::new(&args.port, log.clone())?;
    match args.command {
        Command::Status => worker.get_status(),
        Command::ReadImage { hash } => {
            let image = worker.read_image(hash)?;
            info!(log, "got {} bytes of image data", image.len());
            Ok(())
        }

        Command::GetCerts => {
            let cert_chain_bytes = worker.rot_command(
                HostToRotCommand::GetCertificates,
                RotToHost::RotCertificates,
                |_| 0,
            )?;
            use x509_cert::{
                der::{self, Decode, Encode, Reader},
                Certificate,
            };
            // Incrementally parse the chain of DER-encoded certificates
            let mut cert_chain_bytes = cert_chain_bytes.as_slice();
            while !cert_chain_bytes.is_empty() {
                let reader = der::SliceReader::new(cert_chain_bytes)?;
                let header = reader.peek_header()?;

                // Total len = length from the sequence plus the tag itself
                let seq_len: usize = header.length.try_into()?;
                let tag_len: usize = header.encoded_len()?.try_into()?;
                let end = seq_len + tag_len;
                let (cert, rest) = cert_chain_bytes.split_at(end);

                let cert = Certificate::from_der(cert)?;
                info!(log, "Certificate => {}", cert.tbs_certificate.subject);
                debug!(log, "Full certificate => {cert:?}");
                cert_chain_bytes = rest;
            }
            Ok(())
        }
        Command::GetLog => {
            let measurement_log = worker.rot_command(
                HostToRotCommand::GetMeasurementLog,
                RotToHost::RotMeasurementLog,
                |_| 0,
            )?;
            debug!(log, "got raw log {measurement_log:02x?}");
            let (m, _rest): (Log, _) = hubpack::deserialize(&measurement_log)?;
            info!(
                log,
                "got measurement log with {} entr{}",
                m.len(),
                if m.len() > 1 { "ies" } else { "y" }
            );
            for i in 0..m.len() {
                info!(log, "  {i}: {:?}", m[i]);
            }
            Ok(())
        }
        Command::ApobRead { offset, size } => {
            let (response, data) =
                worker.send_recv(HostToSp::ApobRead { offset, size }, |_| 0)?;
            let SpToHost::ApobRead(r) = response else {
                bail!("invalid response: expected ApobRead, got {response:?}");
            };
            if !matches!(r, host_sp_messages::ApobReadResult::Ok) {
                bail!("got error from APOB read: {r:?}");
            };
            let d = Dumper::new();
            d.dump(&data, u32::try_from(offset).unwrap());
            Ok(())
        }
        Command::ApobWrite { file } => {
            let data = std::fs::read(&file)
                .with_context(|| format!("failed to read {file:?}"))?;
            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            hasher.update(&data);
            let hash = hasher.finalize();
            let hash = hash.as_slice();
            let (r, _) = worker.send_recv(
                HostToSp::ApobBegin {
                    length: data.len().try_into().unwrap(),
                    algorithm: 0u8,
                },
                |buf| {
                    buf[..hash.len()].copy_from_slice(hash);
                    hash.len()
                },
            )?;
            let SpToHost::ApobBegin(r) = r else {
                bail!("invalid response: expected ApobBegin, got {r:?}");
            };
            if !matches!(r, host_sp_messages::ApobBeginResult::Ok) {
                bail!("got error from APOB begin: {r:?}");
            };
            let mut offset = 0;
            for chunk in data.chunks(2048) {
                debug!(log, "writing chunk at offset {offset}");
                worker.send_recv(
                    HostToSp::ApobData {
                        offset: offset.try_into().unwrap(),
                    },
                    |buf| {
                        buf[..chunk.len()].copy_from_slice(chunk);
                        chunk.len()
                    },
                )?;
                offset += chunk.len();
            }
            let r = worker.send(HostToSp::ApobCommit)?;
            let SpToHost::ApobCommit(r) = r else {
                bail!("invalid response: expected ApobCommit, got {r:?}");
            };
            if !matches!(r, host_sp_messages::ApobCommitResult::Ok) {
                bail!("got error from APOB commit: {r:?}");
            };
            Ok(())
        }
    }
}

struct Worker {
    log: Logger,
    port: Box<dyn serialport::SerialPort>,
    sequence: u64,
}

impl Worker {
    fn new(port_path: &Path, log: Logger) -> Result<Self> {
        let Some(port_name) = port_path.to_str() else {
            bail!("could not parse port name from {:?}", port_path);
        };
        info!(log, "connecting to serial port at `{port_name}`");
        let port = serialport::new(port_name, 3_000_000)
            .timeout(Duration::from_millis(200))
            .data_bits(DataBits::Eight)
            .flow_control(FlowControl::None)
            .parity(Parity::None)
            .stop_bits(StopBits::One)
            .open()
            .unwrap();
        Ok(Self {
            log,
            port,
            sequence: 1,
        })
    }

    fn get_status(&mut self) -> Result<()> {
        let (reply, _data) = self.send_recv(HostToSp::GetStatus, |_| 0)?;
        info!(self.log, "got status {reply:?}");
        Ok(())
    }

    fn read_image(&mut self, hash: [u8; 32]) -> Result<Vec<u8>> {
        self.get_status()?;
        let mut offset = 0;
        let mut data_size: Option<u64> = None;
        let mut data = vec![];
        let mut last_speed_print = 0;
        let mut retry_count = 0;
        let start_time = std::time::Instant::now();

        while data_size.is_none_or(|s| offset < s) {
            debug!(self.log, "getting image chunk at offset {offset}");

            let mut r = Err(anyhow!("")); // initialize to a dummy value
            const RETRY_COUNT: usize = 10;
            for i in 0..RETRY_COUNT {
                r = self
                    .send_recv(HostToSp::GetPhase2Data { hash, offset }, |_| 0);
                match &r {
                    Ok(..) => break,
                    Err(e) => {
                        self.port.clear(serialport::ClearBuffer::All)?;
                        if i > RETRY_COUNT {
                            // Add delays if fast retries have failed
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        debug!(self.log, "got error {e:?}");
                        retry_count += 1;
                    }
                }
            }
            let Ok((reply, chunk)) = r else {
                bail!("got too many errors");
            };

            if !matches!(reply, SpToHost::Phase2Data) {
                bail!("got unexpected reply {reply:?}");
            }
            debug!(self.log, "got {} bytes at offset {offset}", chunk.len());
            offset += chunk.len() as u64;
            data.extend(chunk);

            // Periodically print the transfer speed
            let mib = data.len() / (1024 * 1024);
            if mib > last_speed_print {
                last_speed_print = mib;
                let speed =
                    data.len() as f64 / start_time.elapsed().as_secs_f64();
                if let Some(size) = data_size {
                    let eta_secs = (size as f64 - data.len() as f64) / speed;
                    let eta = Duration::from_secs(eta_secs as u64);
                    info!(
                        self.log,
                        "{mib} / {} MiB, {:.2} KiB/sec, ETA {} ({} retries)",
                        size / (1024 * 1024),
                        speed / 1024.0,
                        humantime::format_duration(eta),
                        retry_count,
                    );
                } else {
                    info!(self.log, "{:.2} KiB/sec", speed / 1024.0);
                }
            }

            // Parse and check the image header to get image size
            if data_size.is_none()
                && data.len() >= std::mem::size_of::<BootSpHeader>()
            {
                let (header, _) = BootSpHeader::ref_from_prefix(&data).unwrap();
                info!(self.log, "got boot header");
                if header.magic != BootSpHeader::MAGIC {
                    bail!(
                        "invalid header magic: expected {:#x}, got {:#x}",
                        BootSpHeader::MAGIC,
                        header.magic
                    );
                } else if header.version != BootSpHeader::VERSION {
                    bail!(
                        "invalid header version: expected {:#x}, got {:#x}",
                        BootSpHeader::VERSION,
                        header.version
                    );
                }
                info!(self.log, "  flags:        {:#x}", header.flags);
                info!(self.log, "  data size:    {:#x}", header.data_size);
                info!(self.log, "  image size:   {:#x}", header.image_size);
                info!(self.log, "  target size:  {:#x}", header.target_size);
                info!(
                    self.log,
                    "  sha256:       {}",
                    hex::encode(header.sha256)
                );
                info!(
                    self.log,
                    "  dataset name: {}",
                    if let Ok(s) = std::str::from_utf8(&header.dataset) {
                        s.to_string()
                    } else {
                        format!("{:02x?}", header.dataset)
                    }
                );
                info!(
                    self.log,
                    "  image name:   {}",
                    if let Ok(s) = std::str::from_utf8(&header.imagename) {
                        s.to_string()
                    } else {
                        format!("{:02x?}", header.imagename)
                    }
                );

                let size = header.data_size + BootSpHeader::HEADER_SIZE as u64;
                debug!(self.log, "setting image size to {size}");
                data_size = Some(size);
            }
        }
        Ok(data)
    }

    /// Sends a message with no data buffers (in either direction)
    fn send(&mut self, message: HostToSp) -> Result<SpToHost> {
        self.send_recv(message, |_| 0)
            .map(|(response, _data)| response)
    }

    /// Sends a message with data buffers
    fn send_recv<F>(
        &mut self,
        message: HostToSp,
        fill: F,
    ) -> Result<(SpToHost, Vec<u8>)>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let header = Header {
            magic: MAGIC,
            version: 0x1,
            sequence: self.sequence,
        };
        self.sequence += 1;

        // Serialize into initial buffer
        let mut buf = [0; MAX_MESSAGE_SIZE];
        let n = host_sp_messages::serialize(&mut buf, &header, &message, fill)
            .context("serialization failed")?;
        trace!(self.log, "hubpack {} {:02x?}", n, &buf[..n]);

        // Perform COBS encoding into a second buffer
        let mut corncob_buf = [0; MAX_MESSAGE_SIZE];
        let n = corncobs::encode_buf(&buf[..n], &mut corncob_buf);
        trace!(self.log, "corncob {} {:02x?}", n, &corncob_buf[..n]);

        self.port
            .write_all(&corncob_buf[..n])
            .context("failed to write message")?;
        self.port.flush().context("failed to flush")?;

        // Read back data
        let mut out = vec![];
        'outer: loop {
            let mut chunk = [0u8; 64];
            let n =
                self.port.read(&mut chunk).context("failed to read byte")?;
            for &b in &chunk[..n] {
                if b == 0 {
                    if !out.is_empty() {
                        out.push(b);
                        break 'outer;
                    }
                } else {
                    out.push(b);
                }
            }
        }
        trace!(self.log, "received {} bytes: {:02x?}", out.len(), out);

        let n = corncobs::decode_buf(out.as_slice(), &mut buf)
            .map_err(|e| anyhow!("corncobs error: {e}"))
            .context("failed to decode COBS data")?;
        trace!(self.log, "decoded {} bytes: {:02x?}", n, &buf[..n]);

        let (rx_header, request, data) =
            host_sp_messages::deserialize::<SpToHost>(&buf[..n])
                .map_err(|e| anyhow!("decode failure: {e:?}"))
                .context("failed to deserialize")?;
        if rx_header.magic != header.magic {
            bail!(
                "bad MAGIC in received header: expected {:#x}, got {:#x}",
                header.magic,
                rx_header.magic
            );
        } else if rx_header.version != header.version {
            bail!(
                "bad version in received header: expected {}, got {}",
                header.version,
                rx_header.version
            );
        } else if rx_header.sequence != header.sequence | (1 << 63) {
            bail!(
                "bad sequence in received header: expected {:#x}, got {:#x}",
                header.sequence | (1 << 63),
                rx_header.version
            );
        }
        Ok((request, data.to_owned()))
    }

    fn rot_command<F>(
        &mut self,
        msg: HostToRotCommand,
        expected: RotToHost,
        fill: F,
    ) -> Result<Vec<u8>>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        debug!(
            self.log,
            "sending RoT message {msg:?}, expecting {expected:?}"
        );
        let mut rot_message = vec![0; 12 + 32];
        let message_len =
            attest_data::messages::serialize(&mut rot_message, &msg, fill)?;

        let (_request, data) = self.send_recv(HostToSp::RotRequest, |buf| {
            buf[..message_len].copy_from_slice(&rot_message[..message_len]);
            message_len
        })?;

        let data = attest_data::messages::parse_response(&data, expected)
            .map_err(|e| anyhow!("parse error: {e:?}"))
            .with_context(|| {
                format!("invalid message type (expected {expected:?})")
            })?;
        trace!(self.log, "got data {data:?}");

        debug!(self.log, "done.");
        Ok(data.to_owned())
    }
}

pub struct Dumper {
    /// Word size, in bytes
    pub size: usize,

    /// Width of memory, in bytes
    pub width: usize,

    /// Address size, in nibbles
    pub addrsize: usize,

    /// Left indentation, in characters
    pub indent: usize,

    /// Left indent should be a hanging indent
    pub hanging: bool,

    /// Print the OpenBoot PROM-style header line
    pub header: bool,

    /// Print the ASCII translation of characters in the right margin
    pub ascii: bool,
}

// Borrowed from `oxidecomputer/humility`
impl Dumper {
    pub fn new() -> Self {
        Self {
            size: 1,
            width: 16,
            addrsize: 8,
            indent: 0,
            hanging: false,
            header: true,
            ascii: true,
        }
    }

    pub fn dump(&self, bytes: &[u8], addr: u32) {
        let size = self.size;
        let width = self.width;
        let mut addr = addr;
        let mut indent = if self.hanging { 0 } else { self.indent };

        let print = |line: &[u8], addr, offs, indent| {
            print!(
                "{:indent$}0x{:0width$x} | ",
                "",
                addr,
                indent = indent,
                width = self.addrsize
            );

            for i in (0..width).step_by(size) {
                if i < offs || i - offs >= line.len() {
                    print!(" {:width$}", "", width = size * 2);
                    continue;
                }

                let slice = &line[i - offs..i - offs + size];

                print!(
                    "{:0width$x} ",
                    match size {
                        1 => u32::from(line[i - offs]),
                        2 => u32::from(u16::from_le_bytes(
                            slice.try_into().unwrap()
                        )),
                        4 => u32::from_le_bytes(slice.try_into().unwrap()),
                        _ => {
                            panic!("invalid size");
                        }
                    },
                    width = size * 2
                );
            }

            if self.ascii {
                print!("| ");

                for i in 0..width {
                    if i < offs || i - offs >= line.len() {
                        print!(" ");
                    } else {
                        let c = line[i - offs] as char;

                        if c.is_ascii() && !c.is_ascii_control() {
                            print!("{}", c);
                        } else {
                            print!(".");
                        }
                    }
                }
            }

            println!();
        };

        let offs = (addr & (width - 1) as u32) as usize;
        addr -= offs as u32;

        //
        // Print out header line, OpenBoot PROM style
        //
        if self.header {
            print!("  {:width$}  ", "", width = indent + self.addrsize);

            for i in (0..width).step_by(size) {
                if i == offs {
                    print!(" {:>width$}", "\\/", width = size * 2);
                } else {
                    print!(" {:>width$x}", i, width = size * 2);
                }
            }

            println!();
            indent = self.indent;
        }

        //
        // Print our first line.
        //
        let lim = std::cmp::min(width - offs, bytes.len());
        print(&bytes[0..lim], addr, offs, indent);
        indent = self.indent;

        if lim < bytes.len() {
            let lines = bytes[lim..].chunks(width);

            for line in lines {
                addr += width as u32;
                print(line, addr, 0, indent);
            }
        }
    }
}

impl Default for Dumper {
    fn default() -> Self {
        Self::new()
    }
}
