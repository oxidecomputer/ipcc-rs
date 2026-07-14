// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ipcc-data
//!
//! This is a crate to allow for the interpretation of SP-opaque data payloads
//! over the inter-processor communications channel (IPCC).  (See [RFD 316]
//! for details of this channel and its mechanics.) Because this crate is
//! designed *only* for those payloads that are opaque to the SP (e.g.,
//! `HSSBootFail`, `HSSPanic`), it is not a `no-std` crate:  it is not
//! designed to be used *in situ* by the SP, but rather in higher level
//! software that must interpret IPCC data payloads -- which is to say, the
//! control plane and [Humility].  For the host-side definitions of the IPCC
//! payloads that this crate interprets, see [`kernel_ipcc.h`].
//!
//! [RFD 316]: https://rfd.shared.oxide.computer/rfd/0316
//! [Humility]: https://github.com/oxidecomputer/humility
//! [`kernel_ipcc.h`]: https://github.com/oxidecomputer/illumos-gate/blob/stlouis/usr/src/uts/oxide/sys/kernel_ipcc.h
//!

use anyhow::{bail, Context, Result};
use binrw::helpers::until_eof;
use binrw::{io::Cursor, BinRead, BinWrite};
use derive_more::{Display, LowerHex};
use indexmap::IndexMap;
use std::convert::{TryFrom, TryInto};

/// The version of the IPCC panic data -- and an indicator of whether this
/// version was able to be determined from the data directly, or had to be
/// inferred due to the presence of [hubris#1554].
///
/// [hubris#1554]: https://github.com/oxidecomputer/hubris/issues/1554
///
#[derive(Debug)]
pub enum PanicDataVersion {
    /// Version was determined
    Determined(u8),

    /// Version had to be inferred
    Inferred(u8),
}

impl PanicDataVersion {
    fn number(&self) -> u8 {
        match self {
            PanicDataVersion::Determined(v) => *v,
            PanicDataVersion::Inferred(v) => *v,
        }
    }
}

impl std::fmt::Display for PanicDataVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.number(),
            match self {
                PanicDataVersion::Determined(_) => "determined",
                PanicDataVersion::Inferred(_) => "inferred",
            }
        )
    }
}

/// A host CPU identifier
#[derive(Debug, Display)]
pub struct Cpuid(pub u32);

/// A host CPU memory address
#[derive(Debug, Display, LowerHex)]
pub struct Addr(pub u64);

/// Host time, in adjusted time (that is, seconds and nanoseconds since the
/// Epoch). Note that if this was gathered during boot, its correctness with
/// respect to true wall time will depend on when it was gathered:  if very
/// early in boot, it will be in 1970; if less early but still before any time
/// synchronization has started, it will be like an aging X'er: trapped in the
/// 1980s.
#[derive(Debug)]
pub struct AdjustedTime {
    pub sec: u64,
    pub nsec: u32,
}

/// Host time, in monotonically increasing nanoseconds.
#[derive(Debug, Display)]
pub struct MonotonicNanoseconds(pub u64);

/// A stack frame, consisting of a program text address of the caller.  This
/// is also expressed as a symbol and offset, if present.
#[derive(Debug)]
pub struct StackFrame {
    /// Address of caller
    pub address: Addr,

    /// Symbol of caller, if known
    pub symbol: Option<String>,

    /// Offset from symbol
    pub offset: u64,
}

/// A host register (presuming an AMD64 host).
#[derive(Debug, Hash, Eq, PartialEq, Display)]
#[allow(non_camel_case_types)]
pub enum Register {
    rdi,
    rsi,
    rdx,
    rcx,
    r8,
    r9,
    rax,
    rbx,
    rbp,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,
    fsbase,
    gsbase,
    ds,
    es,
    fs,
    gs,
    trapno,
    err,
    rip,
    cs,
    rfl,
    rsp,
    ss,
}

impl std::fmt::Display for StackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let width = f.width().unwrap_or(0);

        write!(
            f,
            "{:width$}",
            match &self.symbol {
                Some(s) => format!("{}+{:#x}", s, self.offset),
                None => format!("{:#x}", self.address),
            }
        )
    }
}

/// The cause of a panic.
#[derive(Debug, PartialEq)]
pub enum PanicCause {
    /// Explicit call to panic
    Call,

    /// Panic due to a trap
    Trap,

    /// Panic due to a user trap
    UserTrap,

    /// Panic very early in boot
    EarlyBoot,

    /// Panic early in boot due to call to prom_panic()
    EarlyBootPROM,

    /// Panic early in boot due to unexpected trap
    EarlyBootTrap,

    /// Panic early in boot due to unknown cause because of missing LSB
    EarlyBootUnknown,

    /// Corrupt or otherwise unrecognized cause
    Unknown(u16),
}

impl From<u16> for PanicCause {
    fn from(cause: u16) -> Self {
        match cause {
            0xca11 => Self::Call,
            0xa900 => Self::Trap,
            0x5e00 => Self::UserTrap,
            0xeb00 => Self::EarlyBoot,
            0xeb97 => Self::EarlyBootPROM,
            0xeba9 => Self::EarlyBootTrap,
            0xebff => Self::EarlyBootUnknown,
            c => Self::Unknown(c),
        }
    }
}

impl std::fmt::Display for PanicCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Call => "IPCC_PANIC_CALL".to_owned(),
                Self::Trap => "IPCC_PANIC_TRAP".to_owned(),
                Self::UserTrap => "IPCC_PANIC_USERTRAP".to_owned(),
                Self::EarlyBoot => "IPCC_PANIC_EARLYBOOT".to_owned(),
                Self::EarlyBootPROM => "IPCC_PANIC_EARLYBOOT_PROM".to_owned(),
                Self::EarlyBootTrap => "IPCC_PANIC_EARLYBOOT_TRAP".to_owned(),
                Self::EarlyBootUnknown => "IPCC_PANIC_EARLYBOOT_*".to_owned(),
                Self::Unknown(c) => format!("<Unknown cause {c:#06x}>"),
            }
        )
    }
}

/// Host panic data, the payload that corresponds to `HSSPanic` as described
/// in [RFD 316] and implemented in [`kernel_ipcc.h`].
///
/// [RFD 316]: https://rfd.shared.oxide.computer/rfd/0316
/// [`kernel_ipcc.h`]: https://github.com/oxidecomputer/illumos-gate/blob/stlouis/usr/src/uts/oxide/sys/kernel_ipcc.h
///
#[derive(Debug)]
pub struct PanicData {
    /// version of panic data
    pub version: PanicDataVersion,

    /// cause of panic
    pub cause: PanicCause,

    /// error code associated with trap (if any)
    pub error_code: u32,

    /// ID of panicking CPU
    pub cpuid: Cpuid,

    /// panic non-monotonic time (nanoseconds since boot), if present
    pub hrtime: Option<MonotonicNanoseconds>,

    /// panic adjusted time (time since epoch), if present
    pub time: Option<AdjustedTime>,

    /// address of panicking thread
    pub thread: Addr,

    /// address associated with trap (if any)
    pub addr: Addr,

    /// program counter associated with panic
    pub pc: Addr,

    /// frame pointer
    pub fp: Addr,

    /// pointer to panic registers
    pub rp: Addr,

    /// panic message, if any
    pub message: Option<String>,

    /// trap registers, if present
    pub registers: Option<IndexMap<Register, u64>>,

    /// panic stack
    pub stack: Vec<StackFrame>,
}

const IPCC_PANIC_VERSION_MAX: u8 = 0x3f;

// Values and structs are defined in usr/src/uts/oxide/sys/kernel_ipcc.h
// in the `stlouis` branch of `oxidecomputer/illumos-gate`
const IPCC_PANIC_V1_STACKS: usize = 0x10;
const IPCC_PANIC_V1_DATALEN: usize = 0x100;
const IPCC_PANIC_V1_SYMLEN: usize = 0x20;
const IPCC_PANIC_V1_MSGLEN: usize = 0x80;

#[derive(Copy, Clone, Debug, BinRead)]
#[allow(dead_code)]
struct IpccPanicDataV1 {
    ipd_version: u8,
    ipd_cause: u16,
    ipd_error: u32,

    ipd_cpuid: u32,
    ipd_thread: u64,
    ipd_addr: u64,
    ipd_pc: u64,
    ipd_fp: u64,
    ipd_rp: u64,

    ipd_message: [u8; IPCC_PANIC_V1_MSGLEN],

    ipd_stackidx: u8,
    ipd_stack: [IpccPanicStackV1; IPCC_PANIC_V1_STACKS],

    ipd_dataidx: u8,
    ipd_data: [u8; IPCC_PANIC_V1_DATALEN],
}

#[derive(Copy, Clone, Debug, BinRead)]
struct IpccPanicStackV1 {
    ips_symbol: [u8; IPCC_PANIC_V1_SYMLEN],
    ips_addr: u64,
    ips_offset: u64,
}

#[allow(dead_code)]
#[derive(Debug, BinRead, BinWrite)]
struct IpccPanicRegs {
    savfp: u64,
    savpc: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    r8: u64,
    r9: u64,
    rax: u64,
    rbx: u64,
    rbp: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    fsbase: u64,
    gsbase: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
    trapno: u64,
    err: u64,
    rip: u64,
    cs: u64,
    rfl: u64,
    rsp: u64,
    ss: u64,
}

#[derive(Debug, BinRead, BinWrite)]
#[allow(dead_code)]
struct IpccHresTime {
    tv_sec: u64,
    tv_nsec: u64,
}

#[derive(Debug, PartialEq, BinRead, BinWrite)]
#[br(repr = u8)]
#[bw(repr = u8)]
enum IpccPanicItemType {
    Nop,
    Message,
    StackEntry,
    Ancillary,
}

#[derive(Debug, BinRead, BinWrite)]
#[allow(dead_code)]
struct IpccPanicItem {
    ftype: IpccPanicItemType,
    len: u16,
    #[br(count = len.saturating_sub(3))]
    data: Vec<u8>,
}

#[derive(Debug, BinRead)]
#[allow(dead_code)]
struct IpccPanicStack {
    addr: u64,
    offset: u64,
    #[br(parse_with = until_eof)]
    symbol: Vec<u8>,
}

#[derive(Debug, BinRead, BinWrite)]
#[allow(dead_code)]
struct IpccPanicDataV2 {
    #[br(assert(version == 2))]
    version: u8,
    cause: u16,
    error: u32,

    hrtime: u64,
    hrestime: IpccHresTime,

    cpuid: u32,
    thread: u64,
    addr: u64,
    pc: u64,
    fp: u64,
    rp: u64,

    registers: IpccPanicRegs,

    nitems: u16,
    items_len: u16,
    #[br(count = nitems)]
    items: Vec<IpccPanicItem>,
}

pub fn make_a_panic_payload() -> Vec<u8> {
    let todo = IpccPanicDataV2 {
        version: 2,
        cause: 0xa900,
        error: 0x5678_90AB,
        hrtime: 0x1122_3344_5566_7788,
        hrestime: IpccHresTime {
            tv_sec: 0x9900_AABB_CCDD_EEFF,
            tv_nsec: 0x0A_BCDE,
        },
        cpuid: 0xFEDC_BA09,
        thread: 0x1234_2345_3456_4567,
        addr: 0x5678_6789_7890_890A,
        pc: 0x90AB_0ABC_ABCD_BCDE,
        fp: 0x1112_2223_3334_4445,
        rp: 0x5556_6667_7778_8889,
        registers: IpccPanicRegs {
            savfp: 0,
            savpc: 1,
            rdi: 2,
            rsi: 3,
            rdx: 4,
            rcx: 5,
            r8: 6,
            r9: 7,
            rax: 8,
            rbx: 9,
            rbp: 10,
            r10: 11,
            r11: 12,
            r12: 13,
            r13: 14,
            r14: 15,
            r15: 16,
            fsbase: 17,
            gsbase: 18,
            ds: 19,
            es: 20,
            fs: 21,
            gs: 22,
            trapno: 23,
            err: 24,
            rip: 25,
            cs: 26,
            rfl: 27,
            rsp: 28,
            ss: 29,
        },
        nitems: 0,
        items_len: 0,
        items: vec![],
    };

    let mut out = Cursor::new(Vec::new());
    todo.write_le(&mut out).unwrap();

    out.into_inner()
}

//
// Well, this is a galactic mess.  With SPs that don't have the fix for
// https://github.com/oxidecomputer/hubris/issues/1554, the first two bytes
// are not present in the IPCC panic data.  This -- very regrettably --
// includes the version number of the structure (`ipd_version`) along with the
// low byte of `ipd_cause`.  Fortunately, the high byte of `ipd_cause` (which
// is to say: the byte that we've got) does not conflict with our version
// number, which means if we see a valid version number in the first byte, we
// assume that we have an intact and correct payload.  If we don't see that,
// things get a bit grotty, because not only do we need to reconstruct the
// missing `ipd_cause` byte (which we cannot do perfectly, but will come close
// enough, especially when coupled with the panic message), but we also need
// to infer the version of the structure.
//
fn fix_panic_data(d: Vec<u8>) -> Result<(PanicDataVersion, Vec<u8>)> {
    //
    // In some cases, `ipd_cause` is unambiguous based on the first byte;
    // otherwise, we populate a generic value.
    //
    let missing_ipd_cause_byte = match d[0] {
        b if b < IPCC_PANIC_VERSION_MAX && b != 0 => {
            return Ok((PanicDataVersion::Determined(b), d));
        }
        0xca => 0x11,
        0x5e => 0x00,
        0xa9 => 0x00, // fault number is unknown
        0xeb => 0xff, // can't distinguish between different 0xeb**
        b => {
            bail!("could not decode `ipd_cause`: {b:#04x}");
        }
    };

    //
    // Now we need to determine what version we're looking at. As of this writing,
    // there are two versions of the IPCC panic data -- and they differ enough
    // in their binary payloads that we can reasonably infer that if the symbol
    // for every stack frame is a valid UTF-8 string, it must be a V1 payload.
    // (As an added check, we also check that the CPU ID -- a 32-bit value --
    // is in the realm of a practically valid CPU ID.)
    //
    let mut fixed = vec![0xff, missing_ipd_cause_byte];
    fixed.extend(d);

    let mut cursor: Cursor<&Vec<u8>> = Cursor::new(fixed.as_ref());
    let check = IpccPanicDataV1::read_le(&mut cursor)
        .context("failed to deserialize panic data as ")?;

    let cpuid = check.ipd_cpuid;

    let version = if cpuid < 512
        && !check
            .ipd_stack
            .iter()
            .any(|s| std::str::from_utf8(&s.ips_symbol).is_err())
    {
        PanicDataVersion::Inferred(1)
    } else {
        PanicDataVersion::Inferred(2)
    };

    fixed[0] = version.number();

    Ok((version, fixed))
}

impl PanicData {
    fn from_v1(version: PanicDataVersion, d: Vec<u8>) -> Result<Self> {
        let mut cursor = Cursor::new(d);
        let p = IpccPanicDataV1::read_le(&mut cursor)
            .context("failed to deserialize panic data")?;

        let message = match std::str::from_utf8(&p.ipd_message) {
            Ok(s) => s.trim_matches('\0').to_string(),
            Err(_) => {
                bail!("failed to decode ipd_message: {:#x?}", p.ipd_message);
            }
        };

        let mut stack = vec![];

        for (ndx, s) in p.ipd_stack.iter().enumerate() {
            if ndx >= p.ipd_stackidx.into() {
                break;
            }

            stack.push(StackFrame {
                address: Addr(s.ips_addr),
                offset: s.ips_offset,
                symbol: match std::str::from_utf8(&s.ips_symbol) {
                    Ok(s) => Some(s.trim_matches('\0').to_string()),
                    Err(_) => None,
                },
            });
        }

        Ok(Self {
            version,
            cause: p.ipd_cause.into(),
            error_code: p.ipd_error,
            cpuid: Cpuid(p.ipd_cpuid),
            hrtime: None,
            time: None,
            thread: Addr(p.ipd_thread),
            addr: Addr(p.ipd_addr),
            pc: Addr(p.ipd_pc),
            fp: Addr(p.ipd_fp),
            rp: Addr(p.ipd_rp),
            message: Some(message),
            registers: None,
            stack,
        })
    }

    fn from_v2(version: PanicDataVersion, d: Vec<u8>) -> Result<Self> {
        let mut cursor = Cursor::new(d);
        let p = IpccPanicDataV2::read_le(&mut cursor)
            .context("failed to deserialize panic data")?;

        let messages = p
            .items
            .iter()
            .filter(|i| i.ftype == IpccPanicItemType::Message)
            .collect::<Vec<_>>();

        let message = match messages.len() {
            0 => None,
            1 => Some(String::from_utf8_lossy(&messages[0].data).to_string()),
            _ => {
                bail!("found unexpected message items in panic data");
            }
        };

        let mut stack = vec![];

        for i in p
            .items
            .iter()
            .filter(|i| i.ftype == IpccPanicItemType::StackEntry)
        {
            let mut cursor = Cursor::new(&i.data);
            let ps = IpccPanicStack::read_le(&mut cursor)
                .context(format!("failed to deserialize item {i:#x?}"))?;

            stack.push(StackFrame {
                address: Addr(ps.addr),
                offset: ps.offset,
                symbol: match ps.symbol.len() {
                    0 => None,
                    _ => Some(String::from_utf8_lossy(&ps.symbol).to_string()),
                },
            });
        }

        let cause: PanicCause = p.cause.into();

        let registers = if cause != PanicCause::Call {
            let mut registers = IndexMap::new();

            macro_rules! register {
                ($reg:ident) => {
                    registers.insert(Register::$reg, p.registers.$reg);
                };
            }

            //
            // We set the registers in the same order in which they are displayed in
            // dumpregs() in the operating system, allowing for software that just
            // wants to display them to be able to iterate over them and get
            // sufficiently familiar output.
            //
            register!(rdi);
            register!(rsi);
            register!(rdx);
            register!(rcx);
            register!(r8);
            register!(r9);
            register!(rax);
            register!(rbx);
            register!(rbp);
            register!(r10);
            register!(r11);
            register!(r12);
            register!(r13);
            register!(r14);
            register!(fsbase);
            register!(gsbase);
            register!(es);
            register!(fs);
            register!(gs);
            register!(trapno);
            register!(err);
            register!(rip);
            register!(cs);
            register!(rfl);
            register!(rsp);
            register!(ss);

            Some(registers)
        } else {
            None
        };

        let nsec: u32 = match p.hrestime.tv_nsec.try_into() {
            Ok(nsec) => nsec,
            Err(_) => {
                bail!("illegal nsec value {:?}", p.hrestime);
            }
        };

        Ok(Self {
            version,
            cause,
            error_code: p.error,
            cpuid: Cpuid(p.cpuid),
            hrtime: Some(MonotonicNanoseconds(p.hrtime)),
            time: Some(AdjustedTime {
                sec: p.hrestime.tv_sec,
                nsec,
            }),
            thread: Addr(p.thread),
            addr: Addr(p.addr),
            pc: Addr(p.pc),
            fp: Addr(p.fp),
            rp: Addr(p.rp),
            message,
            registers,
            stack,
        })
    }

    /// Infer an IPCC data payload to be `HSSPanic`, creating [`PanicData`]
    /// from received bytes.  This implementation will work around
    /// any presence of [hubris#1554]; the returned [`PanicDataVersion`] will
    /// indicate if the version was able to be determined or had to
    /// be inferred.
    ///
    /// [hubris#1554]: https://github.com/oxidecomputer/hubris/issues/1554
    ///
    pub fn from_bytes(d: Vec<u8>) -> Result<Option<Self>> {
        if !d.iter().any(|&s| s != 0) {
            Ok(None)
        } else {
            let (version, data) = fix_panic_data(d)?;

            match version.number() {
                1 => Ok(Some(Self::from_v1(version, data)?)),
                2 => Ok(Some(Self::from_v2(version, data)?)),
                n => {
                    bail!("unsupported IPCC panic data version: {n}");
                }
            }
        }
    }
}

/// Image boot header
///
/// See `oxide_boot_sp.h` for the equivalent C definition
#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
)]
#[repr(C)]
pub struct BootSpHeader {
    pub magic: u32,
    pub version: u32,

    pub flags: u64,
    pub data_size: u64,
    pub image_size: u64,
    pub target_size: u64,

    pub sha256: [u8; 32],

    pub dataset: [u8; 128],
    pub imagename: [u8; 128],
}

impl BootSpHeader {
    pub const MAGIC: u32 = 0x1DEB0075;
    pub const VERSION: u32 = 2;
    pub const HEADER_SIZE: usize = 0x1000;
    pub const FLAG_COMPRESSED: u32 = 0x1;
}
