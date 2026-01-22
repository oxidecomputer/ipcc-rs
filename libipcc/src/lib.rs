// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! An interface to libipcc (inter-processor communications channel) which
//! currently supports looking up values stored in the SP by key. These
//! values are variously static, passed from the control plane to the SP
//! (through MGS) or set from userland via libipcc.

use cfg_if::cfg_if;
use thiserror::Error;

cfg_if! {
    if #[cfg(target_os = "illumos")] {
        pub mod ffi;
        pub mod handle;
        pub use handle::IpccHandle;
    } else {
        pub mod handle_stub;
        pub use handle_stub::IpccHandle;
    }
}

#[derive(Error, Debug)]
pub enum IpccError {
    #[error("Memory allocation error")]
    NoMem(#[source] IpccErrorInner),
    #[error("Invalid parameter")]
    InvalidParam(#[source] IpccErrorInner),
    #[error("Internal error occurred")]
    Internal(#[source] IpccErrorInner),
    #[error("Requested lookup key was not known to the SP")]
    KeyUnknown(#[source] IpccErrorInner),
    #[error("Value for the requested lookup key was too large for the supplied buffer")]
    KeyBufTooSmall(#[source] IpccErrorInner),
    #[error("Attempted to write to read-only key")]
    KeyReadonly(#[source] IpccErrorInner),
    #[error("Attempted write to key failed because the value is too long")]
    KeyValTooLong(#[source] IpccErrorInner),
    #[error("Compression or decompression failed")]
    KeyZerr(#[source] IpccErrorInner),
    #[error("Unknown libipcc error")]
    UnknownErr(#[source] IpccErrorInner),
}

#[derive(Error, Debug)]
#[error("{context}: {errmsg} ({syserr})")]
pub struct IpccErrorInner {
    pub context: String,
    pub errmsg: String,
    pub syserr: String,
}

// These aren't strictly part of libipcc but are defined as part of the
// Host<->SP protocol as laid out in RFD 316 and are used for message
// calculations for messages which use opaque data.

/// The size of a message with no associated data:
///   magic (4) + version (4) + sequence (8) + command (1) + checksum (2)
pub const IPCC_MIN_MESSAGE_SIZE: usize = 19;
/// The maximum size of message:
///   header (17) + data (4KiB + 8) + checksum (2)
pub const IPCC_MAX_MESSAGE_SIZE: usize = 4123;
/// A message may contain up to 4KiB of payload along with an extra 64-bits of
/// accompanying data.
pub const IPCC_MAX_DATA_SIZE: usize =
    IPCC_MAX_MESSAGE_SIZE - IPCC_MIN_MESSAGE_SIZE;
