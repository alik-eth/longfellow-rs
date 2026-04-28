//! Minimal `io` shim used in place of `std::io` so the verifier path can build under
//! `no_std + alloc`.
//!
//! When the `std` feature is enabled, this module re-exports `std::io::{Cursor, Read, Write,
//! Error, ErrorKind}` directly so existing call sites and `byteorder::{ReadBytesExt,
//! WriteBytesExt}` continue to work unchanged.
//!
//! When `std` is disabled, this module provides drop-in equivalents:
//! - `Cursor<&[u8]>` — a slice-backed cursor mirroring the relevant `std::io::Cursor` surface
//!   (`new`, `position`, `set_position`).
//! - `Read` / `Write` — minimal traits matching the std signatures we use, plus blanket impls
//!   that let `Cursor<&[u8]>` `Read` and `Vec<u8>` `Write`.
//! - `Error` / `ErrorKind` — anyhow-friendly error types.
//!
//! The custom `Read`/`Write` are deliberately compatible with `byteorder`'s extension traits
//! when the `byteorder/std` feature is enabled. With `byteorder` in no-std mode, callers reach
//! for the `LittleEndian::read_*` / `write_*` slice helpers instead, which `lib.rs` already
//! does for the `Codec` impls.

#[cfg(feature = "std")]
pub use std::io::{Cursor, Error, ErrorKind, Read, Write};

#[cfg(not(feature = "std"))]
mod no_std_io {
    use alloc::vec::Vec;
    use core::cmp::min;

    /// A minimal subset of `std::io::ErrorKind`.
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum ErrorKind {
        UnexpectedEof,
        WriteZero,
        Other,
    }

    /// A minimal subset of `std::io::Error`.
    #[derive(Debug)]
    pub struct Error {
        kind: ErrorKind,
    }

    impl Error {
        pub fn new(kind: ErrorKind, _msg: &'static str) -> Self {
            Self { kind }
        }

        pub fn kind(&self) -> ErrorKind {
            self.kind
        }
    }

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "io error: {:?}", self.kind)
        }
    }

    /// Minimal `std::io::Read` shim.
    pub trait Read {
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error>;
    }

    /// Minimal `std::io::Write` shim.
    pub trait Write {
        fn write_all(&mut self, buf: &[u8]) -> Result<(), Error>;
        fn flush(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    impl Write for Vec<u8> {
        fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
            self.extend_from_slice(buf);
            Ok(())
        }
    }

    impl<W: Write + ?Sized> Write for &mut W {
        fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
            (**self).write_all(buf)
        }
    }

    /// Slice-backed cursor mirroring the `std::io::Cursor<&[u8]>` surface used by Codec.
    #[derive(Debug, Clone)]
    pub struct Cursor<T> {
        inner: T,
        pos: u64,
    }

    impl<T: AsRef<[u8]>> Cursor<T> {
        pub fn new(inner: T) -> Self {
            Self { inner, pos: 0 }
        }

        pub fn position(&self) -> u64 {
            self.pos
        }

        pub fn set_position(&mut self, pos: u64) {
            self.pos = pos;
        }

        pub fn get_ref(&self) -> &T {
            &self.inner
        }
    }

    impl<T: AsRef<[u8]>> Read for Cursor<T> {
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            let slice = self.inner.as_ref();
            let pos = self.pos as usize;
            let n = buf.len();
            if pos.checked_add(n).map_or(true, |end| end > slice.len()) {
                return Err(Error::new(ErrorKind::UnexpectedEof, "cursor read past end"));
            }
            let take = min(n, slice.len().saturating_sub(pos));
            buf[..take].copy_from_slice(&slice[pos..pos + take]);
            self.pos += take as u64;
            Ok(())
        }
    }
}

#[cfg(not(feature = "std"))]
pub use no_std_io::{Cursor, Error, ErrorKind, Read, Write};
