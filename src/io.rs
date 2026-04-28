//! Minimal `io` shim used in place of `std::io` so the verifier path can build under
//! `no_std + alloc`.
//!
//! Under both `std` and `no_std` the public surface is the same — `Cursor`, `Read`, `Write`,
//! `Error`, `ErrorKind` — but in `no_std` mode they are local types defined here. The
//! Codec/byteorder rewrite in `lib.rs` calls `byteorder::LittleEndian::{read,write}_*` directly
//! against slices, so `byteorder`'s std-only `ReadBytesExt`/`WriteBytesExt` extension traits are
//! never reached. `read_u24`/`write_u24` helpers are added to the local `Cursor`/`Write` because
//! `Size` (the libzk 24-bit length tag) is the only u24 user.

#[cfg(feature = "std")]
mod std_io {
    pub use std::io::{Cursor, Error, ErrorKind, Read, Write};

    /// Read a little-endian u24 from a `Cursor` and advance by 3 bytes.
    pub fn read_u24_le<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> Result<u32, Error> {
        let mut buf = [0u8; 3];
        Read::read_exact(cursor, &mut buf)?;
        Ok(u32::from(buf[0]) | (u32::from(buf[1]) << 8) | (u32::from(buf[2]) << 16))
    }

    /// Write a little-endian u24 (low 24 bits of `value`) to a `Write`.
    pub fn write_u24_le<W: Write + ?Sized>(writer: &mut W, value: u32) -> Result<(), Error> {
        let buf = [value as u8, (value >> 8) as u8, (value >> 16) as u8];
        writer.write_all(&buf)
    }
}

#[cfg(feature = "std")]
pub use std_io::{Cursor, Error, ErrorKind, Read, Write, read_u24_le, write_u24_le};

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

    impl core::error::Error for Error {}

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

    /// `Write` impl for `&mut [u8]` mirroring `std::io::Write`'s blanket impl: writes consume the
    /// front of the slice in place.
    impl Write for &mut [u8] {
        fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
            if buf.len() > self.len() {
                return Err(Error::new(ErrorKind::WriteZero, "slice too small"));
            }
            let (head, tail) = core::mem::take(self).split_at_mut(buf.len());
            head.copy_from_slice(buf);
            *self = tail;
            Ok(())
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

    /// Read a little-endian u24 from a `Cursor` and advance by 3 bytes.
    pub fn read_u24_le<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> Result<u32, Error> {
        let mut buf = [0u8; 3];
        cursor.read_exact(&mut buf)?;
        Ok(u32::from(buf[0]) | (u32::from(buf[1]) << 8) | (u32::from(buf[2]) << 16))
    }

    /// Write a little-endian u24 (low 24 bits of `value`) to a `Write`.
    pub fn write_u24_le<W: Write + ?Sized>(writer: &mut W, value: u32) -> Result<(), Error> {
        let buf = [value as u8, (value >> 8) as u8, (value >> 16) as u8];
        writer.write_all(&buf)
    }
}

#[cfg(not(feature = "std"))]
pub use no_std_io::{Cursor, Error, ErrorKind, Read, Write, read_u24_le, write_u24_le};
