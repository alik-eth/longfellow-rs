//! Thin `io` module that re-exports the `std::io` surface used by the codec
//! layer (`Cursor`, `Read`, `Write`, `Error`, `ErrorKind`) plus little-endian
//! u24 helpers for the libzk 24-bit length tag (`Size`).
//!
//! This was once a `no_std` shim with a local slice-cursor fallback; the crate
//! is now always `std`, so it simply forwards to `std::io`. Callsites keep
//! importing from `crate::io` to avoid churn.

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
