#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use crate::io::{Cursor, Read, Write, read_u24_le, write_u24_le};
use alloc::vec::Vec;
use anyhow::{Context, anyhow};
use byteorder::{ByteOrder, LittleEndian};
use core::fmt::{self, Display};
use crypto_common::{generic_array::GenericArray, typenum::U32};

pub mod circuit;
pub mod circuit_data;
#[cfg(feature = "mobile")]
pub mod ffi_api;
pub mod fields;
pub mod io;
#[cfg(all(target_family = "wasm", feature = "wasm"))]
pub mod js_api;
pub mod ligero;
pub mod mdoc_zk;
pub mod p7s_zk;
pub mod sumcheck;
#[cfg(test)]
pub mod test_vector;
pub mod transcript;
mod witness;
pub mod zk_one_circuit;

#[cfg(feature = "mobile")]
uniffi::setup_scaffolding!();

/// A serialized size, which is in the range [1, 2^24 -1] per [draft-google-cfrg-libzk-00 section
/// 7][1]. Serialized in little endian order, occupying 3 bytes.
///
/// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Default, Hash)]
pub struct Size(u32);

impl From<u32> for Size {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Size> for usize {
    fn from(value: Size) -> Self {
        // XXX shouldn't assume that usize is big enough for u32
        value.0 as Self
    }
}

impl TryFrom<usize> for Size {
    type Error = anyhow::Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        u32::try_from(value)
            .context("usize too big for u32")
            .map(Self)
    }
}

impl Codec for Size {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        Ok(Self(read_u24_le(bytes).context("failed to read u24")?))
    }

    fn encode<W: Write>(&self, bytes: &mut W) -> Result<(), anyhow::Error> {
        if self.0 >= (1 << 24) {
            return Err(anyhow!(
                "size {} too big to be serialized in 3 bytes",
                self.0
            ));
        }
        write_u24_le(bytes, self.0).context("failed to write u24")
    }
}

impl PartialEq<usize> for Size {
    fn eq(&self, other: &usize) -> bool {
        usize::from(*self) == *other
    }
}

impl PartialOrd<usize> for Size {
    fn partial_cmp(&self, other: &usize) -> Option<core::cmp::Ordering> {
        usize::from(*self).partial_cmp(other)
    }
}

impl Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Size {
    /// Encode this value as a delta from the previous value in some sequence. The least significant
    /// bit is used as the sign bit, with the actual value shifted up by one position ([1]).
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7.6-5
    pub fn encode_delta<W: Write>(
        &self,
        previous: Size,
        bytes: &mut W,
    ) -> Result<(), anyhow::Error> {
        let delta = if self.0 >= previous.0 {
            // Delta is positive: shift the delta up by one, leaving sign bit clear
            (self.0 - previous.0)
                .checked_mul(2)
                .ok_or_else(|| anyhow!("shift would overflow"))?
        } else {
            // Delta is negative: shift the delta up by one and set the sign bit
            (previous.0 - self.0)
                .checked_mul(2)
                .ok_or_else(|| anyhow!("shift would overflow"))?
                | 1
        };

        Size::from(delta).encode(bytes)
    }

    /// Decode this value as a delta from the previous value in some sequence.
    pub fn decode_delta(previous: Size, bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let encoded_delta = Size::decode(bytes)?.0;
        let sign = encoded_delta & 1;
        let delta = encoded_delta >> 1;

        let decoded = if sign == 1 {
            // Delta is negative
            previous.0 - delta
        } else {
            // Delta is positive
            previous.0 + delta
        };

        Ok(Self(decoded))
    }
}

/// Describes how to encode and decode an object from a byte sequence, per the rules in
/// [draft-google-cfrg-libzk-00 section 7][1].
///
/// Adapted from [prio::codec][2].
///
/// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7
/// [2]: https://docs.rs/prio/0.17.0/prio/codec/index.html
pub trait Codec: Sized + PartialEq + Eq + core::fmt::Debug {
    /// Decode an opaque byte buffer into an instance of this type. On success, the decoded value is
    /// returned and `bytes` is advanced by the encoded size of the value. On failure, no further
    /// attempt to read from `bytes` should be made.
    fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error>;

    /// Convenience method to get a decoded value from a byte slice. Returns an error if
    /// [`Self::decode`] fails, or if any bytes are left over in `bytes` after decoding a value.
    fn get_decoded(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        Self::get_decoded_with_param(&(), bytes)
    }

    /// Decode a variable length array of items.
    fn decode_array(cursor: &mut Cursor<&[u8]>) -> Result<Vec<Self>, anyhow::Error> {
        // Variable length array encoding: length as a Size, then the elements one after the other.
        // Empirically, based on the test vector, it's length in *elements*, not bytes.
        let elements = Size::decode(cursor)?;
        Self::decode_fixed_array(cursor, elements.into())
    }

    /// Decode a fixed length array of items.
    fn decode_fixed_array(
        cursor: &mut Cursor<&[u8]>,
        count: usize,
    ) -> Result<Vec<Self>, anyhow::Error> {
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let item = Self::decode(cursor)?;
            items.push(item);
        }

        Ok(items)
    }

    /// Get the encoded form of this object, allocating a vector to hold it.
    fn get_encoded(&self) -> Result<Vec<u8>, anyhow::Error> {
        self.get_encoded_with_param(&())
    }

    /// Append the encoded form of this object to the end of `bytes`, growing the vector as needed.
    fn encode<W: Write>(&self, bytes: &mut W) -> Result<(), anyhow::Error>;

    /// Encode a variable length array of items.
    fn encode_array<W: Write>(items: &[Self], bytes: &mut W) -> Result<(), anyhow::Error> {
        // Variable length array encoding: length in elements as a Size, then the elements one after
        // the other.
        Size(
            items
                .len()
                .try_into()
                .context("vector length too big for u32")?,
        )
        .encode(bytes)?;
        Self::encode_fixed_array(items, bytes)
    }

    /// Encode a fixed length array of items.
    fn encode_fixed_array<W: Write>(items: &[Self], bytes: &mut W) -> Result<(), anyhow::Error> {
        for item in items {
            item.encode(bytes)?;
        }
        Ok(())
    }
}

impl Codec for u8 {
    fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf).context("failed to read u8")?;
        Ok(buf[0])
    }

    fn encode<W: Write>(&self, bytes: &mut W) -> Result<(), anyhow::Error> {
        bytes.write_all(&[*self]).context("failed to write u8")
    }
}

impl Codec for u16 {
    fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buf = [0u8; 2];
        cursor.read_exact(&mut buf).context("failed to read u16")?;
        Ok(LittleEndian::read_u16(&buf))
    }

    fn encode<W: Write>(&self, bytes: &mut W) -> Result<(), anyhow::Error> {
        let mut buf = [0u8; 2];
        LittleEndian::write_u16(&mut buf, *self);
        bytes.write_all(&buf).context("failed to write u16")
    }
}

impl Codec for u32 {
    fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buf = [0u8; 4];
        cursor.read_exact(&mut buf).context("failed to read u32")?;
        Ok(LittleEndian::read_u32(&buf))
    }

    fn encode<W: Write>(&self, bytes: &mut W) -> Result<(), anyhow::Error> {
        let mut buf = [0u8; 4];
        LittleEndian::write_u32(&mut buf, *self);
        bytes.write_all(&buf).context("failed to write u32")
    }
}

/// A SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sha256Digest(pub [u8; 32]);

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Codec for Sha256Digest {
    fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let bytes: [u8; 32] = u8::decode_fixed_array(cursor, 32)?
            .try_into()
            .map_err(|_| anyhow!("failed to convert byte vec to array"))?;

        Ok(Self(bytes))
    }

    fn encode<W: Write>(&self, bytes: &mut W) -> Result<(), anyhow::Error> {
        u8::encode_fixed_array(self.0.as_slice(), bytes)
    }
}

impl From<[u8; 32]> for Sha256Digest {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<GenericArray<u8, U32>> for Sha256Digest {
    fn from(value: GenericArray<u8, U32>) -> Self {
        Self(value.into())
    }
}

/// Describes how to encode and decode an object from a byte sequence, per the rules in
/// [draft-google-cfrg-libzk-00 section 7][1]. Very similar to [`Codec`], but allows an encoding
/// parameter to be passed in for types that require some context.
///
/// Adapted from [prio::codec][2].
///
/// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7
/// [2]: https://docs.rs/prio/0.17.0/prio/codec/index.html
pub trait ParameterizedCodec<P>: Sized + PartialEq + Eq + core::fmt::Debug {
    /// Decode an opaque byte buffer into an instance of this type. On success, the decoded value is
    /// returned and `bytes` is advanced by the encoded size of the value. On failure, no further
    /// attempt to read from `bytes` should be made.
    fn decode_with_param(
        encoding_parameter: &P,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error>;

    /// Convenience method to get a decoded value from a byte slice. Returns an error if
    /// [`Self::decode_with_param`] fails, or if any bytes are left over in `bytes` after decoding
    /// a value.
    fn get_decoded_with_param(encoding_parameter: &P, bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let mut cursor = Cursor::new(bytes);
        let decoded = Self::decode_with_param(encoding_parameter, &mut cursor)?;
        if cursor.position() as usize != bytes.len() {
            return Err(anyhow!(
                "{} bytes left over in buffer after decoding",
                bytes.len() - cursor.position() as usize
            ));
        }

        Ok(decoded)
    }

    /// Append the encoded form of this object to the end of `bytes`, growing the vector as needed.
    fn encode_with_param<W: Write>(
        &self,
        encoding_parameter: &P,
        bytes: &mut W,
    ) -> Result<(), anyhow::Error>;

    /// Get the encoded form of this object, allocating a vector to hold it.
    fn get_encoded_with_param(&self, encoding_parameter: &P) -> Result<Vec<u8>, anyhow::Error> {
        let mut ret = Vec::new();
        self.encode_with_param(encoding_parameter, &mut ret)?;
        Ok(ret)
    }

    #[cfg(test)]
    fn roundtrip(&self, encoding_parameter: &P) {
        let encoded = self.get_encoded_with_param(encoding_parameter).unwrap();
        println!("encoded: {encoded:0x?}");

        let decoded = Self::get_decoded_with_param(encoding_parameter, &encoded).unwrap();

        assert_eq!(*self, decoded)
    }
}

impl<C: Codec, T> ParameterizedCodec<T> for C {
    fn decode_with_param(
        _encoding_parameter: &T,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        Self::decode(cursor)
    }

    fn encode_with_param<W: Write>(
        &self,
        _encoding_parameter: &T,
        bytes: &mut W,
    ) -> Result<(), anyhow::Error> {
        self.encode(bytes)
    }
}

// no_std stubs for the cdylib/staticlib artifacts that `cargo check` builds even when consumers
// only need the rlib. These never run — SP1's zkvm runtime (or any other consumer) supplies real
// allocator + panic_handler when actually linking. Gated to (no std) + (no prover) so it cannot
// collide with consumers that bring their own.
//
// `target_os = "zkvm"` is excluded: SP1's `riscv*-succinct-zkvm-elf`
// target ships a real `std` (its runtime provides the allocator + panic
// handler), so emitting the stub `panic_handler` / `global_allocator`
// here would be a duplicate-lang-item collision with libstd.
#[cfg(all(not(feature = "std"), not(feature = "prover"), not(target_os = "zkvm")))]
mod no_std_artifact_stubs {
    use core::alloc::{GlobalAlloc, Layout};

    struct NoopAlloc;

    unsafe impl GlobalAlloc for NoopAlloc {
        unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
            core::ptr::null_mut()
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    static GLOBAL: NoopAlloc = NoopAlloc;

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// Given a test function that is generic over [`FieldElement`], this macro stamps out a module
    /// containing test cases for multiple specific implementations.
    ///
    /// To ignore specific test instantiations, use the following syntax:
    ///
    /// ```text
    /// field_element_tests!(function, ignore(Field2_128));
    ///
    /// field_element_tests!(function, ignore(Field2_128 = "reason"));
    /// ```
    #[macro_export]
    macro_rules! field_element_tests {
        ($function:ident $($rest:tt)*) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 {}
                @fieldp128_msg {}
                @fieldp256 {}
                @fieldp256_msg {}
                @field2_128 {}
                @field2_128_msg {}
                $($rest)*
            );
        };

        // TT muncher pattern: collect DSL arguments, transform them, and regroup them by field.
        (
            @internal
            $function:ident
            @fieldp128 {}
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(FieldP128)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { ignore }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg {}
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(FieldP128 = $message_p128:tt)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { ignore = $message_p128 }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 {}
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(FieldP256)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { ignore }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg {}
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(FieldP256 = $message_p256:tt)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { ignore = $message_p256 }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 {}
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(Field2_128)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { ignore }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg {}
            , ignore(Field2_128 = $message_2_128:tt)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { ignore = $message_2_128 }
                $($rest)*
            );
        };

        // Base case: no DSL arguments left.
        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            $(,)?
        ) => {
            mod $function {
                use super::*;

                $(#[$ignore_p128])?
                $(#[ignore = $message_p128])?
                #[wasm_bindgen_test(unsupported = test)]
                fn field_p128() {
                    $function::<$crate::fields::fieldp128::FieldP128>();
                }

                $(#[$ignore_p256])?
                $(#[ignore = $message_p256])?
                #[wasm_bindgen_test(unsupported = test)]
                fn field_p256() {
                    $function::<$crate::fields::fieldp256::FieldP256>();
                }

                $(#[$ignore_2_128])?
                $(#[ignore = $message_2_128])?
                #[wasm_bindgen_test(unsupported = test)]
                fn field2_128() {
                    $function::<$crate::fields::field2_128::Field2_128>();
                }
            }
        };
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn codec_roundtrip_u8() {
        12u8.roundtrip(&());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn codec_roundtrip_u32() {
        0xffffab65u32.roundtrip(&());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn codec_roundtrip_size() {
        Size::from(12345).roundtrip(&());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn encode_size_too_big() {
        // 1 << 24 is too big to be encoded as a 3 byte size, so this should fail
        let mut bytes = Vec::new();
        Size::from(1 << 24).encode(&mut bytes).unwrap_err();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn encode_delta_positive_overflow() {
        // (1 << 31 - 0) << 1 will overflow u32, so this should fail
        let mut bytes = Vec::new();
        Size::from(1 << 31)
            .encode_delta(Size::from(0), &mut bytes)
            .unwrap_err();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn encode_delta_negative_overflow() {
        // (1 << 31 - 0) << 1 will overflow u32, so this should fail
        let mut bytes = Vec::new();
        Size::from(0)
            .encode_delta(Size::from(1 << 31), &mut bytes)
            .unwrap_err();
    }
}
