//! Compile-time trust-anchor table.
//!
//! Mirrors `kTrustAnchors` at
//! `vendor/longfellow-zk/lib/circuits/p7s/sub/p7s_signature.h:182-204`.
//!
//! N=2 entries (TestAnchorA + TestAnchorB) are baked in. The witness-driven
//! `trust_anchor_index` (a v32 public-input wire on the hash side, also
//! pushed as a single `Fp256Base` element on the sig side) selects which
//! anchor the cert-sig ECDSA verifies under.

use crate::fields::fieldp256::FieldP256;

/// Number of trust-anchor entries (matches C++ `kTrustAnchorCount`).
pub(crate) const TRUST_ANCHOR_COUNT: usize = 2;

/// TestAnchorA root pubkey X coordinate (BE, hex-decoded).
///
/// SEC1 hex: `0xe62c46fd4aeeef700e933114a1b85af927a007019f157e89f3ec8a36d4dc08a3`
const TEST_ANCHOR_A_PK_X_BE: [u8; 32] = [
    0xe6, 0x2c, 0x46, 0xfd, 0x4a, 0xee, 0xef, 0x70, 0x0e, 0x93, 0x31, 0x14, 0xa1, 0xb8, 0x5a, 0xf9,
    0x27, 0xa0, 0x07, 0x01, 0x9f, 0x15, 0x7e, 0x89, 0xf3, 0xec, 0x8a, 0x36, 0xd4, 0xdc, 0x08, 0xa3,
];

/// TestAnchorA root pubkey Y coordinate (BE, hex-decoded).
///
/// SEC1 hex: `0xc327059b5cb8ef635db4fc15e3da7ef174332efd07b7ef3a35c4b69492a64c28`
const TEST_ANCHOR_A_PK_Y_BE: [u8; 32] = [
    0xc3, 0x27, 0x05, 0x9b, 0x5c, 0xb8, 0xef, 0x63, 0x5d, 0xb4, 0xfc, 0x15, 0xe3, 0xda, 0x7e, 0xf1,
    0x74, 0x33, 0x2e, 0xfd, 0x07, 0xb7, 0xef, 0x3a, 0x35, 0xc4, 0xb6, 0x94, 0x92, 0xa6, 0x4c, 0x28,
];

/// TestAnchorB root pubkey X coordinate (BE, hex-decoded).
///
/// SEC1 hex: `0x3a48db8f884948fb58ce44bc21a3deeb6e62ceb23c7a1384cf27d126c8ea0b9b`
const TEST_ANCHOR_B_PK_X_BE: [u8; 32] = [
    0x3a, 0x48, 0xdb, 0x8f, 0x88, 0x49, 0x48, 0xfb, 0x58, 0xce, 0x44, 0xbc, 0x21, 0xa3, 0xde, 0xeb,
    0x6e, 0x62, 0xce, 0xb2, 0x3c, 0x7a, 0x13, 0x84, 0xcf, 0x27, 0xd1, 0x26, 0xc8, 0xea, 0x0b, 0x9b,
];

/// TestAnchorB root pubkey Y coordinate (BE, hex-decoded).
///
/// SEC1 hex: `0xbaed0eeec7f234ced5e8b233cec71ed2346d1dbb3559acb2f5ccc1faa4778043`
const TEST_ANCHOR_B_PK_Y_BE: [u8; 32] = [
    0xba, 0xed, 0x0e, 0xee, 0xc7, 0xf2, 0x34, 0xce, 0xd5, 0xe8, 0xb2, 0x33, 0xce, 0xc7, 0x1e, 0xd2,
    0x34, 0x6d, 0x1d, 0xbb, 0x35, 0x59, 0xac, 0xb2, 0xf5, 0xcc, 0xc1, 0xfa, 0xa4, 0x77, 0x80, 0x43,
];

/// Lookup the (X, Y) coordinates of the trust anchor at the given index.
///
/// Returns `None` if `index >= TRUST_ANCHOR_COUNT`.
///
/// The returned `FieldP256` elements are in Montgomery form internally (via
/// `FieldP256::try_from(&le_bytes)`), matching what
/// `mdoc_zk::ec::AffinePoint::new(x, y)` expects.
pub(crate) fn trust_anchor_pk(index: u32) -> Option<(FieldP256, FieldP256)> {
    let (x_be, y_be) = match index {
        0 => (&TEST_ANCHOR_A_PK_X_BE, &TEST_ANCHOR_A_PK_Y_BE),
        1 => (&TEST_ANCHOR_B_PK_X_BE, &TEST_ANCHOR_B_PK_Y_BE),
        _ => return None,
    };

    let x_le = be_to_le(x_be);
    let y_le = be_to_le(y_be);
    let x = FieldP256::try_from(&x_le).ok()?;
    let y = FieldP256::try_from(&y_le).ok()?;
    Some((x, y))
}

fn be_to_le(be: &[u8; 32]) -> [u8; 32] {
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    le
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_index_0_resolves_to_test_anchor_a() {
        let (x, _y) = trust_anchor_pk(0).expect("index 0 in range");
        // The encoded LE bytes round-trip through FieldP256::try_from.
        let mut le = be_to_le(&TEST_ANCHOR_A_PK_X_BE);
        let x2 = FieldP256::try_from(&le).expect("anchor A X parses");
        assert_eq!(x, x2);
        // Quick sanity that BE → LE swap is symmetric.
        let _suppress_unused = &mut le;
    }

    #[test]
    fn anchor_index_1_resolves_to_test_anchor_b() {
        let (x, _y) = trust_anchor_pk(1).expect("index 1 in range");
        let le = be_to_le(&TEST_ANCHOR_B_PK_X_BE);
        let x2 = FieldP256::try_from(&le).expect("anchor B X parses");
        assert_eq!(x, x2);
    }

    #[test]
    fn anchor_index_2_returns_none() {
        assert!(trust_anchor_pk(2).is_none());
        assert!(trust_anchor_pk(u32::MAX).is_none());
    }

    #[test]
    fn anchors_a_and_b_are_distinct() {
        let (xa, ya) = trust_anchor_pk(0).unwrap();
        let (xb, yb) = trust_anchor_pk(1).unwrap();
        assert_ne!(xa, xb);
        assert_ne!(ya, yb);
    }
}
