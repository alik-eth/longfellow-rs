//! Witness / public blob byte-format parsers, mirroring `parse_witness_blob`
//! and `parse_public_blob` in `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc`.
//!
//! The C++ parsers use a `skip_host_anchors` flag for a test-only
//! bypass FFI entry. The Rust port always enforces the host-side
//! anchors (production posture); a future task can add a skip flag if
//! the test-bypass parity is needed in Rust too.
//!
//! All field offsets and bound checks mirror the C++ source line-for-
//! line; commentary preserved on novel structural points.

use super::{
    layout::*,
    public_inputs::ParsedPublic,
    witness::ParsedWitness,
};
use alloc::vec::Vec;
use anyhow::{Context, anyhow};

/// 26-byte fixed P-256 SubjectPublicKeyInfo DER prefix asserted in-circuit
/// via `cert_tbs[spki_offset..+26]`. Mirrored in the Rust host parser
/// (`crates/zk-eidas-p7s/src/parser.rs`'s `SPKI_P256_PREFIX`) and the
/// C++ vendor's `kSpkiP256Prefix` (`p7s_zk.cc:337`). Any change requires
/// updating all three sites.
const SPKI_P256_PREFIX: [u8; SPKI_PREFIX_LEN] = [
    0x30, 0x59, // SPKI SEQUENCE hdr (l=89)
    0x30, 0x13, // AlgId SEQUENCE hdr (l=19)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID id-ecPublicKey
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
    0x03, 0x42, 0x00, // BIT STRING hdr (l=66, unused=0)
];

/// 9-byte X.520 serialNumber DER anchor asserted in-circuit at
/// `cert_tbs[subject_sn_offset..+9]`. v13 (Task #37): bytes 1 (outer
/// SEQUENCE length `S`) and 8 (PrintableString length `L`) are
/// variable — placeholders here, validated via the `S == L + 7`
/// linkage. The 7 length-independent bytes are asserted by index
/// against `SUBJECT_SN_ANCHOR_CONST_IDX`. Mirrors C++ `kSubjectSnAnchor`
/// + `kSubjectSnAnchorConstIdx` (`p7s_zk.cc`).
const SUBJECT_SN_ANCHOR: [u8; SUBJECT_SN_ANCHOR_LEN] = [
    0x30, 0x00, // ATV SEQUENCE; [1] = S (variable)
    0x06, 0x03, 0x55, 0x04, 0x05, // OID 2.5.4.5 (serialNumber)
    0x13, 0x00, // PrintableString; [8] = L (variable)
];

/// Indices into `SUBJECT_SN_ANCHOR` whose bytes are length-independent
/// (everything except [1] = `S` and [8] = `L`).
const SUBJECT_SN_ANCHOR_CONST_IDX: [usize; 7] = [0, 2, 3, 4, 5, 6, 7];

/// 17-byte CMS messageDigest attribute DER prefix asserted in-circuit at
/// `signed_attrs[md_offset..+17]`. Mirrored from C++ vendor's
/// `kSignedAttrsMdPrefix` (`p7s_zk.cc:368`).
const SIGNED_ATTRS_MD_PREFIX: [u8; SIGNED_ATTRS_MD_PREFIX_LEN] = [
    0x30, 0x2f, // Attribute SEQUENCE (l=47)
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, // OID messageDigest
    0x31, 0x22, // SET OF AttributeValue (l=34)
    0x04, 0x20, // OCTET STRING hdr (l=32)
];

/// Cursor-based reader over a byte slice. Tracks position; bounds
/// checks return `anyhow!`-typed errors so the caller surfaces a
/// `P7S_INVALID_INPUT`-equivalent classification.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn read_u32_le(&mut self) -> Result<u32, anyhow::Error> {
        if self.remaining() < 4 {
            return Err(anyhow!("truncated blob: need 4 bytes for u32"));
        }
        let v = u32::from_le_bytes(
            self.bytes[self.pos..self.pos + 4]
                .try_into()
                .expect("slice of 4 bytes fits u32"),
        );
        self.pos += 4;
        Ok(v)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], anyhow::Error> {
        if self.remaining() < N {
            return Err(anyhow!("truncated blob: need {N} bytes for fixed array"));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_vec(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error> {
        if self.remaining() < n {
            return Err(anyhow!("truncated blob: need {n} bytes for vec"));
        }
        let out = self.bytes[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }
}

/// Parse a v12 witness blob. Returns `Err` for any malformed input
/// (wrong schema version, out-of-range length, missing host-side
/// anchor, trailing bytes); the C++ side surfaces these as
/// `P7S_INVALID_INPUT`.
pub fn parse_witness_blob(blob: &[u8]) -> Result<ParsedWitness, anyhow::Error> {
    if blob.is_empty() {
        return Err(anyhow!("empty witness blob"));
    }
    let mut r = Reader::new(blob);

    let version = r.read_u32_le().context("witness: schema version")?;
    if version != BLOB_SCHEMA_VERSION {
        return Err(anyhow!(
            "witness schema version mismatch: got {}, want {}",
            version,
            BLOB_SCHEMA_VERSION
        ));
    }

    let context_len = r.read_u32_le().context("witness: context_len")?;
    if (context_len as usize) > CONTEXT_MAX_BYTES {
        return Err(anyhow!(
            "witness: context_len {} exceeds CONTEXT_MAX_BYTES {}",
            context_len,
            CONTEXT_MAX_BYTES
        ));
    }
    let context = r.read_array::<CONTEXT_MAX_BYTES>().context("witness: context")?;

    let signed_content_len = r
        .read_u32_le()
        .context("witness: signed_content_len")?;
    if (signed_content_len as usize) > MAX_SIGNED_CONTENT {
        return Err(anyhow!(
            "witness: signed_content_len {} exceeds MAX_SIGNED_CONTENT {}",
            signed_content_len,
            MAX_SIGNED_CONTENT
        ));
    }
    let signed_content = r
        .read_vec(MAX_SIGNED_CONTENT)
        .context("witness: signed_content")?;

    let json_pk_offset = r.read_u32_le().context("witness: json_pk_offset")?;
    if (json_pk_offset as usize) > MAX_SIGNED_CONTENT - PK_HEX_LEN {
        return Err(anyhow!("witness: json_pk_offset out of range"));
    }
    let pk_hex = r.read_array::<PK_HEX_LEN>().context("witness: pk_hex")?;

    let json_nonce_offset = r.read_u32_le().context("witness: json_nonce_offset")?;
    if (json_nonce_offset as usize) > MAX_SIGNED_CONTENT - NONCE_HEX_LEN {
        return Err(anyhow!("witness: json_nonce_offset out of range"));
    }
    let nonce_hex = r.read_array::<NONCE_HEX_LEN>().context("witness: nonce_hex")?;

    let json_context_offset = r.read_u32_le().context("witness: json_context_offset")?;
    if (json_context_offset as usize) > MAX_SIGNED_CONTENT - CONTEXT_MAX_BYTES {
        return Err(anyhow!("witness: json_context_offset out of range"));
    }

    let json_declaration_offset = r
        .read_u32_le()
        .context("witness: json_declaration_offset")?;
    if (json_declaration_offset as usize) > MAX_SIGNED_CONTENT - DECLARATION_LEN {
        return Err(anyhow!("witness: json_declaration_offset out of range"));
    }

    // v12 invariant 13 — holder_seed_commit hex offset + 64 raw chars.
    let json_holder_seed_commit_offset = r
        .read_u32_le()
        .context("witness: json_holder_seed_commit_offset")?;
    if (json_holder_seed_commit_offset as usize) > MAX_SIGNED_CONTENT - HOLDER_SEED_COMMIT_HEX_LEN
    {
        return Err(anyhow!(
            "witness: json_holder_seed_commit_offset out of range"
        ));
    }
    let holder_seed_commit_hex = r
        .read_array::<HOLDER_SEED_COMMIT_HEX_LEN>()
        .context("witness: holder_seed_commit_hex")?;

    let message_digest = r
        .read_array::<MESSAGE_DIGEST_LEN>()
        .context("witness: message_digest")?;

    // v8 cert_tbs.
    let cert_tbs_len = r.read_u32_le().context("witness: cert_tbs_len")?;
    if (cert_tbs_len as usize) > CERT_TBS_MAX_BYTES {
        return Err(anyhow!("witness: cert_tbs_len exceeds CERT_TBS_MAX_BYTES"));
    }
    // Minimum SHA padding is 9 bytes, so the raw cert_tbs can be at most
    // CERT_TBS_MAX_BYTES - 9 = 2039 bytes.
    if (cert_tbs_len as usize) > CERT_TBS_MAX_BYTES - 9 {
        return Err(anyhow!(
            "witness: cert_tbs_len {} exceeds raw bound {}",
            cert_tbs_len,
            CERT_TBS_MAX_BYTES - 9
        ));
    }
    let cert_tbs_spki_offset = r.read_u32_le().context("witness: cert_tbs_spki_offset")?;
    if (cert_tbs_spki_offset as usize) + SPKI_WINDOW_LEN > (cert_tbs_len as usize) {
        return Err(anyhow!(
            "witness: cert_tbs_spki_offset + SPKI window exceeds cert_tbs_len"
        ));
    }
    let cert_tbs = r.read_vec(CERT_TBS_MAX_BYTES).context("witness: cert_tbs")?;

    // Belt-and-suspenders: 26-byte SPKI prefix at the witnessed offset,
    // then the 0x04 SEC1 uncompressed-point tag.
    if cert_tbs[cert_tbs_spki_offset as usize..(cert_tbs_spki_offset as usize) + SPKI_PREFIX_LEN]
        != SPKI_P256_PREFIX
    {
        return Err(anyhow!("witness: SPKI prefix mismatch at cert_tbs_spki_offset"));
    }
    if cert_tbs[(cert_tbs_spki_offset as usize) + SPKI_PREFIX_LEN] != 0x04 {
        return Err(anyhow!(
            "witness: SEC1 uncompressed-point tag (0x04) missing after SPKI prefix"
        ));
    }

    // v8 raw (r, s).
    let cert_sig_r = r.read_array::<ECDSA_SCALAR_LEN>().context("witness: cert_sig_r")?;
    let cert_sig_s = r.read_array::<ECDSA_SCALAR_LEN>().context("witness: cert_sig_s")?;

    // v9 signedAttrs + content sig.
    let signed_attrs_len = r.read_u32_le().context("witness: signed_attrs_len")?;
    if (signed_attrs_len as usize) > SIGNED_ATTRS_MAX_BYTES {
        return Err(anyhow!(
            "witness: signed_attrs_len exceeds SIGNED_ATTRS_MAX_BYTES"
        ));
    }
    if (signed_attrs_len as usize) > SIGNED_ATTRS_MAX_BYTES - 9 {
        return Err(anyhow!("witness: signed_attrs_len exceeds raw bound"));
    }
    let signed_attrs_md_offset = r
        .read_u32_le()
        .context("witness: signed_attrs_md_offset")?;
    if (signed_attrs_md_offset as usize) + SIGNED_ATTRS_MD_WINDOW_LEN
        > (signed_attrs_len as usize)
    {
        return Err(anyhow!(
            "witness: signed_attrs_md_offset + MD window exceeds signed_attrs_len"
        ));
    }
    let signed_attrs = r
        .read_vec(SIGNED_ATTRS_MAX_BYTES)
        .context("witness: signed_attrs")?;

    // First raw byte must be the CAdES `[0] IMPLICIT` tag 0xA0.
    if signed_attrs_len == 0 || signed_attrs[0] != 0xA0 {
        return Err(anyhow!(
            "witness: signed_attrs first byte must be CAdES [0] IMPLICIT tag 0xA0"
        ));
    }

    // Belt-and-suspenders: 17-byte CMS messageDigest DER prefix.
    if signed_attrs[signed_attrs_md_offset as usize
        ..(signed_attrs_md_offset as usize) + SIGNED_ATTRS_MD_PREFIX_LEN]
        != SIGNED_ATTRS_MD_PREFIX
    {
        return Err(anyhow!(
            "witness: messageDigest DER prefix mismatch at signed_attrs_md_offset"
        ));
    }

    let content_sig_r = r
        .read_array::<ECDSA_SCALAR_LEN>()
        .context("witness: content_sig_r")?;
    let content_sig_s = r
        .read_array::<ECDSA_SCALAR_LEN>()
        .context("witness: content_sig_s")?;

    // v11 invariant 7 host-witnessed offsets + trust-anchor index.
    let subject_sn_offset_in_tbs = r
        .read_u32_le()
        .context("witness: subject_sn_offset_in_tbs")?;
    // The 9-byte serialNumber DER anchor must fit; the value-length
    // bound (`9 + L`) is checked below once `L` is read from the
    // anchor (v13, Task #37 — variable-length serialNumber).
    if (subject_sn_offset_in_tbs as usize) + SUBJECT_SN_ANCHOR_LEN > (cert_tbs_len as usize) {
        return Err(anyhow!(
            "witness: subject_sn_offset + anchor exceeds cert_tbs_len"
        ));
    }
    let subject_dn_start_offset_in_tbs = r
        .read_u32_le()
        .context("witness: subject_dn_start_offset_in_tbs")?;
    // Range sanity: subject_dn_start MUST precede subject_sn (the
    // in-circuit `vlt` check enforces strict inequality).
    if subject_dn_start_offset_in_tbs >= subject_sn_offset_in_tbs {
        return Err(anyhow!(
            "witness: subject_dn_start_offset must precede subject_sn_offset"
        ));
    }
    if (subject_dn_start_offset_in_tbs as usize) >= (cert_tbs_len as usize) {
        return Err(anyhow!(
            "witness: subject_dn_start_offset out of cert_tbs range"
        ));
    }
    let trust_anchor_index = r.read_u32_le().context("witness: trust_anchor_index")?;
    // Bound check against compile-time table size; mirrors in-circuit
    // `vlt(trust_anchor_index, TRUST_ANCHOR_COUNT)`.
    if trust_anchor_index >= TRUST_ANCHOR_COUNT {
        return Err(anyhow!(
            "witness: trust_anchor_index {} >= TRUST_ANCHOR_COUNT {}",
            trust_anchor_index,
            TRUST_ANCHOR_COUNT
        ));
    }

    // v13 (Task #37) — variable-length X.520 serialNumber validation.
    // Belt-and-suspenders host mirror of the in-circuit gadget:
    //   * the 7 length-independent anchor bytes (idx 0, 2..=7),
    //   * the DER length linkage S == L + 7 (S = anchor[1], L = anchor[8]),
    //   * the value length L within [STABLE_ID_MIN_LEN, STABLE_ID_MAX_LEN],
    //   * the value (9 + L) fits within cert_tbs,
    //   * the ETSI EN 319 412-1 `[A-Z]{5}-` natural-person prefix.
    {
        let off = subject_sn_offset_in_tbs as usize;
        let anchor = &cert_tbs[off..off + SUBJECT_SN_ANCHOR_LEN];
        for &idx in &SUBJECT_SN_ANCHOR_CONST_IDX {
            if anchor[idx] != SUBJECT_SN_ANCHOR[idx] {
                return Err(anyhow!(
                    "witness: X.520 serialNumber DER anchor mismatch at subject_sn_offset"
                ));
            }
        }
        let s = anchor[1] as usize;
        let l = anchor[8] as usize;
        if !(STABLE_ID_MIN_LEN..=STABLE_ID_MAX_LEN).contains(&l) {
            return Err(anyhow!(
                "witness: serialNumber length {} out of v13 range [{}, {}]",
                l,
                STABLE_ID_MIN_LEN,
                STABLE_ID_MAX_LEN
            ));
        }
        if s != l + 7 {
            return Err(anyhow!(
                "witness: serialNumber DER length linkage broken (S={}, L={}, expected S==L+7)",
                s,
                l
            ));
        }
        if off + SUBJECT_SN_ANCHOR_LEN + l > cert_tbs_len as usize {
            return Err(anyhow!(
                "witness: serialNumber value (9 + L) exceeds cert_tbs_len"
            ));
        }
        let value = &cert_tbs[off + SUBJECT_SN_ANCHOR_LEN..off + SUBJECT_SN_ANCHOR_LEN + l];
        let etsi_ok =
            value[..5].iter().all(u8::is_ascii_uppercase) && value[5] == b'-';
        if !etsi_ok {
            return Err(anyhow!(
                "witness: serialNumber is not an ETSI EN 319 412-1 \
                 natural-person identifier (expected an [A-Z]{{5}}- prefix)"
            ));
        }
    }

    // v12 holder_seed at the tail.
    let holder_seed = r
        .read_array::<HOLDER_SEED_LEN>()
        .context("witness: holder_seed")?;

    if r.remaining() != 0 {
        return Err(anyhow!(
            "witness: {} trailing bytes after parse",
            r.remaining()
        ));
    }

    Ok(ParsedWitness {
        context_len,
        context,
        signed_content_len,
        signed_content,
        json_pk_offset,
        pk_hex,
        json_nonce_offset,
        nonce_hex,
        json_context_offset,
        json_declaration_offset,
        json_holder_seed_commit_offset,
        holder_seed_commit_hex,
        message_digest,
        cert_tbs_len,
        cert_tbs_spki_offset,
        cert_tbs,
        cert_sig_r,
        cert_sig_s,
        signed_attrs_len,
        signed_attrs_md_offset,
        signed_attrs,
        content_sig_r,
        content_sig_s,
        subject_sn_offset_in_tbs,
        subject_dn_start_offset_in_tbs,
        trust_anchor_index,
        holder_seed,
    })
}

/// Parse a v12 public blob. Returns `Err` for any malformed input —
/// schema version, length, or out-of-range trust-anchor index.
pub fn parse_public_blob(blob: &[u8]) -> Result<ParsedPublic, anyhow::Error> {
    if blob.is_empty() {
        return Err(anyhow!("empty public blob"));
    }
    let mut r = Reader::new(blob);

    let version = r.read_u32_le().context("public: schema version")?;
    if version != BLOB_SCHEMA_VERSION {
        return Err(anyhow!(
            "public schema version mismatch: got {}, want {}",
            version,
            BLOB_SCHEMA_VERSION
        ));
    }

    let context_hash = r.read_array::<32>().context("public: context_hash")?;
    let pk = r.read_array::<PK_BYTES>().context("public: pk")?;
    let nonce = r.read_array::<NONCE_BYTES>().context("public: nonce")?;
    let nullifier = r.read_array::<NULLIFIER_LEN>().context("public: nullifier")?;
    let enroll_commit = r
        .read_array::<ENROLL_COMMIT_LEN>()
        .context("public: enroll_commit")?;
    let enroll_nullifier = r
        .read_array::<ENROLL_NULLIFIER_LEN>()
        .context("public: enroll_nullifier")?;

    let trust_anchor_index = r.read_u32_le().context("public: trust_anchor_index")?;
    if trust_anchor_index >= TRUST_ANCHOR_COUNT {
        return Err(anyhow!(
            "public: trust_anchor_index {} >= TRUST_ANCHOR_COUNT {}",
            trust_anchor_index,
            TRUST_ANCHOR_COUNT
        ));
    }

    if r.remaining() != 0 {
        return Err(anyhow!("public: {} trailing bytes after parse", r.remaining()));
    }

    Ok(ParsedPublic {
        context_hash,
        pk,
        nonce,
        nullifier,
        enroll_commit,
        enroll_nullifier,
        trust_anchor_index,
    })
}
