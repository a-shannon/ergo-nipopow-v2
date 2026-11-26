//! Canonical Ergo header codec matching Ergo commit `8995ff243b140e7fe716bd3204423dd35690c2e4`.
//!
//! Supports both:
//! - `Header::decode_with_witnesses` (fast `no_std` guest path using prover-supplied `y` witnesses), and
//! - `Header::decode_native` (standalone client verifier using `k256`, zero witness needed).

use alloc::vec::Vec;
#[cfg(not(feature = "zisk"))]
use blake2::{digest::consts::U32, Blake2b, Digest};

use crate::secp256k1::{verify_compressed_point_with_witness, PointError};

/// Largest canonical Ergo header byte length.
pub const MAX_HEADER_BYTES: usize = 514;

/// Ergo mainnet genesis header ID (height 1).
pub const MAINNET_GENESIS_ID: [u8; 32] = [
    0xb0, 0x24, 0x4d, 0xfc, 0x26, 0x7b, 0xac, 0xa9, 0x74, 0xa4, 0xca, 0xee, 0x06, 0x12, 0x03, 0x21,
    0x56, 0x27, 0x84, 0x30, 0x3a, 0x8a, 0x68, 0x89, 0x76, 0xae, 0x56, 0x17, 0x0e, 0x4d, 0x17, 0x5b,
];

/// Height of the last Autolykos v1 header on Ergo mainnet.
pub const AUTOLYKOS_V1_LAST_HEIGHT: u32 = 417_791;

/// Height of Autolykos v2 activation on Ergo mainnet.
pub const AUTOLYKOS_V2_FIRST_HEIGHT: u32 = 417_792;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    Empty,
    TooLong,
    UnexpectedEof,
    TrailingBytes,
    VlqOverflow,
    NonMinimalVlq,
    HeightOutOfRange,
    InvalidPoint(PointError),
    NonCanonicalDistance,
    DistanceTooLong,
    ExtensionNotAllowed,
    ExtensionTooLong,
    PowVersionMismatch,
    NonCanonicalHeader,
    IdMismatch,
    EraVersionMismatch,
    MissingPointWitness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupElement(pub [u8; 33]);

impl GroupElement {
    pub const INFINITY: Self = Self([0u8; 33]);

    pub const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PowSolution {
    V1 {
        pk: GroupElement,
        w: GroupElement,
        nonce: [u8; 8],
        /// Unsigned big-endian magnitude (Bouncy Castle 1.66: zero is empty).
        distance: Vec<u8>,
    },
    V2 {
        pk: GroupElement,
        nonce: [u8; 8],
    },
}

/// Witness coordinates for curve points inside a header (1 for v2+, 2 for v1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeaderPointWitness {
    pub pk_y: [u8; 32],
    pub w_y: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: i8,
    pub parent_id: [u8; 32],
    pub ad_proofs_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub state_root: [u8; 33],
    /// Native JVM signed 64-bit timestamp.
    pub timestamp: i64,
    pub extension_root: [u8; 32],
    pub n_bits: u32,
    pub height: u32,
    pub votes: [u8; 3],
    pub unparsed_bytes: Vec<u8>,
    pub pow: PowSolution,
}

impl Header {
    /// Decode and canonically verify raw header bytes using witness `y` coordinates.
    pub fn decode_with_witness(
        bytes: &[u8],
        witness: &HeaderPointWitness,
        expected_id: Option<&[u8; 32]>,
    ) -> Result<Self, HeaderError> {
        let header = Self::parse_raw(bytes, |pk, w_opt| {
            verify_compressed_point_with_witness(pk, &witness.pk_y)
                .map_err(HeaderError::InvalidPoint)?;
            if let Some(w) = w_opt {
                verify_compressed_point_with_witness(w, &witness.w_y)
                    .map_err(HeaderError::InvalidPoint)?;
            } else if witness.w_y != [0u8; 32] {
                return Err(HeaderError::InvalidPoint(PointError::NonCanonicalInfinity));
            }
            Ok(())
        })?;
        if let Some(expected) = expected_id {
            if &blake2b256(bytes) != expected {
                return Err(HeaderError::IdMismatch);
            }
        }
        Ok(header)
    }

    /// Decode and canonically verify raw header bytes natively with `k256`.
    #[cfg(feature = "native-pow")]
    pub fn decode_native(
        bytes: &[u8],
        expected_id: Option<&[u8; 32]>,
    ) -> Result<(Self, HeaderPointWitness), HeaderError> {
        let mut wit = HeaderPointWitness {
            pk_y: [0u8; 32],
            w_y: [0u8; 32],
        };
        let header = Self::parse_raw(bytes, |pk, w_opt| {
            wit.pk_y = crate::secp256k1::compute_point_witness(pk)
                .map_err(HeaderError::InvalidPoint)?;
            if let Some(w) = w_opt {
                wit.w_y = crate::secp256k1::compute_point_witness(w)
                    .map_err(HeaderError::InvalidPoint)?;
            }
            Ok(())
        })?;
        if let Some(expected) = expected_id {
            if &blake2b256(bytes) != expected {
                return Err(HeaderError::IdMismatch);
            }
        }
        Ok((header, wit))
    }

    fn parse_raw(
        bytes: &[u8],
        mut check_points: impl FnMut(&[u8; 33], Option<&[u8; 33]>) -> Result<(), HeaderError>,
    ) -> Result<Self, HeaderError> {
        if bytes.is_empty() {
            return Err(HeaderError::Empty);
        }
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(HeaderError::TooLong);
        }
        let mut reader = Reader { bytes, pos: 0 };
        let version = reader.byte()? as i8;
        let parent_id = reader.array()?;
        let ad_proofs_root = reader.array()?;
        let transactions_root = reader.array()?;
        let state_root = reader.array()?;
        let timestamp = reader.vlq()? as i64;
        let extension_root = reader.array()?;
        let n_bits = u32::from_be_bytes(reader.array()?);
        let height = reader.vlq()?;
        if height > i32::MAX as u64 {
            return Err(HeaderError::HeightOutOfRange);
        }
        let votes = reader.array()?;
        let unparsed_bytes = if version > 1 {
            let len = reader.byte()? as usize;
            if version > 4 {
                reader.take(len)?.to_vec()
            } else {
                if len != 0 {
                    return Err(HeaderError::ExtensionNotAllowed);
                }
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let pk_bytes: [u8; 33] = reader.array()?;
        let pow = if version == 1 {
            let w_bytes: [u8; 33] = reader.array()?;
            check_points(&pk_bytes, Some(&w_bytes))?;
            let nonce = reader.array()?;
            let len = reader.byte()? as usize;
            let distance = reader.take(len)?.to_vec();
            if distance.first() == Some(&0) {
                return Err(HeaderError::NonCanonicalDistance);
            }
            PowSolution::V1 {
                pk: GroupElement(pk_bytes),
                w: GroupElement(w_bytes),
                nonce,
                distance,
            }
        } else {
            check_points(&pk_bytes, None)?;
            PowSolution::V2 {
                pk: GroupElement(pk_bytes),
                nonce: reader.array()?,
            }
        };
        if reader.pos != bytes.len() {
            return Err(HeaderError::TrailingBytes);
        }
        let header = Self {
            version,
            parent_id,
            ad_proofs_root,
            transactions_root,
            state_root,
            timestamp,
            extension_root,
            n_bits,
            height: height as u32,
            votes,
            unparsed_bytes,
            pow,
        };
        // Round-trip canonical re-encoding check
        let canonical = header.encode()?;
        if canonical.as_slice() != bytes {
            return Err(HeaderError::NonCanonicalHeader);
        }
        Ok(header)
    }

    pub fn encode(&self) -> Result<Vec<u8>, HeaderError> {
        if self.height > i32::MAX as u32 {
            return Err(HeaderError::HeightOutOfRange);
        }
        if self.version <= 4 && !self.unparsed_bytes.is_empty() {
            return Err(HeaderError::ExtensionNotAllowed);
        }
        if self.unparsed_bytes.len() > u8::MAX as usize {
            return Err(HeaderError::ExtensionTooLong);
        }
        match (&self.pow, self.version) {
            (PowSolution::V1 { distance, .. }, 1) => {
                if distance.len() > u8::MAX as usize {
                    return Err(HeaderError::DistanceTooLong);
                }
                if distance.first() == Some(&0) {
                    return Err(HeaderError::NonCanonicalDistance);
                }
            }
            (PowSolution::V2 { .. }, v) if v != 1 => {}
            _ => return Err(HeaderError::PowVersionMismatch),
        }
        let mut out = Vec::with_capacity(MAX_HEADER_BYTES);
        out.push(self.version as u8);
        out.extend_from_slice(&self.parent_id);
        out.extend_from_slice(&self.ad_proofs_root);
        out.extend_from_slice(&self.transactions_root);
        out.extend_from_slice(&self.state_root);
        put_vlq(self.timestamp as u64, &mut out);
        out.extend_from_slice(&self.extension_root);
        out.extend_from_slice(&self.n_bits.to_be_bytes());
        put_vlq(self.height as u64, &mut out);
        out.extend_from_slice(&self.votes);
        if self.version > 1 {
            out.push(self.unparsed_bytes.len() as u8);
            out.extend_from_slice(&self.unparsed_bytes);
        }
        match &self.pow {
            PowSolution::V1 {
                pk,
                w,
                nonce,
                distance,
            } => {
                out.extend_from_slice(pk.as_bytes());
                out.extend_from_slice(w.as_bytes());
                out.extend_from_slice(nonce);
                out.push(distance.len() as u8);
                out.extend_from_slice(distance);
            }
            PowSolution::V2 { pk, nonce } => {
                out.extend_from_slice(pk.as_bytes());
                out.extend_from_slice(nonce);
            }
        }
        Ok(out)
    }

    /// Enforce height-to-PoW-era binding (`v1` for heights `1..=417_791`, `v2+` for heights `>= 417_792`).
    pub fn check_era_binding(&self) -> Result<(), HeaderError> {
        let expect_v1 = self.height <= AUTOLYKOS_V1_LAST_HEIGHT;
        if expect_v1 {
            if self.version != 1 {
                return Err(HeaderError::EraVersionMismatch);
            }
        } else if self.version < 2 {
            return Err(HeaderError::EraVersionMismatch);
        }
        Ok(())
    }

    pub fn id(&self) -> Result<[u8; 32], HeaderError> {
        Ok(blake2b256(&self.encode()?))
    }
}

#[cfg(not(feature = "zisk"))]
pub fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(bytes).into()
}

/// Hardware-accelerated RFC 7693 unkeyed BLAKE2b-256 via ZisK `syscall_blake2b_round`.
#[cfg(feature = "zisk")]
pub fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    const IV_UNKEYED_32: [u64; 8] = [
        0x6a09_e667_f3bc_c908 ^ 0x0101_0020,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ];
    let mut h = IV_UNKEYED_32;
    let mut t = [0u64; 2];
    let mut offset = 0usize;

    while bytes.len().saturating_sub(offset) > 128 {
        let mut m = [0u64; 16];
        for i in 0..16 {
            let s = offset + i * 8;
            m[i] = u64::from_le_bytes(bytes[s..s + 8].try_into().unwrap());
        }
        let (next_lo, carry) = t[0].overflowing_add(128);
        t[0] = next_lo;
        if carry {
            t[1] = t[1].wrapping_add(1);
        }
        ziskos::zisklib::blake2b_compress(12, &mut h, &m, &t, false);
        offset += 128;
    }

    let rem = bytes.len() - offset;
    let mut block = [0u8; 128];
    block[..rem].copy_from_slice(&bytes[offset..]);
    let mut m = [0u64; 16];
    for i in 0..16 {
        let s = i * 8;
        m[i] = u64::from_le_bytes(block[s..s + 8].try_into().unwrap());
    }
    let (next_lo, carry) = t[0].overflowing_add(rem as u64);
    t[0] = next_lo;
    if carry {
        t[1] = t[1].wrapping_add(1);
    }
    ziskos::zisklib::blake2b_compress(12, &mut h, &m, &t, true);

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

fn put_vlq(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], HeaderError> {
        let end = self.pos.checked_add(len).ok_or(HeaderError::UnexpectedEof)?;
        let bytes = self.bytes.get(self.pos..end).ok_or(HeaderError::UnexpectedEof)?;
        self.pos = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, HeaderError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], HeaderError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn vlq(&mut self) -> Result<u64, HeaderError> {
        let mut value = 0u64;
        for group in 0..10 {
            let byte = self.byte()?;
            if group == 9 && byte > 1 {
                return Err(HeaderError::VlqOverflow);
            }
            if group > 0 && byte == 0 {
                return Err(HeaderError::NonMinimalVlq);
            }
            value |= ((byte & 0x7f) as u64) << (7 * group);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(HeaderError::VlqOverflow)
    }
}
