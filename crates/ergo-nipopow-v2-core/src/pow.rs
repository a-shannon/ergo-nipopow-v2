//! Exact native per-header Autolykos v1 & v2 PoW verifier matching Ergo
//! commit `8995ff243b140e7fe716bd3204423dd35690c2e4` (`AutolykosPowScheme.scala`).

#[cfg(feature = "native-pow")]
use k256::{elliptic_curve::PrimeField, ProjectivePoint, PublicKey, Scalar};
use num_bigint::BigUint;
use num_traits::Zero;

use crate::daa::decode_compact;
use crate::header::{blake2b256, GroupElement, Header, PowSolution};

const Q_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const N_BASE: u32 = 1 << 26;
const N_START: u32 = 614_400;
const N_PERIOD: u32 = 51_200;
const N_CAP_HEIGHT: u32 = 4_198_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePowError {
    Encoding,
    Difficulty,
    Target,
    FinitePoint,
    Scalar,
    Equation,
    Sum,
}

#[cfg(feature = "native-pow")]
pub fn verify_header_pow(header: &Header) -> Result<(), NativePowError> {
    let msg = header_message(header)?;
    let diff = decode_compact(header.n_bits).map_err(|_| NativePowError::Difficulty)?;
    let target = BigUint::from_bytes_be(&Q_BE) / BigUint::from(diff);
    if header.version == 1 {
        let PowSolution::V1 {
            pk,
            w,
            nonce,
            distance,
        } = &header.pow
        else {
            return Err(NativePowError::Encoding);
        };
        let d = BigUint::from_bytes_be(distance);
        if d >= target {
            return Err(NativePowError::Target);
        }
        let pk_point = finite_point(pk)?;
        let w_point = finite_point(w)?;
        let f = v1_scalar(&msg, nonce, pk, w);
        let d_sc = to_scalar(&d)?;
        let f_sc = to_scalar(&f)?;
        if w_point * f_sc == ProjectivePoint::GENERATOR * d_sc + pk_point {
            Ok(())
        } else {
            Err(NativePowError::Equation)
        }
    } else {
        let PowSolution::V2 { nonce, .. } = &header.pow else {
            return Err(NativePowError::Encoding);
        };
        let hit = v2_hit(&msg, nonce, header.height)?;
        if BigUint::from_bytes_be(&hit) < target {
            Ok(())
        } else {
            Err(NativePowError::Target)
        }
    }
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    use blake2::{digest::consts::U32, Blake2b, Digest};
    let mut h = Blake2b::<U32>::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn header_message(header: &Header) -> Result<[u8; 32], NativePowError> {
    let raw = header.encode().map_err(|_| NativePowError::Encoding)?;
    let tail = match (&header.pow, header.version) {
        (PowSolution::V1 { distance, .. }, 1) => {
            75usize.checked_add(distance.len()).ok_or(NativePowError::Encoding)?
        }
        (PowSolution::V2 { .. }, v) if v != 1 => 41,
        _ => return Err(NativePowError::Encoding),
    };
    let prefix = raw.len().checked_sub(tail).ok_or(NativePowError::Encoding)?;
    Ok(blake2b256(&raw[..prefix]))
}

#[cfg(feature = "native-pow")]
fn finite_point(point: &GroupElement) -> Result<ProjectivePoint, NativePowError> {
    PublicKey::from_sec1_bytes(point.as_bytes())
        .map(ProjectivePoint::from)
        .map_err(|_| NativePowError::FinitePoint)
}

#[cfg(feature = "native-pow")]
fn to_scalar(value: &BigUint) -> Result<Scalar, NativePowError> {
    let bytes = magnitude32(value)?;
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).ok_or(NativePowError::Scalar)
}

fn table_size(height: u32, version: i8) -> u32 {
    let mut n = N_BASE;
    let capped = height.min(N_CAP_HEIGHT);
    if version != 1 && capped >= N_START {
        for _ in 0..=((capped - N_START) / N_PERIOD) {
            n = (n / 100) * 105;
        }
    }
    n
}

fn m_bytes() -> [u8; 8192] {
    let mut m = [0u8; 8192];
    for (i, chunk) in m.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&(i as u64).to_be_bytes());
    }
    m
}

fn indices(seed: &[u8; 32], n: u32) -> [u32; 32] {
    let mut ext = [0u8; 35];
    ext[..32].copy_from_slice(seed);
    ext[32..].copy_from_slice(&seed[..3]);
    core::array::from_fn(|i| u32::from_be_bytes(ext[i..i + 4].try_into().unwrap()) % n)
}

fn mod_q_with(mut digest: [u8; 32]) -> BigUint {
    while digest >= Q_BE {
        digest = blake2b256(&digest);
    }
    BigUint::from_bytes_be(&digest)
}

fn v1_scalar(message: &[u8; 32], nonce: &[u8; 8], pk: &GroupElement, w: &GroupElement) -> BigUint {
    let seed = hash_parts(&[message, nonce]);
    let m = m_bytes();
    let mut sum = BigUint::zero();
    for index in indices(&seed, N_BASE) {
        let digest = hash_parts(&[
            &index.to_be_bytes(),
            &m,
            pk.as_bytes(),
            message,
            w.as_bytes(),
        ]);
        sum += mod_q_with(digest);
    }
    sum % BigUint::from_bytes_be(&Q_BE)
}

fn magnitude32(value: &BigUint) -> Result<[u8; 32], NativePowError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(NativePowError::Sum);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

fn v2_hit(message: &[u8; 32], nonce: &[u8; 8], height: u32) -> Result<[u8; 32], NativePowError> {
    let n = table_size(height, 2);
    let height_bytes = height.to_be_bytes();
    let m = m_bytes();
    let digest = hash_parts(&[message, nonce]);
    let preindex =
        (u64::from_be_bytes(digest[24..].try_into().unwrap()) % u64::from(n)) as u32;
    let first = hash_parts(&[&preindex.to_be_bytes(), &height_bytes, &m]);
    let seed = hash_parts(&[&first[1..], message, nonce]);
    let mut sum = BigUint::zero();
    for index in indices(&seed, n) {
        let element = hash_parts(&[&index.to_be_bytes(), &height_bytes, &m]);
        sum += BigUint::from_bytes_be(&element[1..]);
    }
    Ok(blake2b256(&magnitude32(&sum)?))
}
