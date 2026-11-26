//! Exact Ergo mainnet contextual difficulty adjustment (legacy + v2 reset + EIP-37)
//! and Appendix B legacy introduction upper envelope `B_j`.
//!
//! Matches Ergo commit `8995ff243b140e7fe716bd3204423dd35690c2e4`:
//! - `DifficultyAdjustment.scala`
//! - `DifficultySerializer.scala`
//! - `HeadersProcessor.scala`
//!
//! Pure integer arithmetic (`no_std`, zero floating point).

use alloc::vec::Vec;
use num_bigint::{BigInt, BigUint};
use num_traits::{Signed, ToPrimitive, Zero};

pub const INITIAL_DIFFICULTY: u128 = 0x0117_6500_0000;
pub const V2_RESET_DIFFICULTY: u128 = 0x6f98_d500_0000;
pub const V2_RESET_HEIGHTS: [u32; 2] = [417_792, 417_793];
pub const LEGACY_EPOCH: u32 = 1024;
pub const EIP37_EPOCH: u32 = 128;
pub const EIP37_FIRST_CHILD: u32 = 844_673;
pub const TARGET_BLOCK_MS: u64 = 120_000;
pub const PRECISION: u64 = 1_000_000_000;
pub const MAX_CAP: u128 = 1u128 << 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaaError {
    InvalidCompactDifficulty,
    ZeroDifficulty,
    DifficultyExceedsCap,
    NonPositiveElapsedTime,
    MissingAnchor,
    HeightOutOfRange,
    DifficultyMismatch { expected: u128, got: u128 },
}

/// Decode Ergo's 4-byte compact `nBits` representation into an exact positive integer.
/// Rejects negative sign bit (`0x0080_0000`), zero, or values exceeding `2^64`.
pub fn decode_compact(n_bits: u32) -> Result<u128, DaaError> {
    if n_bits & 0x0080_0000 != 0 {
        return Err(DaaError::InvalidCompactDifficulty);
    }
    let exponent = (n_bits >> 24) as usize;
    let mantissa = (n_bits & 0x007f_ffff) as u128;
    let d = if exponent <= 3 {
        mantissa >> (8 * (3 - exponent))
    } else {
        let shift = 8 * (exponent - 3);
        if shift >= 128 {
            return Err(DaaError::DifficultyExceedsCap);
        }
        mantissa
            .checked_shl(shift as u32)
            .ok_or(DaaError::DifficultyExceedsCap)?
    };
    if d == 0 {
        return Err(DaaError::ZeroDifficulty);
    }
    if d > MAX_CAP {
        return Err(DaaError::DifficultyExceedsCap);
    }
    Ok(d)
}

/// Numerical compact round-trip `C(v) = decode(encode(v))` for any non-negative `BigUint`,
/// matching Java's signed `BigInteger.toByteArray()` + `DifficultySerializer.encodeCompactBits`.
pub fn compact_roundtrip_big(v: &BigUint) -> BigUint {
    if v.is_zero() {
        return BigUint::zero();
    }
    // Java BigInteger.toByteArray() big-endian two's complement representation:
    // prepend 0x00 if MSB of first byte is 1.
    let raw = v.to_bytes_be();
    let needs_sign_zero = (raw[0] & 0x80) != 0;
    let size = raw.len() + usize::from(needs_sign_zero);
    // Keep top 3 bytes of the Java signed array
    let byte_at = |idx: usize| -> u8 {
        if needs_sign_zero {
            if idx == 0 {
                0
            } else {
                raw.get(idx - 1).copied().unwrap_or(0)
            }
        } else {
            raw.get(idx).copied().unwrap_or(0)
        }
    };
    let mantissa: u32 = if size <= 3 {
        let mut m = 0u32;
        for i in 0..size {
            m = (m << 8) | (byte_at(i) as u32);
        }
        m << (8 * (3 - size))
    } else {
        ((byte_at(0) as u32) << 16) | ((byte_at(1) as u32) << 8) | (byte_at(2) as u32)
    };
    // If mantissa has bit 23 set (impossible when needs_sign_zero applied properly,
    // kept exact to match DifficultySerializer):
    let (exp, mant) = if (mantissa & 0x0080_0000) != 0 {
        (size + 1, mantissa >> 8)
    } else {
        (size, mantissa)
    };
    if exp <= 3 {
        BigUint::from(mant >> (8 * (3 - exp)))
    } else {
        BigUint::from(mant) << (8 * (exp - 3))
    }
}

/// Epoch boundary anchor `(height, timestamp, decoded_difficulty)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DaaAnchor {
    pub height: u32,
    pub timestamp: i64,
    pub difficulty: u128,
}

/// Linear regression prediction matching Ergo's `DifficultyAdjustment.interpolate`
/// for `m = 1..=8` intervals ending at heights `x_0, ..., x_{m-1}` (with spacing `epoch`).
pub fn interpolate_prediction(heights: &[u32], y_vals: &[BigInt], epoch: u32) -> BigInt {
    let m = heights.len();
    debug_assert!(m >= 1 && m == y_vals.len());
    if m == 1 {
        return y_vals[0].clone();
    }
    let m_bi = BigInt::from(m as i64);
    let p_bi = BigInt::from(PRECISION);
    let mut x_sum = BigInt::zero();
    let mut y_sum = BigInt::zero();
    let mut xy_sum = BigInt::zero();
    let mut x2_sum = BigInt::zero();
    for (&h, y) in heights.iter().zip(y_vals.iter()) {
        let x = BigInt::from(h as i64);
        x_sum += &x;
        y_sum += y;
        xy_sum += &x * y;
        x2_sum += &x * &x;
    }
    let b_num = (&m_bi * &xy_sum - &x_sum * &y_sum) * &p_bi;
    let b_den = &m_bi * &x2_sum - &x_sum * &x_sum;
    let b = b_num / b_den; // Rust BigInt `/` truncates toward zero, matching JVM BigInteger.divide!
    let a = ((&y_sum * &p_bi - &b * &x_sum) / &m_bi) / &p_bi;
    let next_x = BigInt::from(*heights.last().unwrap() as i64 + epoch as i64);
    a + (b * next_x) / &p_bi
}

fn clamp_big(val: BigInt, lo: &BigInt, hi: &BigInt) -> BigInt {
    if val < *lo {
        lo.clone()
    } else if val > *hi {
        hi.clone()
    } else {
        val
    }
}

/// Compute exact Ergo required difficulty for `child_height >= 2`, given:
/// - `parent_difficulty`: decoded difficulty of `child_height - 1`
/// - `anchors`: chronological epoch boundary anchors needed when retargeting
///   (heights `parent - k*epoch` for `k = 8..=0`, excluding 0).
pub fn required_difficulty(
    child_height: u32,
    parent_difficulty: u128,
    anchors: &[DaaAnchor],
) -> Result<u128, DaaError> {
    if child_height < 2 {
        return Err(DaaError::HeightOutOfRange);
    }
    if child_height == 2 {
        return Ok(INITIAL_DIFFICULTY);
    }
    if V2_RESET_HEIGHTS.contains(&child_height) {
        return Ok(V2_RESET_DIFFICULTY);
    }
    let is_eip37 = child_height >= EIP37_FIRST_CHILD;
    let epoch = if is_eip37 { EIP37_EPOCH } else { LEGACY_EPOCH };
    let parent_height = child_height - 1;
    if parent_height % epoch != 0 {
        return Ok(parent_difficulty);
    }
    // At child_height == 1025 (parent_height == 1024), only 1 anchor exists (1024),
    // so there are 0 complete intervals -> carry parent difficulty.
    if !is_eip37 && parent_height == LEGACY_EPOCH {
        return Ok(parent_difficulty);
    }
    // Extract exact expected sample heights
    let mut expected_heights = Vec::with_capacity(9);
    for back in (0..=8u32).rev() {
        if let Some(h) = parent_height.checked_sub(back * epoch) {
            if h > 0 {
                expected_heights.push(h);
            }
        }
    }
    if expected_heights.len() < 2 {
        return Ok(parent_difficulty);
    }
    // Locate each expected anchor in `anchors`
    let mut selected = Vec::with_capacity(expected_heights.len());
    for &eh in &expected_heights {
        let found = anchors
            .iter()
            .find(|a| a.height == eh)
            .ok_or(DaaError::MissingAnchor)?;
        selected.push(*found);
    }
    let interval_count = selected.len() - 1;
    let mut right_heights = Vec::with_capacity(interval_count);
    let mut y_vals = Vec::with_capacity(interval_count);
    let desired = BigInt::from(TARGET_BLOCK_MS) * BigInt::from(epoch as u64);
    for i in 0..interval_count {
        let left = selected[i];
        let right = selected[i + 1];
        let dt = right
            .timestamp
            .checked_sub(left.timestamp)
            .ok_or(DaaError::NonPositiveElapsedTime)?;
        if dt <= 0 {
            return Err(DaaError::NonPositiveElapsedTime);
        }
        let y = (BigInt::from(right.difficulty) * &desired) / BigInt::from(dt);
        right_heights.push(right.height);
        y_vals.push(y);
    }
    let pred = interpolate_prediction(&right_heights, &y_vals, epoch);
    let normalized = if pred.is_positive() {
        compact_roundtrip_big(pred.magnitude())
    } else {
        compact_roundtrip_big(&BigUint::from(INITIAL_DIFFICULTY))
    };

    let final_big = if !is_eip37 {
        normalized
    } else {
        let lo = BigInt::from(parent_difficulty / 2);
        let hi = BigInt::from(parent_difficulty + parent_difficulty / 2);
        let limited = clamp_big(BigInt::from(normalized), &lo, &hi);
        let y_last = y_vals.last().unwrap();
        let average = (y_last + &limited) / BigInt::from(2);
        let clamped_avg = clamp_big(average, &lo, &hi);
        if clamped_avg.is_positive() {
            compact_roundtrip_big(clamped_avg.magnitude())
        } else {
            compact_roundtrip_big(&BigUint::from(INITIAL_DIFFICULTY))
        }
    };
    let result = final_big
        .to_u128()
        .ok_or(DaaError::DifficultyExceedsCap)?;
    if result == 0 {
        return Err(DaaError::ZeroDifficulty);
    }
    if result > MAX_CAP {
        return Err(DaaError::DifficultyExceedsCap);
    }
    Ok(result)
}

/// Compute exact Appendix B legacy introduction upper bound `B_j` for a legacy retarget
/// parent `j = 1024 * (q + 1) <= 843_776`, evaluated at height `j - k0` (`k0 = 64`).
///
/// Uses `D(j-k0)`, `t(j-k0)`, and the earlier legacy anchors `j - m*1024` (with `m = 1..=8`).
/// Pure exact rational/integer arithmetic — no floating point.
pub fn appendix_b_legacy_bound(
    j: u32,
    k0: u32,
    d_at_j_minus_k0: u128,
    t_at_j_minus_k0: i64,
    legacy_anchors: &[DaaAnchor],
) -> Result<u128, DaaError> {
    // Collect earlier anchors j - 8*1024 ..= j - 1024 (> 0)
    let mut earlier = Vec::with_capacity(8);
    for back in (1..=8u32).rev() {
        if let Some(h) = j.checked_sub(back * LEGACY_EPOCH) {
            if h > 0 {
                let a = legacy_anchors
                    .iter()
                    .find(|a| a.height == h)
                    .ok_or(DaaError::MissingAnchor)?;
                earlier.push(*a);
            }
        }
    }
    if earlier.is_empty() {
        return Ok(INITIAL_DIFFICULTY);
    }
    let last_anchor = *earlier.last().unwrap(); // height j - 1024
    let delta_min = (t_at_j_minus_k0 as i128) + (k0 as i128) - (last_anchor.timestamp as i128);
    if delta_min <= 0 {
        return Err(DaaError::NonPositiveElapsedTime);
    }
    let desired = BigInt::from(TARGET_BLOCK_MS) * BigInt::from(LEGACY_EPOCH as u64);
    let y_max = (BigInt::from(d_at_j_minus_k0) * &desired) / BigInt::from(delta_min);

    let ell = earlier.len(); // number of complete intervals including the bounded last interval
    if ell == 1 {
        let ym = y_max.to_u128().unwrap_or(MAX_CAP);
        return Ok(INITIAL_DIFFICULTY.max(ym));
    }
    // Earlier (ell - 1) actual intervals
    let mut y_earlier = Vec::with_capacity(ell - 1);
    for i in 0..(ell - 1) {
        let dt = (earlier[i + 1].timestamp as i128) - (earlier[i].timestamp as i128);
        if dt <= 0 {
            return Err(DaaError::NonPositiveElapsedTime);
        }
        let y = (BigInt::from(earlier[i + 1].difficulty) * &desired) / BigInt::from(dt);
        y_earlier.push(y);
    }
    // Exact rational sum: sum_{i=1..ell-1} c_i * Y_i + (4/ell) * Y_max + 2 + E*(ell+1)/(2*P0)
    // where c_i = 2*(3*i - ell - 2) / (ell * (ell - 1)) for 1-based i = 1..=ell-1.
    // Common denominator: D_comm = 2 * P0 * ell * (ell - 1).
    let ell_i = ell as i64;
    let p0 = PRECISION as i64;
    let d_comm = BigInt::from(2 * p0 * ell_i * (ell_i - 1));
    let mut num = BigInt::zero();
    for (idx0, y_i) in y_earlier.iter().enumerate() {
        let i = (idx0 + 1) as i64;
        // c_i * d_comm = 2*(3*i - ell - 2) * 2 * p0
        let w = BigInt::from(4 * p0 * (3 * i - ell_i - 2));
        num += w * y_i;
    }
    // (4/ell) * d_comm = 8 * p0 * (ell - 1)
    num += BigInt::from(8 * p0 * (ell_i - 1)) * &y_max;
    // + 2 * d_comm
    num += BigInt::from(2) * &d_comm;
    // + E*(ell+1)/(2*P0) * d_comm = E * (ell+1) * ell * (ell-1)
    num += BigInt::from((LEGACY_EPOCH as i64) * (ell_i + 1) * ell_i * (ell_i - 1));

    // Take ceiling(num / d_comm)
    let ceil_val = if !num.is_positive() {
        0u128
    } else {
        let q = (&num + &d_comm - BigInt::from(1)) / &d_comm;
        q.to_u128().unwrap_or(MAX_CAP)
    };
    Ok(INITIAL_DIFFICULTY.max(ceil_val))
}
