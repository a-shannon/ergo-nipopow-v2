//! Exact secp256k1 compressed-point verification for Ergo headers.
//!
//! In a zkVM guest, computing modular square roots (`(x^3 + 7)^((p+1)/4) mod p`)
//! takes ~270 modular multiplications (~300,000 rv32im cycles per point).
//! Supplying the 32-byte `y` coordinate as untrusted prover witness reduces
//! curve-membership verification to 3 modular multiplications (`y^2 == x^3 + 7 mod p`),
//! a range check (`x < p`, `y < p`), and a parity check (`(y & 1) == (prefix & 1)`).
//!
//! Because `p = 2^256 - 2^32 - 977` is prime and `y -> -y (mod p)` flips parity
//! for every nonzero `y`, there exists a valid witness `y` iff `prefix || x` is a
//! valid canonical SEC1 compressed point on secp256k1.

/// secp256k1 base field prime `p = 2^256 - 2^32 - 977` in 4 little-endian u64 limbs.
pub const P: [u64; 4] = [
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// Reduction constant `2^256 mod p = 2^32 + 977 = 0x1_0000_03D1`.
const C_REDUCE: u64 = 0x1_0000_03D1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointError {
    NonCanonicalInfinity,
    InvalidPrefix,
    CoordOutOfRange,
    ParityMismatch,
    NotOnCurve,
}

#[inline]
fn from_be_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
    ]
}

#[inline]
fn lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

#[inline]
fn sub_if_ge_p(mut a: [u64; 4]) -> [u64; 4] {
    if !lt(&a, &P) {
        let mut borrow = 0u128;
        for i in 0..4 {
            let lhs = a[i] as u128;
            let rhs = P[i] as u128 + borrow;
            if lhs >= rhs {
                a[i] = (lhs - rhs) as u64;
                borrow = 0;
            } else {
                a[i] = ((1u128 << 64) + lhs - rhs) as u64;
                borrow = 1;
            }
        }
        debug_assert_eq!(borrow, 0);
    }
    a
}

#[inline]
fn add_mod(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let sum = a[i] as u128 + b[i] as u128 + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
    }
    if carry != 0 {
        // Subtract p <=> add C_REDUCE (since 2^256 - p = C_REDUCE)
        let mut c2 = C_REDUCE as u128;
        for limb in &mut out {
            let s = *limb as u128 + c2;
            *limb = s as u64;
            c2 = s >> 64;
        }
        debug_assert_eq!(c2, 0);
    }
    sub_if_ge_p(out)
}

#[inline]
fn mul_mod(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    // Schoolbook 4x4 -> 8 limbs
    let mut prod = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let acc = prod[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            prod[i + j] = acc as u64;
            carry = acc >> 64;
        }
        prod[i + 4] = carry as u64;
    }
    // First reduction: low + high * C_REDUCE (into 5 limbs)
    let mut r = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..4 {
        let acc = prod[i] as u128 + (prod[i + 4] as u128) * (C_REDUCE as u128) + carry;
        r[i] = acc as u64;
        carry = acc >> 64;
    }
    r[4] = carry as u64;
    // Second reduction: fold r[4] * C_REDUCE into 4 limbs
    let mut out = [0u64; 4];
    let mut c2 = (r[4] as u128) * (C_REDUCE as u128);
    for i in 0..4 {
        let acc = r[i] as u128 + c2;
        out[i] = acc as u64;
        c2 = acc >> 64;
    }
    if c2 != 0 {
        // At most 1 carry into 2^256
        let mut c3 = c2 * (C_REDUCE as u128);
        for limb in &mut out {
            let acc = *limb as u128 + c3;
            *limb = acc as u64;
            c3 = acc >> 64;
        }
        debug_assert_eq!(c3, 0);
    }
    sub_if_ge_p(out)
}

/// Verify a canonical 33-byte Ergo sigma `GroupElement` (compressed secp256k1 point
/// or 33-byte zero infinity) using a prover-supplied 32-byte big-endian `y` witness.
///
/// For infinity (`[0; 33]`), `y_witness` must be `[0; 32]`.
pub fn verify_compressed_point_with_witness(
    bytes: &[u8; 33],
    y_witness: &[u8; 32],
) -> Result<(), PointError> {
    if bytes[0] == 0 {
        return if *bytes == [0u8; 33] && *y_witness == [0u8; 32] {
            Ok(())
        } else {
            Err(PointError::NonCanonicalInfinity)
        };
    }
    if bytes[0] != 2 && bytes[0] != 3 {
        return Err(PointError::InvalidPrefix);
    }
    let mut x_be = [0u8; 32];
    x_be.copy_from_slice(&bytes[1..33]);
    let x = from_be_bytes(&x_be);
    let y = from_be_bytes(y_witness);
    if !lt(&x, &P) || !lt(&y, &P) {
        return Err(PointError::CoordOutOfRange);
    }
    let expected_odd = (bytes[0] & 1) as u64;
    if (y[0] & 1) != expected_odd {
        return Err(PointError::ParityMismatch);
    }
    let y2 = mul_mod(&y, &y);
    let x2 = mul_mod(&x, &x);
    let x3 = mul_mod(&x2, &x);
    let rhs = add_mod(&x3, &[7, 0, 0, 0]);
    if y2 != rhs {
        return Err(PointError::NotOnCurve);
    }
    Ok(())
}

/// Native host helper: compute the exact 32-byte `y` witness for a canonical 33-byte point.
#[cfg(feature = "native-pow")]
pub fn compute_point_witness(bytes: &[u8; 33]) -> Result<[u8; 32], PointError> {
    use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    if bytes[0] == 0 {
        return if *bytes == [0u8; 33] {
            Ok([0u8; 32])
        } else {
            Err(PointError::NonCanonicalInfinity)
        };
    }
    if bytes[0] != 2 && bytes[0] != 3 {
        return Err(PointError::InvalidPrefix);
    }
    let pk = PublicKey::from_sec1_bytes(bytes).map_err(|_| PointError::NotOnCurve)?;
    if pk.to_encoded_point(true).as_bytes() != bytes {
        return Err(PointError::NotOnCurve);
    }
    let uncompressed = pk.to_encoded_point(false);
    let y_slice = uncompressed.y().ok_or(PointError::NotOnCurve)?;
    let mut y = [0u8; 32];
    y.copy_from_slice(y_slice);
    verify_compressed_point_with_witness(bytes, &y)?;
    Ok(y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_and_negatives() {
        // secp256k1 generator G compressed
        let g: [u8; 33] = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let gy: [u8; 32] = [
            0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11,
            0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f,
            0xfb, 0x10, 0xd4, 0xb8,
        ];
        assert!(verify_compressed_point_with_witness(&g, &gy).is_ok());
        // Infinity valid
        assert!(verify_compressed_point_with_witness(&[0u8; 33], &[0u8; 32]).is_ok());
        // Non-zero infinity rejected
        let mut bad_inf = [0u8; 33];
        bad_inf[32] = 1;
        assert_eq!(
            verify_compressed_point_with_witness(&bad_inf, &[0u8; 32]),
            Err(PointError::NonCanonicalInfinity)
        );
        // Wrong parity rejected
        let mut wrong_prefix = g;
        wrong_prefix[0] = 0x03;
        assert_eq!(
            verify_compressed_point_with_witness(&wrong_prefix, &gy),
            Err(PointError::ParityMismatch)
        );
        // Tampered y rejected
        let mut bad_y = gy;
        bad_y[30] ^= 1;
        assert_eq!(
            verify_compressed_point_with_witness(&g, &bad_y),
            Err(PointError::NotOnCurve)
        );
        // Coordinate >= p rejected
        let mut overflow_x = [0xFFu8; 33];
        overflow_x[0] = 0x02;
        assert_eq!(
            verify_compressed_point_with_witness(&overflow_x, &gy),
            Err(PointError::CoordOutOfRange)
        );
        #[cfg(feature = "native-pow")]
        {
            assert_eq!(compute_point_witness(&g).unwrap(), gy);
        }
    }
}
