#!/usr/bin/env python3
"""Certified pure exact-rational (fractions.Fraction) parameter verifier for
Ergo NiPoPoW V2 (`V2Production128`, strict 128-bit end-to-end security).

Zero floating-point arithmetic is used in any inequality proof or maturity certification.
Transcendental functions ln(1+u), -ln(1-v), and exp(x) are enclosed by provable
exact rational upper/lower Taylor/artanh bounds with dyadic rounding in the safe direction.
"""

from fractions import Fraction
import math


def trunc_rat_lo(x: Fraction, bits: int = 160) -> Fraction:
    scale = 1 << bits
    n = (x.numerator * scale) // x.denominator
    res = Fraction(n, scale)
    assert res <= x
    return res


def trunc_rat_hi(x: Fraction, bits: int = 160) -> Fraction:
    scale = 1 << bits
    num = x.numerator * scale
    n = num // x.denominator + (1 if num % x.denominator != 0 else 0)
    res = Fraction(n, scale)
    assert res >= x
    return res


def ln1p_enclosure(u: Fraction, terms: int = 40):
    """Exact rational (lo, hi) for ln(1 + u), 0 < u < 1 via 2*artanh(u/(2+u))."""
    assert Fraction(0) < u < Fraction(1)
    y = u / (2 + u)
    y2 = y * y
    s = Fraction(0)
    p = y
    for j in range(terms):
        s += p / (2 * j + 1)
        p *= y2
    lo = trunc_rat_lo(2 * s)
    hi = trunc_rat_hi(2 * (s + p / ((2 * terms + 1) * (1 - y2))))
    assert lo < hi
    return lo, hi


def neg_ln1m_enclosure(v: Fraction, terms: int = 35):
    """Exact rational (lo, hi) for -ln(1 - v), 0 < v < 1 via 2*artanh(v/(2-v))."""
    assert Fraction(0) < v < Fraction(1)
    y = v / (2 - v)
    y2 = y * y
    s = Fraction(0)
    p = y
    for j in range(terms):
        s += p / (2 * j + 1)
        p *= y2
    lo = trunc_rat_lo(2 * s)
    hi = trunc_rat_hi(2 * (s + p / ((2 * terms + 1) * (1 - y2))))
    assert lo < hi
    return lo, hi


def ln2_enclosure(terms: int = 35):
    return neg_ln1m_enclosure(Fraction(1, 2), terms)


def ln_int_enclosure(n: int):
    assert n >= 1
    k = n.bit_length() - 1
    ln2_lo, ln2_hi = ln2_enclosure(35)
    base_lo, base_hi = k * ln2_lo, k * ln2_hi
    rem = Fraction(n, 1 << k) - 1
    if rem == 0:
        return base_lo, base_hi
    r_lo, r_hi = ln1p_enclosure(rem, 35)
    return trunc_rat_lo(base_lo + r_lo), trunc_rat_hi(base_hi + r_hi)


def exp_pos_enclosure(x: Fraction, terms: int = 35):
    assert x > 0 and terms + 1 > x
    x_lo = trunc_rat_lo(x, 140)
    x_hi = trunc_rat_hi(x, 140)

    def eval_series(xv: Fraction, want_hi: bool) -> Fraction:
        s = Fraction(1)
        term = Fraction(1)
        for k in range(1, terms + 1):
            term = term * xv / k
            s += term
        if not want_hi:
            return trunc_rat_lo(s, 140)
        nxt = term * xv / (terms + 1)
        return trunc_rat_hi(s + nxt / (1 - xv / (terms + 1)), 140)

    lo = eval_series(x_lo, False)
    hi = eval_series(x_hi, True)
    assert lo < hi
    return lo, hi


def log2_frac(fr: Fraction) -> float:
    return math.log2(fr.numerator) - math.log2(fr.denominator)


def verify_profile(
    name: str,
    grid_n: int,
    L: int,
    s: int,
    beta: Fraction,
    r_theta: Fraction,
    b1: int,
    draws_per_scale: int,
    expected_m_sampled,
    expected_m_exact,
    race_target_bits: int,
    QA_exp: int,
    audit_target_bits: int,
    rank_A: int,
    rank_t: int,
    rank_target_bits: int,
    early_target_bits: int,
    check_union_bits=None,
):
    a = Fraction(4, 15)
    h = Fraction(3, 4) * (1 - Fraction(1, 1 << 32))
    b = Fraction(16, 15)
    nu = Fraction(1, 20)
    omega = Fraction(16, 1)
    k0 = 64
    p_star = Fraction(1, 2) + Fraction(1, 1 << 37)
    Q_native = (1 << 80) + 1
    Q_A = (1 << QA_exp) + 1

    # Fresh CQ ratio invariant: s/L == 15/64 (23.4375%)
    assert Fraction(s, L) == Fraction(15, 64), f"{name}: fresh CQ ratio drifted"

    ln2_lo, ln2_hi = ln2_enclosure(35)
    theta_lo, theta_hi = ln1p_enclosure(r_theta - 1, 35)
    z = Fraction(1) - a * (r_theta - 1) / h - Fraction(1, 1 << 40)
    v = Fraction(1) - z
    v_lo, v_hi = trunc_rat_lo(v, 140), trunc_rat_hi(v, 140)
    neg_ln_z_lo, _ = neg_ln1m_enclosure(v_lo, 30)
    _, neg_ln_z_hi = neg_ln1m_enclosure(v_hi, 30)

    c_theta = b * nu * (r_theta - 1)
    eta_lo = trunc_rat_lo(neg_ln_z_lo + c_theta, 140)
    eta_hi = trunc_rat_hi(neg_ln_z_hi + c_theta, 140)

    # Admissibility checks (eq. 10, 14, pruning)
    assert eta_lo > c_theta
    assert eta_hi <= theta_lo
    _, exp_eta_hi = exp_pos_enclosure(eta_hi, 30)
    assert p_star * exp_eta_hi <= Fraction(1)
    c_eta_hi = b * nu * (exp_eta_hi - 1)
    exp_neg_ln_z_lo, _ = exp_pos_enclosure(neg_ln_z_lo, 30)
    assert a * (r_theta - 1) + h * (Fraction(1) / exp_neg_ln_z_lo - 1) <= 0
    assert eta_lo > c_eta_hi
    exp_eta_minus_ceta_lo, _ = exp_pos_enclosure(eta_lo - c_eta_hi, 30)
    assert a * (exp_eta_hi - 1) + h * (Fraction(1) / exp_eta_minus_ceta_lo - 1) <= 0

    J_beta_lo = beta * theta_lo - eta_hi
    J_1_lo = theta_lo - eta_hi
    assert J_beta_lo > 0 and J_1_lo > 0

    # Autolykos v2 rank bound (eq. 5-6)
    rank_sum = Fraction(0)
    for r in range(rank_t):
        rank_sum += Fraction(
            math.comb(rank_t - 1, r) * ((r + 1) ** (8 * (rank_t - r - 1))),
            1 << (168 * (rank_t - r - 1) + 248 * r),
        )
    eps_rank = rank_sum * (1 << (31 + rank_A * rank_t))
    assert eps_rank < Fraction(1, 1 << rank_target_bits)
    assert Fraction(1 << 64) * Fraction(Q_native, 1 << rank_A) < Fraction(1, 60)
    assert Fraction(Q_native, 1 << rank_A) < Fraction(1, 1 << 32)

    # Early-tag survival bound (eq. 17)
    eps_early = Fraction(Q_native) * (p_star ** s)
    assert eps_early < Fraction(1, 1 << early_target_bits)

    # Geometric audit miss bound (eq. 4)
    delta = Fraction(1) - beta
    miss = Fraction(1) - delta / (2 * (1 - delta))
    eps_audit = Fraction(Q_A) * (miss ** draws_per_scale)
    assert eps_audit < Fraction(1, 1 << audit_target_bits)

    # Race bounds (eq. 25)
    _, ln_glob_hi = ln_int_enclosure(grid_n * 4 * Q_native * Q_native)
    _, ln_loc_hi = ln_int_enclosure(grid_n * Q_native)
    common_hi = eta_hi * k0 + a * omega * (r_theta - 1)

    extras = [
        (ln_glob_hi, common_hi + theta_hi * b1),
        (ln_glob_hi, common_hi + eta_hi * b1),
        (ln_loc_hi, common_hi + eta_hi * (L + 1) + c_theta),
    ]
    sampled_logs = []
    exact_logs = []
    for idx, (ln_pre_hi, extra_hi) in enumerate(extras):
        es = ln_pre_hi + extra_hi - (expected_m_sampled[idx] - k0) * J_beta_lo
        assert es <= -race_target_bits * ln2_hi, f"{name}: sampled zone {idx} failed"
        sampled_logs.append(float(es / ln2_lo))

        ee = ln_pre_hi + extra_hi - (expected_m_exact[idx] - k0) * J_1_lo
        assert ee <= -race_target_bits * ln2_hi, f"{name}: exact zone {idx} failed"
        exact_logs.append(float(ee / ln2_lo))

    union_str = ""
    if check_union_bits is not None:
        eps_union = eps_rank + eps_audit + eps_early + Fraction(2, 1 << race_target_bits)
        assert eps_union < Fraction(1, 1 << check_union_bits), f"{name}: union sum failed"
        eps_union_3 = eps_rank + eps_audit + eps_early + Fraction(3, 1 << race_target_bits)
        assert eps_union_3 < Fraction(1, 1 << check_union_bits), f"{name}: conservative union failed"
        union_str = (
            f" | union(5) <= 2^({log2_frac(eps_union):.2f}), "
            f"union(6) <= 2^({log2_frac(eps_union_3):.2f}) < 2^(-{check_union_bits})"
        )

    print(
        f"[PASS] {name}: m_sampled={expected_m_sampled}, m_exact={expected_m_exact}, "
        f"draws={draws_per_scale} | eps_rank<=2^({log2_frac(eps_rank):.2f}), "
        f"eps_early<=2^({log2_frac(eps_early):.2f}), eps_audit<=2^({log2_frac(eps_audit):.2f}), "
        f"race_s<=2^({max(sampled_logs):.2f}), race_e<=2^({max(exact_logs):.2f}){union_str}"
    )


def main():
    verify_profile(
        name="V2Production128 (128-bit end-to-end)",
        grid_n=513,
        L=896,
        s=210,
        beta=Fraction(3, 4),
        r_theta=Fraction(27, 20),
        b1=9072,
        draws_per_scale=982,
        expected_m_sampled=[40099, 21769, 4142],
        expected_m_exact=[19879, 10807, 2083],
        race_target_bits=131,
        QA_exp=128,
        audit_target_bits=130,
        rank_A=151,
        rank_t=40,
        rank_target_bits=131,
        early_target_bits=129,
        check_union_bits=128,
    )
    print("V2_PRODUCTION_128_RATIONALLY_CERTIFIED")


if __name__ == "__main__":
    main()
