//! Exact associative maturity-guard & difficulty-cap monoid for incremental
//! segment-recursive Ergo NiPoPoW V2 proving.
//!
//! Mathematical proof of associativity:
//! For any contiguous height segment `S = [a, b]` and any future extension `R = [b+1, c]`:
//! - In zones 0 & 1 (`i < s_L`), `V_{S||R}(i) = max(U_global(S), u_R)` where
//!   `u_R = gridceil(max(E_legacy(R), floor(3 * max_{r in R} D(r) / 2)))`.
//! - In zone 2 (`i >= s_L`), `V_{S||R}(i) = max(V_S(i), q_R)` where
//!   `q_R = gridceil(floor(3 * max_{r in R} D(r) / 2))`.
//! Therefore:
//! ```text
//! max_{i in S} [W(i) + m(i) * V_{S||R}(i)]
//!   = max(
//!       max_{i in S} [W(i) + m(i) * V_S(i)],
//!       W_max_z0(S) + m_0 * u_R,
//!       W_max_z1(S) + m_1 * u_R,
//!       W_max_z2(S) + m_2 * q_R,
//!     )
//! ```
//! (with inactive zones having `has_z[k] = false` so they contribute nothing).
//! Merging `S` and `R` is therefore an exact associative monoid with ZERO approximation!

use crate::profile::ProfileParams;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScoreMonoid {
    /// `max_{i in S} [W(i) + m_sampled(i) * V_S(i)]` (using caps known through end of S).
    pub a_sampled: u128,
    /// `max_{i in S} [W(i) + m_exact(i) * V_S(i)]` (using caps known through end of S).
    pub a_exact: u128,
    /// Whether this segment contains at least one origin in zone `0, 1, 2`.
    pub has_zone: [bool; 3],
    /// Maximum prefix work `W(i)` among origins in zone `k` inside this segment.
    pub w_max_zone: [u128; 3],
    /// Running cap contribution for early zones (`< s_L`): `gridceil(max(E_legacy(S), floor(3*D_max(S)/2)))`.
    pub u_global_contrib: u128,
    /// Running cap contribution for modern zone (`>= s_L`): `gridceil(floor(3*D_max(S)/2))`.
    pub q_modern_contrib: u128,
}

impl ScoreMonoid {
    pub const fn identity() -> Self {
        Self {
            a_sampled: 0,
            a_exact: 0,
            has_zone: [false; 3],
            w_max_zone: [0; 3],
            u_global_contrib: 0,
            q_modern_contrib: 0,
        }
    }

    /// Observe a single origin `height` with prefix work `w_prefix`, local cap `v_local`
    /// (already computed using all difficulties through `height` and the preceding `L+k0` window),
    /// and cap contributions `(u_step, q_step)` introduced at `height`.
    pub fn push_origin(
        &mut self,
        params: &ProfileParams,
        height: u32,
        w_prefix: u128,
        v_local: u128,
        u_step: u128,
        q_step: u128,
    ) {
        // First, update all previous origins in `self` with the new cap contributions `(u_step, q_step)`.
        self.apply_suffix_caps(params, u_step, q_step);

        // Now add this origin `height` (whose local cap `v_local` already includes `height`).
        let z = params.origin_zone(height);
        let eff_v = if z < 2 {
            self.u_global_contrib.max(v_local)
        } else {
            v_local
        };
        let s_val = w_prefix.saturating_add(params.m_sampled[z].saturating_mul(eff_v));
        let e_val = w_prefix.saturating_add(params.m_exact[z].saturating_mul(eff_v));
        if s_val > self.a_sampled {
            self.a_sampled = s_val;
        }
        if e_val > self.a_exact {
            self.a_exact = e_val;
        }
        self.has_zone[z] = true;
        if w_prefix > self.w_max_zone[z] {
            self.w_max_zone[z] = w_prefix;
        }
    }

    /// Update previously accumulated origins with suffix cap contributions `(u_suffix, q_suffix)`
    /// WITHOUT adding any new origins (used e.g. for heights in `(f, n]` when checking sampled score,
    /// or inside associative merge).
    pub fn apply_suffix_caps(&mut self, params: &ProfileParams, u_suffix: u128, q_suffix: u128) {
        if u_suffix > self.u_global_contrib {
            self.u_global_contrib = u_suffix;
        }
        if q_suffix > self.q_modern_contrib {
            self.q_modern_contrib = q_suffix;
        }
        // Zone 0 & Zone 1 use `u_suffix` (global cap); Zone 2 uses `q_suffix` (modern cap).
        let caps = [u_suffix, u_suffix, q_suffix];
        for z in 0..3 {
            if self.has_zone[z] && caps[z] > 0 {
                let s_up = self.w_max_zone[z].saturating_add(params.m_sampled[z].saturating_mul(caps[z]));
                let e_up = self.w_max_zone[z].saturating_add(params.m_exact[z].saturating_mul(caps[z]));
                if s_up > self.a_sampled {
                    self.a_sampled = s_up;
                }
                if e_up > self.a_exact {
                    self.a_exact = e_up;
                }
            }
        }
    }

    /// Exact associative composition `left || right` for adjacent contiguous segments.
    pub fn merge(params: &ProfileParams, left: &Self, right: &Self) -> Self {
        let mut out = *left;
        // 1. Right segment's caps raise left segment's origins' requirements:
        out.apply_suffix_caps(params, right.u_global_contrib, right.q_modern_contrib);
        // 2. Also, for early zones (0 & 1) inside `right`, their `V(i) = U_global` includes `left.u_global_contrib`!
        let mut right_adj = *right;
        for z in 0..2 {
            if right_adj.has_zone[z] && left.u_global_contrib > 0 {
                let s_up = right_adj.w_max_zone[z]
                    .saturating_add(params.m_sampled[z].saturating_mul(left.u_global_contrib));
                let e_up = right_adj.w_max_zone[z]
                    .saturating_add(params.m_exact[z].saturating_mul(left.u_global_contrib));
                if s_up > right_adj.a_sampled {
                    right_adj.a_sampled = s_up;
                }
                if e_up > right_adj.a_exact {
                    right_adj.a_exact = e_up;
                }
            }
        }
        // 3. Take componentwise maxima
        out.a_sampled = out.a_sampled.max(right_adj.a_sampled);
        out.a_exact = out.a_exact.max(right_adj.a_exact);
        for z in 0..3 {
            if right_adj.has_zone[z] {
                out.has_zone[z] = true;
                out.w_max_zone[z] = out.w_max_zone[z].max(right_adj.w_max_zone[z]);
            }
        }
        out.u_global_contrib = out.u_global_contrib.max(right.u_global_contrib);
        out.q_modern_contrib = out.q_modern_contrib.max(right.q_modern_contrib);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileId;

    #[test]
    fn monoid_is_strictly_associative_across_all_three_zones() {
        for profile in [
            ProfileId::V2Production,
            ProfileId::V2Production128,
            ProfileId::V2LegacyR15,
        ] {
            let p = profile.params();
            // Build 3 synthetic segments spanning v1, early_v2, and modern zones
            let mut s1 = ScoreMonoid::identity();
            s1.push_origin(&p, 100, 1_000, 512, 512, 256);
            s1.push_origin(&p, 417_791, 5_000_000, 2048, 2048, 1024);

            let mut s2 = ScoreMonoid::identity();
            s2.push_origin(&p, 500_000, 9_000_000, 1024, 1024, 1024);
            s2.push_origin(&p, p.modern_origin_start + 100, 20_000_000, 4096, 4096, 4096);

            let mut s3 = ScoreMonoid::identity();
            s3.push_origin(&p, 900_000, 35_000_000, 8192, 8192, 8192);
            s3.push_origin(&p, 950_000, 40_000_000, 2048, 2048, 2048);

            let lr = ScoreMonoid::merge(&p, &ScoreMonoid::merge(&p, &s1, &s2), &s3);
            let rl = ScoreMonoid::merge(&p, &s1, &ScoreMonoid::merge(&p, &s2, &s3));
            assert_eq!(lr, rl, "associativity failed for {profile:?}");
        }
    }
}
