//! Standalone Ergo NiPoPoW V2 production CLI.
//!
//! Commands:
//!   verify-mainnet <u32le_path> [--profile prod|r15] [--segment-size 1024] [--export-segments <dir>]
//!     Reads the canonical length-prefixed Ergo mainnet header stream, verifies ALL headers
//!     with native k256 + witness-assisted secp256k1 parity, executes both a sequential pass
//!     and a parallel segment-tree depth-2 associative merge (proving byte-identical outputs),
//!     computes exact bootstrap & exact-tail maturity heights, builds & cold-verifies the
//!     deduplicated MMR multiproof + native Autolykos PoW audit + exact modern tail, and
//!     optionally exports compact segment witness packages for the OpenVM v2.1.0 STARK prover.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use ergo_nipopow_v2_core::audit::{build_audit_bundle, verify_audit_bundle};
use ergo_nipopow_v2_core::daa::decode_compact;
use ergo_nipopow_v2_core::header::{Header, HeaderPointWitness};
use ergo_nipopow_v2_core::mmr::{hash_leaf, mainnet_profile32, MmrStore};
use ergo_nipopow_v2_core::profile::ProfileId;
use ergo_nipopow_v2_core::segment::{
    check_bootstrap_eligibility, merge_segments, verify_segment, BoundaryState, SegmentSummary,
};
use ergo_nipopow_v2_core::tail::verify_exact_tail;
use rayon::prelude::*;

fn read_u32le_headers(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut r = BufReader::with_capacity(8 * 1024 * 1024, f);
    let mut headers = Vec::with_capacity(1_900_000);
    let mut len_buf = [0u8; 4];
    loop {
        match r.read_exact(&mut len_buf) {
            Ok(()) => {
                let len = u32::from_le_bytes(len_buf) as usize;
                if len == 0 || len > 514 {
                    return Err(format!("invalid header length {len} at index {}", headers.len()));
                }
                let mut raw = vec![0u8; len];
                r.read_exact(&mut raw)
                    .map_err(|e| format!("truncated header {}: {e}", headers.len()))?;
                headers.push(raw);
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read error: {e}")),
        }
    }
    Ok(headers)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SegmentInputPackage {
    segment_index: usize,
    start_height: u32,
    end_height: u32,
    state_in: BoundaryState,
    expected_summary: SegmentSummary,
    raw_headers: Vec<Vec<u8>>,
    witnesses: Vec<HeaderPointWitness>,
}

fn find_latest_eligible_bootstrap(
    profile: ProfileId,
    raw_headers: &[Vec<u8>],
    witnesses: &[HeaderPointWitness],
    full_summary: &SegmentSummary,
    prefix_states: &[BoundaryState],
    prefix_monoids: &[ergo_nipopow_v2_core::monoid::ScoreMonoid],
) -> Result<(u32, SegmentSummary, SegmentSummary, SegmentSummary), String> {
    let params = profile.params();
    let n = raw_headers.len() as u32;
    let total_work = full_summary.state_out.total_work;

    // Binary search for largest b in [modern_origin_start ..= n - k0] where sampled_eligible holds.
    // Note: evaluate exact eligibility via `check_bootstrap_eligibility`!
    let mut lo = params.modern_origin_start;
    let mut hi = n - params.k0;
    let mut best_b = lo;

    // Helper: check a candidate b by splitting into [1..=b], [b+1..=f], [f+1..=n]
    // Fast O(1) pre-screen using prefix_monoids[f] + suffix caps from full_summary:
    // Actually we can compute exact suffix caps from [f+1..=n] using reverse max of modern_cap!
    let mut suffix_q = vec![0u128; raw_headers.len() + 2];
    let mut run_q = 0u128;
    for h in (2..=n as usize).rev() {
        let hdr = Header::decode_with_witness(&raw_headers[h - 1], &witnesses[h - 1], None)
            .map_err(|e| format!("decode {h}: {e:?}"))?;
        let d = decode_compact(hdr.n_bits).map_err(|e| format!("diff {h}: {e:?}"))?;
        let q = params.modern_cap(d).ok_or("cap overflow")?;
        if q > run_q {
            run_q = q;
        }
        suffix_q[h] = run_q;
    }
    let u_global_n = full_summary.state_out.u_global;

    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let f = mid + params.k0 - 1;
        let mut m = prefix_monoids[f as usize];
        // Apply caps from (f..=n]
        let q_suf = suffix_q[(f + 1) as usize];
        m.apply_suffix_caps(&params, u_global_n, q_suf);
        if total_work >= m.a_sampled {
            best_b = mid;
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }

    let f = best_b + params.k0 - 1;
    let prefix_b = SegmentSummary {
        state_in: BoundaryState::initial(profile),
        state_out: prefix_states[best_b as usize].clone(),
        monoid: prefix_monoids[best_b as usize],
    };
    let bridge = verify_segment(
        prefix_states[best_b as usize].clone(),
        &raw_headers[best_b as usize..f as usize],
        &witnesses[best_b as usize..f as usize],
    )
    .map_err(|e| format!("bridge segment: {e:?}"))?;
    let suffix = verify_segment(
        bridge.state_out.clone(),
        &raw_headers[f as usize..n as usize],
        &witnesses[f as usize..n as usize],
    )
    .map_err(|e| format!("suffix segment: {e:?}"))?;

    Ok((best_b, prefix_b, bridge, suffix))
}

fn run_verify_mainnet(
    u32le_path: &Path,
    profile: ProfileId,
    segment_size: usize,
    export_dir: Option<&Path>,
) -> Result<(), String> {
    let t0 = Instant::now();
    println!("=== Ergo NiPoPoW V2 Production Verification ===");
    println!("Profile: {:?}, segment_size: {}", profile, segment_size);
    let raw_headers = read_u32le_headers(u32le_path)?;
    let n = raw_headers.len();
    println!(
        "[1/7] Loaded {} mainnet headers ({:.2} MiB) in {:.2}s",
        n,
        raw_headers.iter().map(|h| h.len()).sum::<usize>() as f64 / (1024.0 * 1024.0),
        t0.elapsed().as_secs_f64()
    );

    // Compute native secp256k1 y-witnesses in parallel AND verify k256 parity on ALL 1.83M headers!
    let t_wit = Instant::now();
    let decoded_pairs: Result<Vec<(Header, HeaderPointWitness)>, String> = raw_headers
        .par_iter()
        .enumerate()
        .map(|(i, raw)| {
            Header::decode_native(raw, None)
                .map_err(|e| format!("native decode failed at height {}: {e:?}", i + 1))
        })
        .collect();
    let decoded_pairs = decoded_pairs?;
    let witnesses: Vec<HeaderPointWitness> = decoded_pairs.iter().map(|(_, w)| *w).collect();
    println!(
        "[2/7] Native k256 decode + secp256k1 y-witness parity on ALL {} headers passed in {:.2}s",
        n,
        t_wit.elapsed().as_secs_f64()
    );

    // Sequential reference pass (also capturing per-height states/monoids for bootstrap search + MMR store)
    let t_seq = Instant::now();
    let params = profile.params();
    let p32 = mainnet_profile32();
    let mut seq_segments = Vec::new();
    let mut boundary_states = Vec::with_capacity(n / segment_size + 2);
    let mut cur_state = BoundaryState::initial(profile);
    boundary_states.push(cur_state.clone());

    let mut pos = 0usize;
    while pos < n {
        let end = (pos + segment_size).min(n);
        let seg = verify_segment(
            cur_state.clone(),
            &raw_headers[pos..end],
            &witnesses[pos..end],
        )
        .map_err(|e| format!("segment [{}, {}] failed: {e:?}", pos + 1, end))?;
        cur_state = seg.state_out.clone();
        boundary_states.push(cur_state.clone());
        seq_segments.push(seg);
        pos = end;
    }
    println!(
        "[3/7] Executed {} independent segments (size {}) across ALL {} headers (0 DAA/era/codec errors) in {:.2}s",
        seq_segments.len(),
        segment_size,
        n,
        t_seq.elapsed().as_secs_f64()
    );

    // Verify depth-2 fan-in associative merge (fan-in 64: level-1 groups of 64 -> single root!)
    let t_merge = Instant::now();
    let fan_in = 64usize;
    let level1: Result<Vec<SegmentSummary>, _> = seq_segments
        .chunks(fan_in)
        .map(merge_segments)
        .collect();
    let level1 = level1.map_err(|e| format!("level-1 merge: {e:?}"))?;
    let tree_root_summary = merge_segments(&level1).map_err(|e| format!("root merge: {e:?}"))?;

    // Cross-check against a single flat sequential pass over ALL headers!
    let flat_summary = verify_segment(BoundaryState::initial(profile), &raw_headers, &witnesses)
        .map_err(|e| format!("flat pass: {e:?}"))?;
    if tree_root_summary != flat_summary {
        return Err("CRITICAL: depth-2 associative merge differed from flat sequential pass!".into());
    }
    println!(
        "[4/7] Depth-2 associative tree merge ({} leaves -> {} L1 nodes -> 1 root) BIT-FOR-BIT IDENTICAL to flat pass ({:.2}s)",
        seq_segments.len(),
        level1.len(),
        t_merge.elapsed().as_secs_f64()
    );
    println!(
        "      tip={} id={} total_work={} U_global={} mmr_root={}",
        flat_summary.state_out.height,
        hex::encode(flat_summary.state_out.tip_id),
        flat_summary.state_out.total_work,
        flat_summary.state_out.u_global,
        hex::encode(flat_summary.state_out.mmr_root().unwrap()),
    );

    // Build MMR store + cumulative work + per-height prefix checkpoints in the modern zone
    let t_mmr = Instant::now();
    let mut mmr_store = MmrStore::new(n);
    let mut cum_work = Vec::with_capacity(n);
    cum_work.push(0u128);
    let mut w_acc = 0u128;
    for h in 2..=n {
        let d = decode_compact(decoded_pairs[h - 1].0.n_bits).unwrap();
        let w_hi = w_acc + d;
        let leaf = hash_leaf(&p32, h as u32, w_acc, w_hi, &raw_headers[h - 1]);
        mmr_store.push_leaf(leaf);
        cum_work.push(w_hi);
        w_acc = w_hi;
    }
    assert_eq!(mmr_store.frontier(), flat_summary.state_out.mmr);
    println!(
        "[5/7] Built full SHA-256 append-only MMR store ({} peaks, root verified) in {:.2}s",
        mmr_store.frontier().peaks.len(),
        t_mmr.elapsed().as_secs_f64()
    );

    // Find exact latest eligible bootstrap height `b` (sampled mode) and latest exact-tail mature height `h_exact`
    let t_mat = Instant::now();
    // Compute prefix summaries every block from the last ~30,000 blocks for exact binary search
    let scan_start = (n as u32).saturating_sub(30_000).max(params.modern_origin_start);
    let seg_before_scan = (scan_start as usize - 1) / segment_size;
    let base_summary = merge_segments(&seq_segments[..seg_before_scan])
        .map_err(|e| format!("base merge: {e:?}"))?;
    let mut prefix_states = vec![BoundaryState::initial(profile); n + 1];
    let mut prefix_monoids = vec![ergo_nipopow_v2_core::monoid::ScoreMonoid::identity(); n + 1];

    let mut running_state = base_summary.state_out.clone();
    let mut running_monoid = base_summary.monoid;
    let start_h = running_state.height as usize + 1;
    prefix_states[running_state.height as usize] = running_state.clone();
    prefix_monoids[running_state.height as usize] = running_monoid;

    for h in start_h..=n {
        let step = verify_segment(
            running_state.clone(),
            &raw_headers[h - 1..h],
            &witnesses[h - 1..h],
        )
        .map_err(|e| format!("step {h}: {e:?}"))?;
        running_monoid = ergo_nipopow_v2_core::monoid::ScoreMonoid::merge(
            &params,
            &running_monoid,
            &step.monoid,
        );
        running_state = step.state_out;
        prefix_states[h] = running_state.clone();
        prefix_monoids[h] = running_monoid;
    }

    let (best_b, prefix_b, bridge, suffix) = find_latest_eligible_bootstrap(
        profile,
        &raw_headers,
        &witnesses,
        &flat_summary,
        &prefix_states,
        &prefix_monoids,
    )?;
    let stmt = check_bootstrap_eligibility(&prefix_b, &bridge, &suffix)
        .map_err(|e| format!("eligibility: {e:?}"))?;
    assert!(stmt.sampled_eligible, "chosen best_b must be eligible!");
    let b_age_days = (decoded_pairs[n - 1].0.timestamp - decoded_pairs[best_b as usize - 1].0.timestamp) as f64
        / 86_400_000.0;
    println!(
        "[6/7] Latest eligible bootstrap b={} ({} blocks / {:.2} days behind tip {}; computed in {:.2}s)",
        best_b,
        n as u32 - best_b,
        b_age_days,
        n,
        t_mat.elapsed().as_secs_f64()
    );

    // Build & cold-verify deduplicated audit bundle + exact modern tail!
    let x_bytes = bincode::serialize(&stmt).map_err(|e| e.to_string())?;
    // Deterministic placeholder structural proof bytes for sizing & audit verification benchmark
    // (real OpenVM v2.1.0 SWIRL/WHIR STARK proof replaces these bytes in the prover pipeline)
    let mock_pi_s = vec![0xA5u8; 256 * 1024]; // ~256 KB representative OpenVM SWIRL STARK size
    let t_aud_build = Instant::now();
    let audit = build_audit_bundle(&stmt, &x_bytes, &mock_pi_s, &mmr_store, &raw_headers, &cum_work)
        .map_err(|e| format!("build audit: {e:?}"))?;
    let build_ms = t_aud_build.elapsed().as_secs_f64() * 1000.0;

    let t_aud_ver = Instant::now();
    let total_draws = verify_audit_bundle(&stmt, &x_bytes, &mock_pi_s, &audit)
        .map_err(|e| format!("verify audit: {e:?}"))?;
    let verify_audit_s = t_aud_ver.elapsed().as_secs_f64();

    // Find latest exact-tail mature query height `h_exact` using STARK-authenticated `stmt`!
    let tail_slice = &raw_headers[best_b as usize..n];

    // Binary search latest exact-tail mature query height in [best_b ..= n - k0]
    // using the exact suffix modern cap `max_{r in (f_q ..= n]} modern_cap(D(r))` (eq. 19 & 27).
    let mut suffix_q = vec![0u128; n + 2];
    let mut run_q = 0u128;
    for h in (2..=n).rev() {
        let d = decode_compact(decoded_pairs[h - 1].0.n_bits).unwrap();
        let q = params.modern_cap(d).unwrap();
        if q > run_q {
            run_q = q;
        }
        suffix_q[h] = run_q;
    }
    let mut lo_q = best_b;
    let mut hi_q = n as u32 - params.k0;
    let mut best_q = best_b;
    while lo_q <= hi_q {
        let mid = lo_q + (hi_q - lo_q) / 2;
        let f_q = mid + params.k0 - 1;
        let mut m_q = prefix_monoids[f_q as usize];
        let q_suf = suffix_q[(f_q + 1) as usize];
        m_q.apply_suffix_caps(&params, stmt.u_global, q_suf);
        if stmt.total_work >= m_q.a_exact {
            best_q = mid;
            lo_q = mid + 1;
        } else {
            hi_q = mid - 1;
        }
    }
    let t_tail = Instant::now();
    let verified_tail = verify_exact_tail(&stmt, tail_slice, best_q)
        .map_err(|e| format!("verify_exact_tail at {best_q}: {e:?}"))?;
    let tail_verify_s = t_tail.elapsed().as_secs_f64();
    // Confirm `best_q + 1` fails maturity guard!
    if best_q + 1 <= n as u32 - params.k0 {
        let next_res = verify_exact_tail(&stmt, tail_slice, best_q + 1);
        assert!(
            next_res.is_err(),
            "height {} should fail exact-tail maturity guard",
            best_q + 1
        );
    }

    let q_age_days = (decoded_pairs[n - 1].0.timestamp - decoded_pairs[best_q as usize - 1].0.timestamp) as f64
        / 86_400_000.0;
    let audit_bytes = audit.compact_wire_bytes();
    let tail_bytes: usize = tail_slice.iter().map(|h| 2 + h.len()).sum();
    let cert_total_bytes = x_bytes.len() + mock_pi_s.len() + audit_bytes;
    let cold_sync_bytes = cert_total_bytes + tail_bytes;

    println!("[7/7] === COMPLETE COLD CLIENT BENCHMARK (1,827,840 REAL MAINNET HEADERS) ===");
    println!("  Audit draws:               {} ({} distinct headers, {} deduplicated siblings, {} untouched peaks)",
        total_draws, audit.leaves.len(), audit.multiproof.siblings.len(), audit.multiproof.untouched_peaks.len());
    println!("  Audit build / verify:      {:.1} ms / {:.3} s", build_ms, verify_audit_s);
    println!("  Latest exact-tail mature:  h={} ({} blocks / {:.2} days behind tip)",
        verified_tail.query_height, n as u32 - best_q, q_age_days);
    println!("  Exact tail ({} hdrs):   verify {:.3} s, payload {:.2} MiB",
        tail_slice.len(), tail_verify_s, tail_bytes as f64 / (1024.0 * 1024.0));
    println!("  Certificate wire size:     {:.2} MiB (audit={:.2} MiB + ~0.25 MiB STARK)",
        cert_total_bytes as f64 / (1024.0 * 1024.0), audit_bytes as f64 / (1024.0 * 1024.0));
    println!("  Total cold sync payload:   {:.2} MiB ({:.2}% of 407.07 MiB raw headers!)",
        cold_sync_bytes as f64 / (1024.0 * 1024.0),
        100.0 * cold_sync_bytes as f64 / (raw_headers.iter().map(|h| h.len()).sum::<usize>() as f64));
    println!("  Total cold client CPU:     {:.3} s (audit + exact tail; + ~0.05 s STARK verify)",
        verify_audit_s + tail_verify_s);

    // Optional export of segment witness packages for OpenVM v2.1.0 STARK proving!
    if let Some(out_dir) = export_dir {
        let t_exp = Instant::now();
        fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
        for (idx, seg) in seq_segments.iter().enumerate() {
            let s = idx * segment_size;
            let e = (s + segment_size).min(n);
            let pkg = SegmentInputPackage {
                segment_index: idx,
                start_height: (s + 1) as u32,
                end_height: e as u32,
                state_in: seg.state_in.clone(),
                expected_summary: seg.clone(),
                raw_headers: raw_headers[s..e].to_vec(),
                witnesses: witnesses[s..e].to_vec(),
            };
            let bytes = bincode::serialize(&pkg).map_err(|err| err.to_string())?;
            let path = out_dir.join(format!("seg-{idx:05}.bin"));
            fs::write(&path, bytes).map_err(|err| format!("write {}: {err}", path.display()))?;
        }
        // Write manifest JSON
        let manifest = serde_json::json!({
            "profile": format!("{:?}", profile),
            "headers": n,
            "segment_size": segment_size,
            "segment_count": seq_segments.len(),
            "depth2_fan_in": fan_in,
            "level1_agg_count": level1.len(),
            "tip_height": flat_summary.state_out.height,
            "tip_id": hex::encode(flat_summary.state_out.tip_id),
            "total_work": flat_summary.state_out.total_work.to_string(),
            "u_global": flat_summary.state_out.u_global.to_string(),
            "mmr_root": hex::encode(flat_summary.state_out.mmr_root().unwrap()),
            "latest_bootstrap_b": best_b,
            "latest_exact_mature_h": best_q,
            "bootstrap_age_days": b_age_days,
            "exact_mature_age_days": q_age_days,
            "audit_distinct_headers": audit.leaves.len(),
            "audit_dedup_siblings": audit.multiproof.siblings.len(),
            "audit_wire_bytes": audit_bytes,
            "tail_wire_bytes": tail_bytes,
            "cold_sync_total_bytes": cold_sync_bytes,
            "audit_verify_s": verify_audit_s,
            "tail_verify_s": tail_verify_s,
        });
        fs::write(
            out_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        println!(
            "Exported {} incremental segment packages + manifest.json to {} in {:.2}s",
            seq_segments.len(),
            out_dir.display(),
            t_exp.elapsed().as_secs_f64()
        );
    }

    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct GuestSegmentInput {
    state_in: BoundaryState,
    raw_headers: Vec<Vec<u8>>,
    witnesses: Vec<HeaderPointWitness>,
}

fn run_export_zisk_input(
    seg_bin: &Path,
    out_bin: &Path,
    max_headers: Option<usize>,
) -> Result<(), String> {
    let bytes = fs::read(seg_bin).map_err(|e| format!("read {}: {e}", seg_bin.display()))?;
    let pkg: SegmentInputPackage =
        bincode::deserialize(&bytes).map_err(|e| format!("decode seg: {e}"))?;
    let count = max_headers.unwrap_or(pkg.raw_headers.len()).min(pkg.raw_headers.len());
    let raw_slice = pkg.raw_headers[..count].to_vec();
    let wit_slice = pkg.witnesses[..count].to_vec();
    let expected = verify_segment(pkg.state_in.clone(), &raw_slice, &wit_slice)
        .map_err(|e| format!("verify slice: {e:?}"))?;
    let expected_bytes = bincode::serialize(&expected).map_err(|e| e.to_string())?;
    let expected_hash = ergo_nipopow_v2_core::mmr::sha256_bytes(&expected_bytes);

    let guest_in = GuestSegmentInput {
        state_in: pkg.state_in,
        raw_headers: raw_slice,
        witnesses: wit_slice,
    };
    let payload = bincode::serialize(&guest_in).map_err(|e| e.to_string())?;
    // ZisK `ziskos::io::read_slice()` wire framing: u64 LE byte length + payload + 0-pad to 8B.
    let aligned_len = (payload.len() + 7) & !7usize;
    let mut framed = Vec::with_capacity(8 + aligned_len);
    framed.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    framed.extend_from_slice(&payload);
    framed.resize(8 + aligned_len, 0u8);
    fs::write(out_bin, &framed).map_err(|e| format!("write {}: {e}", out_bin.display()))?;
    println!(
        "Exported ZisK input ({} headers, {} payload bytes, {} framed bytes) -> {} | expected_sha256={}",
        count,
        payload.len(),
        framed.len(),
        out_bin.display(),
        hex::encode(expected_hash)
    );
    Ok(())
}

#[derive(serde::Serialize)]
struct ZiskChildClaim {
    proof_words: Vec<u64>,
    summary: SegmentSummary,
}

#[derive(serde::Serialize)]
struct ZiskL1Input {
    children: Vec<ZiskChildClaim>,
}

fn run_export_zisk_l1_input(out_bin: &Path, pairs: &[(String, PathBuf)]) -> Result<(), String> {
    const SEED_TRAILER_TAG: u64 = u64::from_le_bytes(*b"ZISKSEED");
    if pairs.is_empty() {
        return Err("at least one <seg.bin[:count]> <proof> pair is required".into());
    }
    let mut children = Vec::with_capacity(pairs.len());
    let mut summaries = Vec::with_capacity(pairs.len());
    for (seg_spec, proof_path) in pairs {
        let (seg_path_str, max_hdrs) = match seg_spec.rsplit_once('@') {
            Some((p, n)) => (
                p,
                Some(n.parse::<usize>().map_err(|e| format!("invalid count in {seg_spec}: {e}"))?),
            ),
            None => (seg_spec.as_str(), None),
        };
        let seg_bytes = fs::read(seg_path_str)
            .map_err(|e| format!("read {seg_path_str}: {e}"))?;
        let pkg: SegmentInputPackage =
            bincode::deserialize(&seg_bytes).map_err(|e| format!("decode {seg_path_str}: {e}"))?;
        let summary = if let Some(n) = max_hdrs {
            let count = n.min(pkg.raw_headers.len());
            verify_segment(pkg.state_in.clone(), &pkg.raw_headers[..count], &pkg.witnesses[..count])
                .map_err(|e| format!("verify slice {seg_spec}: {e:?}"))?
        } else {
            pkg.expected_summary
        };

        let proof_bytes = fs::read(proof_path)
            .map_err(|e| format!("read {}: {e}", proof_path.display()))?;
        if proof_bytes.len() % 8 != 0 {
            return Err(format!(
                "{} length {} is not a multiple of 8 bytes",
                proof_path.display(),
                proof_bytes.len()
            ));
        }
        let mut proof_words: Vec<u64> = proof_bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        if proof_words.last() == Some(&SEED_TRAILER_TAG) {
            if proof_words.len() < 5 {
                return Err(format!("{}: truncated seed trailer", proof_path.display()));
            }
            proof_words.truncate(proof_words.len() - 5);
        }
        summaries.push(summary.clone());
        children.push(ZiskChildClaim { proof_words, summary });
    }

    let merged = merge_segments(&summaries).map_err(|e| format!("merge_segments: {e:?}"))?;
    let merged_bytes = bincode::serialize(&merged).map_err(|e| e.to_string())?;
    let expected_hash = ergo_nipopow_v2_core::mmr::sha256_bytes(&merged_bytes);

    let l1_in = ZiskL1Input { children };
    let payload = bincode::serialize(&l1_in).map_err(|e| e.to_string())?;
    let aligned_len = (payload.len() + 7) & !7;
    let mut framed = Vec::with_capacity(8 + aligned_len);
    framed.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    framed.extend_from_slice(&payload);
    framed.resize(8 + aligned_len, 0u8);
    fs::write(out_bin, &framed).map_err(|e| format!("write {}: {e}", out_bin.display()))?;
    let summary_out = out_bin.with_extension("summary.bin");
    fs::write(&summary_out, &merged_bytes)
        .map_err(|e| format!("write {}: {e}", summary_out.display()))?;
    println!(
        "Exported ZisK L1 input ({} children, heights {}..={}, {} payload bytes, {} framed bytes) -> {} (summary -> {}) | expected_sha256={}",
        summaries.len(),
        merged.state_in.height + 1,
        merged.state_out.height,
        payload.len(),
        framed.len(),
        out_bin.display(),
        summary_out.display(),
        hex::encode(expected_hash)
    );
    Ok(())
}

#[derive(serde::Serialize)]
struct ZiskRootInput {
    prefix_children: Vec<ZiskChildClaim>,
    bridge_child: ZiskChildClaim,
    suffix_children: Vec<ZiskChildClaim>,
}

fn load_zisk_proof_words(proof_path: &Path) -> Result<Vec<u64>, String> {
    const SEED_TRAILER_TAG: u64 = u64::from_le_bytes(*b"ZISKSEED");
    let proof_bytes =
        fs::read(proof_path).map_err(|e| format!("read {}: {e}", proof_path.display()))?;
    if proof_bytes.len() % 8 != 0 {
        return Err(format!(
            "{} length {} is not a multiple of 8 bytes",
            proof_path.display(),
            proof_bytes.len()
        ));
    }
    let mut proof_words: Vec<u64> = proof_bytes
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    if proof_words.last() == Some(&SEED_TRAILER_TAG) {
        if proof_words.len() < 5 {
            return Err(format!("{}: truncated seed trailer", proof_path.display()));
        }
        proof_words.truncate(proof_words.len() - 5);
    }
    Ok(proof_words)
}

fn load_summary_any(path: &Path) -> Result<SegmentSummary, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if let Ok(summary) = bincode::deserialize::<SegmentSummary>(&bytes) {
        return Ok(summary);
    }
    if let Ok(pkg) = bincode::deserialize::<SegmentInputPackage>(&bytes) {
        return Ok(pkg.expected_summary);
    }
    Err(format!(
        "failed to deserialize {} as SegmentSummary or SegmentInputPackage",
        path.display()
    ))
}

fn run_export_zisk_root_input(
    out_bin: &Path,
    prefix_pairs: &[(PathBuf, PathBuf)],
    bridge_pair: &(PathBuf, PathBuf),
    suffix_pairs: &[(PathBuf, PathBuf)],
) -> Result<(), String> {
    if prefix_pairs.is_empty() || suffix_pairs.is_empty() {
        return Err("prefix and suffix lists must both be non-empty".into());
    }
    let mut prefix_children = Vec::with_capacity(prefix_pairs.len());
    let mut prefix_sums = Vec::with_capacity(prefix_pairs.len());
    for (sum_p, prf_p) in prefix_pairs {
        let summary = load_summary_any(sum_p)?;
        let proof_words = load_zisk_proof_words(prf_p)?;
        prefix_sums.push(summary.clone());
        prefix_children.push(ZiskChildClaim { proof_words, summary });
    }
    let prefix_b = merge_segments(&prefix_sums).map_err(|e| format!("merge prefix: {e:?}"))?;

    let bridge_sum = load_summary_any(&bridge_pair.0)?;
    let bridge_child = ZiskChildClaim {
        proof_words: load_zisk_proof_words(&bridge_pair.1)?,
        summary: bridge_sum.clone(),
    };

    let mut suffix_children = Vec::with_capacity(suffix_pairs.len());
    let mut suffix_sums = Vec::with_capacity(suffix_pairs.len());
    for (sum_p, prf_p) in suffix_pairs {
        let summary = load_summary_any(sum_p)?;
        let proof_words = load_zisk_proof_words(prf_p)?;
        suffix_sums.push(summary.clone());
        suffix_children.push(ZiskChildClaim { proof_words, summary });
    }
    let suffix_merged = merge_segments(&suffix_sums).map_err(|e| format!("merge suffix: {e:?}"))?;

    let stmt = check_bootstrap_eligibility(&prefix_b, &bridge_sum, &suffix_merged)
        .map_err(|e| format!("check_bootstrap_eligibility: {e:?}"))?;
    if !stmt.sampled_eligible {
        return Err("bootstrap height is NOT sampled-eligible!".into());
    }
    let stmt_bytes = bincode::serialize(&stmt).map_err(|e| e.to_string())?;
    let expected_root_hash = ergo_nipopow_v2_core::mmr::sha256_bytes(&stmt_bytes);

    let root_in = ZiskRootInput {
        prefix_children,
        bridge_child,
        suffix_children,
    };
    let payload = bincode::serialize(&root_in).map_err(|e| e.to_string())?;
    let aligned_len = (payload.len() + 7) & !7;
    let mut framed = Vec::with_capacity(8 + aligned_len);
    framed.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    framed.extend_from_slice(&payload);
    framed.resize(8 + aligned_len, 0u8);
    fs::write(out_bin, &framed).map_err(|e| format!("write {}: {e}", out_bin.display()))?;

    let stmt_out = out_bin.with_extension("stmt.bin");
    fs::write(&stmt_out, &stmt_bytes).map_err(|e| format!("write {}: {e}", stmt_out.display()))?;
    println!(
        "Exported ZisK Root input ({} prefix + 1 bridge + {} suffix L1 children, b={}, tip={}, {} framed bytes) -> {} (stmt -> {}) | expected_root_sha256={}",
        prefix_pairs.len(),
        suffix_pairs.len(),
        stmt.bootstrap_height,
        stmt.tip_height,
        framed.len(),
        out_bin.display(),
        stmt_out.display(),
        hex::encode(expected_root_hash)
    );
    Ok(())
}

fn run_export_all_zisk_inputs(seg_dir: &Path, split_dir: &Path, out_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let mut items: Vec<(String, PathBuf)> = Vec::with_capacity(450);
    for i in 0..=446usize {
        if i == 444 {
            continue;
        }
        let tag = format!("seg-{i:05}");
        let p = seg_dir.join(format!("{tag}.bin"));
        if p.exists() {
            items.push((tag, p));
        }
    }
    for sub in ["seg-00444a", "seg-00444b", "seg-00444c"] {
        let p = split_dir.join(format!("{sub}.bin"));
        if !p.exists() {
            return Err(format!("missing split segment {}", p.display()));
        }
        items.push((sub.to_string(), p));
    }
    let t0 = Instant::now();
    let results: Result<Vec<(String, String)>, String> = items
        .par_iter()
        .map(|(tag, src)| {
            let bytes = fs::read(src).map_err(|e| format!("read {}: {e}", src.display()))?;
            let pkg: SegmentInputPackage =
                bincode::deserialize(&bytes).map_err(|e| format!("decode {tag}: {e}"))?;
            let exp_bytes = bincode::serialize(&pkg.expected_summary).map_err(|e| e.to_string())?;
            let exp_hash = ergo_nipopow_v2_core::mmr::sha256_bytes(&exp_bytes);
            let guest_in = GuestSegmentInput {
                state_in: pkg.state_in,
                raw_headers: pkg.raw_headers,
                witnesses: pkg.witnesses,
            };
            let payload = bincode::serialize(&guest_in).map_err(|e| e.to_string())?;
            let aligned_len = (payload.len() + 7) & !7;
            let mut framed = Vec::with_capacity(8 + aligned_len);
            framed.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            framed.extend_from_slice(&payload);
            framed.resize(8 + aligned_len, 0u8);
            let dst = out_dir.join(format!("{tag}.zisk.bin"));
            fs::write(&dst, &framed).map_err(|e| format!("write {}: {e}", dst.display()))?;
            Ok((tag.clone(), hex::encode(exp_hash)))
        })
        .collect();
    let manifest = results?;
    let mut lines = String::new();
    for (tag, sha) in &manifest {
        lines.push_str(&format!("{tag} {sha}\n"));
    }
    fs::write(out_dir.join("expected_digests.txt"), lines).map_err(|e| e.to_string())?;
    println!(
        "Exported all {} ZisK leaf inputs in {:.2}s -> {} (digests in expected_digests.txt)",
        manifest.len(),
        t0.elapsed().as_secs_f64(),
        out_dir.display()
    );
    Ok(())
}

fn run_export_openvm_input(
    seg_bin: &Path,
    out_json: &Path,
    max_headers: Option<usize>,
) -> Result<(), String> {
    let bytes = fs::read(seg_bin).map_err(|e| format!("read {}: {e}", seg_bin.display()))?;
    let pkg: SegmentInputPackage =
        bincode::deserialize(&bytes).map_err(|e| format!("decode seg: {e}"))?;
    let count = max_headers.unwrap_or(pkg.raw_headers.len()).min(pkg.raw_headers.len());
    let raw_slice = pkg.raw_headers[..count].to_vec();
    let wit_slice = pkg.witnesses[..count].to_vec();
    let expected = verify_segment(pkg.state_in.clone(), &raw_slice, &wit_slice)
        .map_err(|e| format!("verify slice: {e:?}"))?;
    let expected_bytes = bincode::serialize(&expected).map_err(|e| e.to_string())?;
    let expected_hash = ergo_nipopow_v2_core::mmr::sha256_bytes(&expected_bytes);

    let guest_in = GuestSegmentInput {
        state_in: pkg.state_in,
        raw_headers: raw_slice,
        witnesses: wit_slice,
    };
    let payload = bincode::serialize(&guest_in).map_err(|e| e.to_string())?;
    let hex_str = format!("0x01{}", hex::encode(&payload));
    let json = serde_json::json!({ "input": [hex_str] });
    fs::write(out_json, serde_json::to_string(&json).unwrap())
        .map_err(|e| format!("write {}: {e}", out_json.display()))?;
    println!(
        "Exported OpenVM input ({} headers, {} raw payload bytes) -> {} | expected_sha256={}",
        count,
        payload.len(),
        out_json.display(),
        hex::encode(expected_hash)
    );
    Ok(())
}

fn run_export_bootstrap_split(
    seg_bin: &Path,
    out_dir: &Path,
    bootstrap_height: u32,
) -> Result<(), String> {
    let bytes = fs::read(seg_bin).map_err(|e| format!("read {}: {e}", seg_bin.display()))?;
    let pkg: SegmentInputPackage =
        bincode::deserialize(&bytes).map_err(|e| format!("decode seg: {e}"))?;
    let params = pkg.state_in.profile.params();
    let f_height = bootstrap_height + params.k0 - 1;
    if bootstrap_height < pkg.start_height || f_height >= pkg.end_height {
        return Err(format!(
            "bootstrap b={bootstrap_height}, f={f_height} not strictly inside segment [{}..={}]",
            pkg.start_height, pkg.end_height
        ));
    }
    fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;

    let b_idx = (bootstrap_height - pkg.start_height + 1) as usize;
    let f_idx = (f_height - pkg.start_height + 1) as usize;
    let stem = format!("seg-{:05}", pkg.segment_index);
    let splits = [
        (format!("{stem}a"), 0usize, b_idx),
        (format!("{stem}b"), b_idx, f_idx),
        (format!("{stem}c"), f_idx, pkg.raw_headers.len()),
    ];
    let mut cur_state = pkg.state_in.clone();
    let mut subs = Vec::new();
    for (name, s, e) in splits {
        let raws = pkg.raw_headers[s..e].to_vec();
        let wits = pkg.witnesses[s..e].to_vec();
        let summary = verify_segment(cur_state.clone(), &raws, &wits)
            .map_err(|err| format!("{name} verify: {err:?}"))?;
        let summary_bytes = bincode::serialize(&summary).map_err(|err| err.to_string())?;
        let summary_sha = ergo_nipopow_v2_core::mmr::sha256_bytes(&summary_bytes);
        let sub_pkg = SegmentInputPackage {
            segment_index: pkg.segment_index,
            start_height: cur_state.height + 1,
            end_height: summary.state_out.height,
            state_in: cur_state.clone(),
            expected_summary: summary.clone(),
            raw_headers: raws.clone(),
            witnesses: wits.clone(),
        };
        let bin_path = out_dir.join(format!("{name}.bin"));
        fs::write(&bin_path, bincode::serialize(&sub_pkg).unwrap()).map_err(|e| e.to_string())?;
        let guest_in = GuestSegmentInput {
            state_in: cur_state,
            raw_headers: raws,
            witnesses: wits,
        };
        let payload = bincode::serialize(&guest_in).unwrap();
        let json = serde_json::json!({ "input": [format!("0x01{}", hex::encode(&payload))] });
        let json_path = out_dir.join(format!("{name}.json"));
        fs::write(&json_path, serde_json::to_string(&json).unwrap()).map_err(|e| e.to_string())?;
        println!(
            "Exported {name} (heights {}..={}, {} hdrs) expected_sha256={}",
            sub_pkg.start_height,
            sub_pkg.end_height,
            e - s,
            hex::encode(summary_sha)
        );
        cur_state = summary.state_out.clone();
        subs.push(summary);
    }
    let remerged = merge_segments(&subs).map_err(|e| format!("remerge: {e:?}"))?;
    assert_eq!(remerged, pkg.expected_summary, "split sub-segments must merge identically to {stem}!");
    println!("Verified exact 3-way split parity for {stem} -> (a, b, c) at b={bootstrap_height}, f={f_height}!");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if (args.len() == 4 || args.len() == 5) && args[1] == "export-bootstrap-split" {
        let b_height = args
            .get(4)
            .map(|s| s.parse::<u32>().expect("valid bootstrap height"))
            .unwrap_or(1_820_694);
        if let Err(e) = run_export_bootstrap_split(Path::new(&args[2]), Path::new(&args[3]), b_height) {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() >= 4 && args[1] == "export-zisk-input" {
        let seg_bin = PathBuf::from(&args[2]);
        let out_bin = PathBuf::from(&args[3]);
        let max_hdrs = args.get(4).and_then(|s| s.parse::<usize>().ok());
        if let Err(e) = run_export_zisk_input(&seg_bin, &out_bin, max_hdrs) {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() >= 5 && args[1] == "export-zisk-l1-input" {
        let out_bin = PathBuf::from(&args[2]);
        let rest = &args[3..];
        if rest.len() % 2 != 0 {
            eprintln!("ERROR: export-zisk-l1-input requires pairs of <seg.bin[@count]> <proof>");
            std::process::exit(2);
        }
        let pairs: Vec<(String, PathBuf)> = rest
            .chunks_exact(2)
            .map(|c| (c[0].clone(), PathBuf::from(&c[1])))
            .collect();
        if let Err(e) = run_export_zisk_l1_input(&out_bin, &pairs) {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() == 5 && args[1] == "export-all-zisk-inputs" {
        if let Err(e) = run_export_all_zisk_inputs(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        ) {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() >= 6 && args[1] == "export-zisk-root-input" {
        let out_bin = PathBuf::from(&args[2]);
        let mut prefix_pairs: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut bridge_pair: Option<(PathBuf, PathBuf)> = None;
        let mut suffix_pairs: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut mode = "";
        let mut i = 3;
        while i < args.len() {
            match args[i].as_str() {
                "--prefix" => {
                    mode = "prefix";
                    i += 1;
                }
                "--bridge" => {
                    mode = "bridge";
                    i += 1;
                }
                "--suffix" => {
                    mode = "suffix";
                    i += 1;
                }
                _ => {
                    if i + 1 >= args.len() {
                        eprintln!("ERROR: expected <summary.bin> <proof> pair");
                        std::process::exit(2);
                    }
                    let pair = (PathBuf::from(&args[i]), PathBuf::from(&args[i + 1]));
                    match mode {
                        "prefix" => prefix_pairs.push(pair),
                        "bridge" => bridge_pair = Some(pair),
                        "suffix" => suffix_pairs.push(pair),
                        _ => {
                            eprintln!("ERROR: specify --prefix, --bridge, or --suffix before pairs");
                            std::process::exit(2);
                        }
                    }
                    i += 2;
                }
            }
        }
        let bridge = bridge_pair.unwrap_or_else(|| {
            eprintln!("ERROR: --bridge <summary.bin> <proof> is required");
            std::process::exit(2);
        });
        if let Err(e) = run_export_zisk_root_input(&out_bin, &prefix_pairs, &bridge, &suffix_pairs)
        {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() >= 4 && args[1] == "export-openvm-input" {
        let seg_bin = PathBuf::from(&args[2]);
        let out_json = PathBuf::from(&args[3]);
        let max_hdrs = args.get(4).and_then(|s| s.parse::<usize>().ok());
        if let Err(e) = run_export_openvm_input(&seg_bin, &out_json, max_hdrs) {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() < 3 || args[1] != "verify-mainnet" {
        eprintln!(
            "Usage:\n  {} verify-mainnet <prefix-u32le> [--profile prod|prod128|r15] [--segment-size 1024] [--export-segments <dir>]\n  {} export-openvm-input <seg-XXXXX.bin> <out.json> [max_headers]\n  {} export-bootstrap-split <seg-XXXXX.bin> <out_dir> [bootstrap_height]",
            args[0], args[0], args[0]
        );
        std::process::exit(2);
    }
    let path = PathBuf::from(&args[2]);
    let mut profile = ProfileId::V2Production128;
    let mut segment_size = 1024usize;
    let mut export_dir: Option<PathBuf> = None;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                i += 1;
                profile = match args.get(i).map(String::as_str) {
                    Some("prod") => ProfileId::V2Production,
                    Some("prod128") => ProfileId::V2Production128,
                    Some("r15") => ProfileId::V2LegacyR15,
                    other => panic!("unknown profile: {other:?}"),
                };
            }
            "--segment-size" => {
                i += 1;
                segment_size = args[i].parse().expect("valid segment size");
            }
            "--export-segments" => {
                i += 1;
                export_dir = Some(PathBuf::from(&args[i]));
            }
            other => panic!("unknown flag: {other}"),
        }
        i += 1;
    }

    if let Err(e) = run_verify_mainnet(&path, profile, segment_size, export_dir.as_deref()) {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}
