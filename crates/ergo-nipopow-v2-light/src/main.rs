//! Minimal zero-prover-SDK CLI verifier for Ergo NiPoPoW V2 (`V2Production128`).

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, Subcommand};
use ergo_nipopow_v2_core::state_proof::ErgoTxMerkleProof;
use ergo_nipopow_v2_core::tail::LightCheckpoint;
use ergo_nipopow_v2_light::{
    compare_peer_certificates, extend_light_checkpoint_bytes, parse_zisk_vk,
    verify_block_ad_proofs, verify_light_certificate, verify_tx_inclusion,
    PINNED_ZISK_ROOT_VK_PROD128,
};
use flate2::write::GzEncoder;
use flate2::Compression;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Minimal standalone Ergo NiPoPoW V2 light-client verifier (zero prover SDK, zero CUDA)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Cold-verify a 128-bit certificate (raw or .gz) + exact tail, optionally saving a ~1.2 KiB LightCheckpoint.
    VerifyCert {
        #[arg(long)]
        cert_bin: PathBuf,
        #[arg(long)]
        headers_u32le: PathBuf,
        #[arg(long, default_value_t = 1_823_986)]
        query_height: u32,
        #[arg(long)]
        zisk_root_vk: Option<String>,
        #[arg(long)]
        save_checkpoint: Option<PathBuf>,
    },
    /// Extend a previously saved LightCheckpoint with plain Ergo headers (~160 KiB/day, zero STARK download).
    ExtendTail {
        #[arg(long)]
        checkpoint_in: PathBuf,
        #[arg(long)]
        new_headers_u32le: PathBuf,
        #[arg(long)]
        checkpoint_out: PathBuf,
    },
    /// Cold-verify certificate + exact tail, extract certified headers h-1 & h, and verify real Ergo
    /// mainnet AVL+ ADProofs UTXO state transition + transaction Merkle inclusion proof against them.
    VerifyStateProof {
        #[arg(long)]
        cert_bin: PathBuf,
        #[arg(long)]
        headers_u32le: PathBuf,
        #[arg(long)]
        state_fixture_json: PathBuf,
        #[arg(long)]
        zisk_root_vk: Option<String>,
    },
    /// Extend a saved LightCheckpoint with plain post-STARK Ergo headers and verify real live
    /// AVL+ ADProofs UTXO state transition + Scorex Tx Merkle proof directly at the new live tip.
    VerifyLiveStateProof {
        #[arg(long)]
        checkpoint_in: PathBuf,
        #[arg(long)]
        new_headers_u32le: PathBuf,
        #[arg(long)]
        state_fixture_json: PathBuf,
    },
    /// Verify multiple untrusted peer (cert, tail) bundles, reject invalid/tampered peers
    /// fail-closed, and deterministically pick the heaviest valid chain via `select_best`.
    CompareCerts {
        /// Repeatable peer candidate formatted as `<label>=<cert_path>,<tail_path>`.
        #[arg(long = "peer", required = true)]
        peers: Vec<String>,
        #[arg(long, default_value_t = 1_823_986)]
        query_height: u32,
        #[arg(long)]
        zisk_root_vk: Option<String>,
    },
    /// Compress a certificate or header tail with pure-Rust gzip level 9 for mobile transport.
    Compress {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(serde::Deserialize)]
struct LiveStateProofFixture {
    height: u32,
    prev_height: u32,
    ad_proofs_hex: String,
    spent_box_ids: Vec<String>,
    created_boxes: Vec<RawCreatedBox>,
    merkle_tx_proof: RawMerkleProof,
}

#[derive(serde::Deserialize)]
struct RawCreatedBox {
    box_id: String,
    raw_bytes_hex: String,
}

#[derive(serde::Deserialize)]
struct RawMerkleProof {
    #[serde(rename = "leafData")]
    leaf_data: String,
    levels: Vec<(String, u8)>,
}

#[derive(serde::Deserialize)]
struct StateProofFixture {
    height: u32,
    ad_proofs_hex: String,
    spent_box_ids: Vec<String>,
    created_boxes: Vec<RawCreatedBox>,
    merkle_tx_proof_1823985: RawMerkleProof,
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32-byte hex".to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::VerifyCert {
            cert_bin,
            headers_u32le,
            query_height,
            zisk_root_vk,
            save_checkpoint,
        } => {
            let t0 = Instant::now();
            let zvk = match zisk_root_vk {
                Some(s) => parse_zisk_vk(&s)?,
                None => PINNED_ZISK_ROOT_VK_PROD128,
            };
            let cert_bytes = fs::read(&cert_bin)?;
            let tail_bytes = fs::read(&headers_u32le)?;
            let res = verify_light_certificate(&cert_bytes, &tail_bytes, query_height, &zvk)?;
            if let Some(cp_path) = save_checkpoint {
                fs::write(&cp_path, serde_json::to_vec_pretty(&res.tail.checkpoint)?)?;
            }
            let qh = res.tail.query_header.as_ref().expect("query header");
            println!(
                "LIGHT_COLD_VERIFY_PASS: backend={:?} dual_openvm_present={} h={} tip={} id={} state_root={} tx_root={} draws={} total={:.3}s",
                res.backend,
                res.dual_openvm_half_present,
                qh.height,
                res.tail.tip_height,
                hex::encode(qh.id),
                hex::encode(qh.state_root),
                hex::encode(qh.transactions_root),
                res.audit_draws,
                t0.elapsed().as_secs_f64()
            );
        }
        Cmd::ExtendTail {
            checkpoint_in,
            new_headers_u32le,
            checkpoint_out,
        } => {
            let t0 = Instant::now();
            let cp: LightCheckpoint = serde_json::from_slice(&fs::read(&checkpoint_in)?)?;
            let old_tip = cp.tip_height;
            let raw = fs::read(&new_headers_u32le)?;
            let (next, appended) = extend_light_checkpoint_bytes(&cp, &raw)?;
            fs::write(&checkpoint_out, serde_json::to_vec_pretty(&next)?)?;
            println!(
                "LIGHT_EXTEND_TAIL_PASS: {} -> {} (+{} headers, {} B wire, zero STARK) tip_id={} state_root={} elapsed={:.3}s",
                old_tip,
                next.tip_height,
                appended.len(),
                raw.len(),
                hex::encode(next.tip_id),
                hex::encode(next.tip_state_root),
                t0.elapsed().as_secs_f64()
            );
        }
        Cmd::VerifyStateProof {
            cert_bin,
            headers_u32le,
            state_fixture_json,
            zisk_root_vk,
        } => {
            let t0 = Instant::now();
            let zvk = match zisk_root_vk {
                Some(s) => parse_zisk_vk(&s)?,
                None => PINNED_ZISK_ROOT_VK_PROD128,
            };
            let fix: StateProofFixture =
                serde_json::from_slice(&fs::read(&state_fixture_json)?)?;
            let cert_bytes = fs::read(&cert_bin)?;
            let tail_bytes = fs::read(&headers_u32le)?;
            let res = verify_light_certificate(&cert_bytes, &tail_bytes, fix.height, &zvk)?;
            let prev_hdr = res
                .tail
                .prev_query_header
                .as_ref()
                .ok_or("missing certified header h-1")?;
            let curr_hdr = res
                .tail
                .query_header
                .as_ref()
                .ok_or("missing certified header h")?;

            let ad_bytes = hex::decode(&fix.ad_proofs_hex)?;
            let spent: Vec<[u8; 32]> = fix
                .spent_box_ids
                .iter()
                .map(|s| hex32(s))
                .collect::<Result<Vec<_>, _>>()?;
            let created: Vec<([u8; 32], Vec<u8>)> = fix
                .created_boxes
                .iter()
                .map(|b| Ok((hex32(&b.box_id)?, hex::decode(&b.raw_bytes_hex)?)))
                .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

            let t_st = Instant::now();
            let new_root = verify_block_ad_proofs(prev_hdr, curr_hdr, &ad_bytes, &spent, &created)?;
            let tx_proof = ErgoTxMerkleProof {
                leaf_data: hex32(&fix.merkle_tx_proof_1823985.leaf_data)?,
                levels: fix
                    .merkle_tx_proof_1823985
                    .levels
                    .iter()
                    .map(|(h, s)| Ok((hex32(h)?, *s)))
                    .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
            };
            verify_tx_inclusion(prev_hdr, &tx_proof)?;
            let state_ms = t_st.elapsed().as_secs_f64() * 1000.0;

            // Negative tamper checks on real certified state roots (must ALL fail closed!)
            let mut bad_ad = ad_bytes.clone();
            bad_ad[100] ^= 0x01;
            assert!(
                verify_block_ad_proofs(prev_hdr, curr_hdr, &bad_ad, &spent, &created).is_err(),
                "TAMPER FAILED: modified ADProofs passed!"
            );
            let mut bad_created = created.clone();
            bad_created[0].1[0] ^= 0x01;
            assert!(
                verify_block_ad_proofs(prev_hdr, curr_hdr, &ad_bytes, &spent, &bad_created)
                    .is_err(),
                "TAMPER FAILED: modified UTXO box passed!"
            );
            let mut bad_tx = tx_proof.clone();
            bad_tx.leaf_data[0] ^= 0x01;
            assert!(
                verify_tx_inclusion(prev_hdr, &bad_tx).is_err(),
                "TAMPER FAILED: modified tx Merkle proof passed!"
            );

            println!(
                "TRUSTLESS_STATE_PROOF_PASS: cert_h={} avl_transition={}->{} spent={} created={} ad_bytes={} tx_merkle_h={} state_verify={:.2}ms total={:.3}s (3/3 tamper checks rejected)",
                curr_hdr.height,
                hex::encode(prev_hdr.state_root),
                hex::encode(new_root),
                spent.len(),
                created.len(),
                ad_bytes.len(),
                prev_hdr.height,
                state_ms,
                t0.elapsed().as_secs_f64()
            );
        }
        Cmd::VerifyLiveStateProof {
            checkpoint_in,
            new_headers_u32le,
            state_fixture_json,
        } => {
            let t0 = Instant::now();
            let cp: LightCheckpoint = serde_json::from_slice(&fs::read(&checkpoint_in)?)?;
            let ext_raw = fs::read(&new_headers_u32le)?;
            let fix: LiveStateProofFixture =
                serde_json::from_slice(&fs::read(&state_fixture_json)?)?;
            let (next, hdrs) = extend_light_checkpoint_bytes(&cp, &ext_raw)?;
            let prev_hdr = hdrs
                .iter()
                .find(|h| h.height == fix.prev_height)
                .ok_or("prev_height not found in extension")?;
            let curr_hdr = hdrs
                .iter()
                .find(|h| h.height == fix.height)
                .ok_or("height not found in extension")?;

            let ad_bytes = hex::decode(&fix.ad_proofs_hex)?;
            let spent: Vec<[u8; 32]> = fix
                .spent_box_ids
                .iter()
                .map(|s| hex32(s))
                .collect::<Result<Vec<_>, _>>()?;
            let created: Vec<([u8; 32], Vec<u8>)> = fix
                .created_boxes
                .iter()
                .map(|b| Ok((hex32(&b.box_id)?, hex::decode(&b.raw_bytes_hex)?)))
                .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

            let t_st = Instant::now();
            let new_root = verify_block_ad_proofs(prev_hdr, curr_hdr, &ad_bytes, &spent, &created)?;
            let tx_proof = ErgoTxMerkleProof {
                leaf_data: hex32(&fix.merkle_tx_proof.leaf_data)?,
                levels: fix
                    .merkle_tx_proof
                    .levels
                    .iter()
                    .map(|(h, s)| Ok((hex32(h)?, *s)))
                    .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
            };
            verify_tx_inclusion(curr_hdr, &tx_proof)?;
            let state_ms = t_st.elapsed().as_secs_f64() * 1000.0;

            // Negative tamper checks on live extended tip
            let mut bad_ad = ad_bytes.clone();
            bad_ad[42] ^= 0x01;
            assert!(verify_block_ad_proofs(prev_hdr, curr_hdr, &bad_ad, &spent, &created).is_err());
            let mut bad_created = created.clone();
            bad_created[0].1[10] ^= 0x01;
            assert!(
                verify_block_ad_proofs(prev_hdr, curr_hdr, &ad_bytes, &spent, &bad_created)
                    .is_err()
            );
            let mut bad_tx = tx_proof.clone();
            bad_tx.leaf_data[0] ^= 0x01;
            assert!(verify_tx_inclusion(curr_hdr, &bad_tx).is_err());

            println!(
                "TRUSTLESS_LIVE_TIP_STATE_PROOF_PASS: {} -> {} (+{} plain hdrs, zero STARK) live_h={} avl_transition={}->{} spent={} created={} ad_bytes={} state_verify={:.2}ms total={:.3}s (3/3 tamper checks rejected)",
                cp.tip_height,
                next.tip_height,
                hdrs.len(),
                curr_hdr.height,
                hex::encode(prev_hdr.state_root),
                hex::encode(new_root),
                spent.len(),
                created.len(),
                ad_bytes.len(),
                state_ms,
                t0.elapsed().as_secs_f64()
            );
        }
        Cmd::CompareCerts {
            peers,
            query_height,
            zisk_root_vk,
        } => {
            let t0 = Instant::now();
            let zvk = match zisk_root_vk {
                Some(s) => parse_zisk_vk(&s)?,
                None => PINNED_ZISK_ROOT_VK_PROD128,
            };
            let mut loaded: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::with_capacity(peers.len());
            for spec in &peers {
                let (label, paths) = spec
                    .split_once('=')
                    .ok_or("each --peer must be formatted as <label>=<cert_path>,<tail_path>")?;
                let (cert_p, tail_p) = paths
                    .split_once(',')
                    .ok_or("each --peer must be formatted as <label>=<cert_path>,<tail_path>")?;
                loaded.push((label.to_string(), fs::read(cert_p)?, fs::read(tail_p)?));
            }
            let refs: Vec<(&str, &[u8], &[u8])> = loaded
                .iter()
                .map(|(l, c, t)| (l.as_str(), c.as_slice(), t.as_slice()))
                .collect();
            let res = compare_peer_certificates(&refs, query_height, &zvk)?;
            for (bad_label, reason) in &res.rejected_peers {
                println!("PEER_REJECTED_FAIL_CLOSED: peer={bad_label} reason={reason}");
            }
            println!(
                "MULTI_PEER_SELECT_BEST_PASS: winner={} (idx={}) admitted={} rejected={} work={} h={} id={} elapsed={:.3}s",
                res.winner_label,
                res.winner_index,
                res.admitted_count,
                res.rejected_peers.len(),
                res.winner_work,
                query_height,
                hex::encode(res.winner_header_id),
                t0.elapsed().as_secs_f64()
            );
        }
        Cmd::Compress { input, output } => {
            let raw = fs::read(&input)?;
            let mut enc = GzEncoder::new(Vec::new(), Compression::best());
            enc.write_all(&raw)?;
            let compressed = enc.finish()?;
            fs::write(&output, &compressed)?;
            println!(
                "COMPRESSED_OK: {} ({} B) -> {} ({} B, {:.1}%)",
                input.display(),
                raw.len(),
                output.display(),
                compressed.len(),
                100.0 * compressed.len() as f64 / raw.len().max(1) as f64
            );
        }
    }
    Ok(())
}
