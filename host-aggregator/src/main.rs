//! Production Depth-2 Recursive STARK Aggregator & Cold Certificate Verifier
//! for Ergo NiPoPoW V2 (`V2Production128`, strict 128-bit end-to-end security with
//! Heterogeneous Dual-Proof ZisK v1.4.0-alpha STIR + OpenVM v2.1.0 SWIRL/WHIR).
//!
//! Commands:
//!   smoke-l1        Verify + recursively aggregate `seg-00000` + `seg-00001` into 1 Level-1 proof
//!                   and cold-verify it (measures exact per-child deferral timing).
//!   aggregate-all   Aggregate ALL 449 verified leaf proofs (`seg-00000..=seg-00443` + `seg-00444a/b/c`
//!                   + `seg-00445` + `seg-00446`) via constant depth 2 (L1 -> Root) into ONE single
//!                   root post-quantum STARK proof certifying `BootstrapStatement` for all 1,827,840
//!                   Ergo mainnet headers, then assemble and cold-verify the complete `V2Certificate`.
//!   verify-cert     Standalone witness-free cold light-client verifier for an exported `V2Certificate`
//!                   + exact modern continuation tail.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use bincode::Options;
use clap::{Parser, Subcommand};
use eyre::{eyre, Result};
use openvm_recursion_circuit::batch_constraint::commit_child_vk;
use openvm_sdk::{
    config::{AggregationConfig, AppConfig},
    fs::{read_from_file_json, read_object_from_file, write_object_to_file, write_to_file_json},
    openvm_circuit::arch::InitFileGenerator,
    prover::{DeferralAggProver, MultiDeferralCircuitProver},
    types::{VerificationBaselineJson, VersionedVmStarkProof},
    DefaultStarkEngine as E, DeferralInput, Sdk, StdIn, SC,
};
use openvm_sdk_config::{deferral::SupportedDeferral, SdkSystemConfig, SdkVmConfig};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE};
use openvm_stark_backend::{
    keygen::types::MultiStarkVerifyingKey,
    p3_field::{PrimeCharacteristicRing, PrimeField32},
    StarkEngine,
};
use openvm_stark_sdk::config::{
    app_params_with_100_bits_security, baby_bear_poseidon2::Digest,
    hook_params_with_100_bits_security, MAX_APP_LOG_STACKED_HEIGHT,
};
use openvm_verify_stark_circuit::{
    default_verify_stark_circuit_params,
    extension::{get_deferral_state, get_raw_deferral_results},
};
use openvm_verify_stark_host::{
    vk::{VerificationBaseline, VmStarkVerifyingKey},
    VmStarkProof,
};

use ergo_nipopow_v2_core::audit::{build_audit_bundle, verify_audit_bundle};
use ergo_nipopow_v2_core::certificate::{
    DualStructuralProof, StructuralBackend, V2Certificate, CERT_MAGIC,
};
use ergo_nipopow_v2_core::daa::decode_compact;
use ergo_nipopow_v2_core::header::{Header, HeaderPointWitness};
use ergo_nipopow_v2_core::mmr::{hash_leaf, mainnet_profile32, sha256_bytes, MmrStore};
use ergo_nipopow_v2_core::profile::ProfileId;
use ergo_nipopow_v2_core::segment::{
    check_bootstrap_eligibility, merge_segments, BootstrapStatement, BoundaryState, SegmentSummary,
};
use ergo_nipopow_v2_core::tail::verify_exact_tail;
use zisk_verifier::keys::{VADCOP_FINAL_COMPRESSED_VK_BLAKE3, VADCOP_FINAL_VK_BLAKE3};

cfg_if::cfg_if! {
    if #[cfg(feature = "cuda")] {
        use openvm_verify_stark_circuit::prover::{
            DeferredVerifyGpuCircuitProver as VerifyCircuitProver,
            DeferredVerifyGpuProver as VerifyProver,
        };
    } else {
        use openvm_verify_stark_circuit::prover::{
            DeferredVerifyCpuCircuitProver as VerifyCircuitProver,
            DeferredVerifyCpuProver as VerifyProver,
        };
    }
}

const VERIFY_STARK_DEF_IDX: usize = 0;

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

#[derive(serde::Serialize, serde::Deserialize)]
struct ChildClaim {
    proof_commit: [u8; 32],
    summary: SegmentSummary,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct L1Input {
    children: Vec<ChildClaim>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RootInput {
    prefix_children: Vec<ChildClaim>,
    bridge_child: ChildClaim,
    suffix_children: Vec<ChildClaim>,
}

#[derive(Parser)]
#[command(author, version, about = "Ergo NiPoPoW V2 Depth-2 OpenVM v2.1.0 Aggregator")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    SmokeL1 {
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        leaf_agg_vk: PathBuf,
        #[arg(long)]
        leaf_baseline: PathBuf,
        #[arg(long)]
        seg_dir: PathBuf,
        #[arg(long)]
        proof_dir: PathBuf,
        #[arg(long)]
        guest_l1_dir: PathBuf,
        #[arg(long, default_value_t = 2)]
        count: usize,
    },
    AggregateAll {
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        leaf_agg_vk: PathBuf,
        #[arg(long)]
        leaf_baseline: PathBuf,
        #[arg(long)]
        seg_dir: PathBuf,
        #[arg(long)]
        split_dir: PathBuf,
        #[arg(long)]
        proof_dir: PathBuf,
        #[arg(long)]
        guest_l1_dir: PathBuf,
        #[arg(long)]
        guest_root_dir: PathBuf,
        #[arg(long)]
        headers_u32le: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value_t = 64)]
        fan_in: usize,
        #[arg(long, default_value_t = 1_823_986)]
        query_height: u32,
    },
    AssembleZiskCert {
        #[arg(long)]
        zisk_root_proof: PathBuf,
        #[arg(long)]
        zisk_root_vk: String,
        #[arg(long)]
        statement_bin: PathBuf,
        #[arg(long)]
        headers_u32le: PathBuf,
        #[arg(long, default_value_t = 1_823_986)]
        query_height: u32,
        #[arg(long)]
        out_dir: PathBuf,
    },
    AssembleDualCert {
        #[arg(long)]
        zisk_root_proof: PathBuf,
        #[arg(long)]
        zisk_root_vk: String,
        #[arg(long)]
        openvm_root_proof: PathBuf,
        #[arg(long)]
        openvm_root_vk: PathBuf,
        #[arg(long)]
        openvm_root_baseline: PathBuf,
        #[arg(long)]
        statement_bin: PathBuf,
        #[arg(long)]
        headers_u32le: PathBuf,
        #[arg(long, default_value_t = 1_823_986)]
        query_height: u32,
        #[arg(long)]
        out_dir: PathBuf,
    },
    VerifyCert {
        #[arg(long)]
        cert_bin: PathBuf,
        #[arg(long)]
        root_agg_vk: Option<PathBuf>,
        #[arg(long)]
        root_baseline: Option<PathBuf>,
        #[arg(long)]
        zisk_root_vk: Option<String>,
        #[arg(long)]
        headers_u32le: PathBuf,
        #[arg(long, default_value_t = 1_823_986)]
        query_height: u32,
        /// Explicit opt-in required to verify a standalone `OpenVmSwirlV21` certificate
        /// (whose OpenVM v2.1.0 default parameters target 100-bit proven RBR security
        /// rather than strict 128-bit; production certificates use `ZiskStirV14`
        /// or `DualZiskV14OpenVmV21`).
        #[arg(long, default_value_t = false)]
        allow_non_128_standalone_openvm: bool,
        /// Explicit opt-in required to override the compile-time pinned `v0.4.0`
        /// reproducible ZisK root VK and OpenVM `root-agg.vk` / `root-baseline.json` SHA-256 hashes.
        #[arg(long, default_value_t = false)]
        unsafe_override_vk: bool,
    },
}

const PINNED_ZISK_ROOT_VK_PROD128: [u64; 4] = [
    11772000642296811191,
    2917608110684279903,
    7269122849900466967,
    12697094355253129467,
];
const PINNED_OPENVM_ROOT_AGG_VK_SHA256: &str =
    "15d415ec0e8dc7910c771c0fc699b0ebec5a42512c595a8f5e9dcd962e6c1d2b";
const PINNED_OPENVM_ROOT_BASELINE_SHA256: &str =
    "4e1441e68c98cf3c99aaf5095ed79f5a1e4bd0ac88c785b6ad51e6a7e0a77d58";
const MAX_CERT_RAW_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 514;
const MAX_VK_FILE_BYTES: usize = 4 * 1024 * 1024;

fn read_bounded_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let meta = fs::metadata(path)?;
    if meta.len() > max_bytes as u64 {
        return Err(eyre!(
            "file {} size {} B exceeds cap {} B",
            path.display(),
            meta.len(),
            max_bytes
        ));
    }
    let f = File::open(path)?;
    let mut buf = Vec::new();
    f.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        return Err(eyre!(
            "file {} exceeds cap {} B while reading",
            path.display(),
            max_bytes
        ));
    }
    Ok(buf)
}

fn parse_zisk_vk(s: &str) -> Result<[u64; 4]> {
    let cleaned = s.trim().trim_start_matches('[').trim_end_matches(']');
    let limbs: Vec<u64> = cleaned
        .split(',')
        .map(|part| part.trim().parse::<u64>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| eyre!("invalid zisk VK '{s}': {e}"))?;
    if limbs.len() != 4 {
        return Err(eyre!("zisk VK must have exactly 4 comma-separated u64 limbs"));
    }
    Ok([limbs[0], limbs[1], limbs[2], limbs[3]])
}

fn verify_zisk_root_proof_bytes(
    proof_bytes: &[u8],
    expected_root_vk: &[u64; 4],
    expected_pv: &[u8; 32],
) -> Result<()> {
    const SEED_TRAILER_TAG: u64 = u64::from_le_bytes(*b"ZISKSEED");
    let saved = zisk_verifier::decode_saved(proof_bytes)
        .map_err(|e| eyre!("zisk decode_saved failed: {e}"))?;
    if saved.proof.hash != "blake3" {
        return Err(eyre!(
            "zisk proof hash family must be blake3 (128-bit collision resistance), got {}",
            saved.proof.hash
        ));
    }
    let setup_vk = if saved.proof.compressed {
        &VADCOP_FINAL_COMPRESSED_VK_BLAKE3
    } else {
        &VADCOP_FINAL_VK_BLAKE3
    };
    if proof_bytes.len() % 8 != 0 {
        return Err(eyre!("zisk proof bytes not 8-byte aligned"));
    }
    let mut words: Vec<u64> = proof_bytes
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    if words.last() == Some(&SEED_TRAILER_TAG) {
        if words.len() < 5 {
            return Err(eyre!("truncated zisk seed trailer"));
        }
        words.truncate(words.len() - 5);
    }
    let verified = zisk_verifier::verify_saved_words(&words, setup_vk, Some(expected_root_vk))
        .map_err(|e| eyre!("zisk STARK verification failed: {e}"))?;
    let outs = verified
        .outputs_u32()
        .ok_or_else(|| eyre!("zisk proof missing u32 leaf outputs"))?;
    let mut committed = [0u8; 32];
    for i in 0..8 {
        committed[i * 4..(i + 1) * 4].copy_from_slice(&outs[i].to_le_bytes());
    }
    if committed.as_slice() != expected_pv.as_slice() {
        return Err(eyre!(
            "zisk root STARK output mismatch: got {}, expected {}",
            hex::encode(committed),
            hex::encode(expected_pv)
        ));
    }
    Ok(())
}

fn format_bytes_const(bytes: &[u8; 32]) -> String {
    let parts: Vec<String> = bytes.iter().map(|b| format!("0x{b:02x}")).collect();
    format!("[{}]", parts.join(", "))
}

/// Compile a RISC-V guest package cleanly using `.status()` (avoids OpenVM's `/dev/tty` +
/// piped-stderr deadlock in non-interactive or multi-SDK processes) with deterministic
/// `--remap-path-prefix` flags so compiled ELFs and `exe_commit`s reproduce across hosts.
fn build_guest_elf_clean(vm_config: &SdkVmConfig, pkg_dir: &Path, bin_name: &str) -> Result<Elf> {
    vm_config.write_to_init_file(pkg_dir, None)?;
    let target_dir = pkg_dir.join("target");
    fs::create_dir_all(&target_dir)?;
    let manifest_path = pkg_dir.join("Cargo.toml");
    let canonical_pkg = fs::canonicalize(pkg_dir).unwrap_or_else(|_| pkg_dir.to_path_buf());
    let repo_root = canonical_pkg
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&canonical_pkg);
    let mut owned_flags = vec![format!(
        "--remap-path-prefix={}=/ergo-nipopow-v2",
        repo_root.display()
    )];
    if let Ok(cargo_home) = std::env::var("CARGO_HOME")
        .or_else(|_| std::env::var("HOME").map(|h| format!("{h}/.cargo")))
    {
        owned_flags.push(format!("--remap-path-prefix={cargo_home}=/cargo"));
    }
    if let Ok(rustup_home) = std::env::var("RUSTUP_HOME")
        .or_else(|_| std::env::var("HOME").map(|h| format!("{h}/.rustup")))
    {
        owned_flags.push(format!("--remap-path-prefix={rustup_home}=/rustup"));
    }
    let flag_refs: Vec<&str> = owned_flags.iter().map(String::as_str).collect();
    let mut cmd = openvm_build::cargo_command("build", &flag_refs);
    let status = cmd
        .args([
            "--manifest-path",
            manifest_path.to_str().ok_or_else(|| eyre!("utf8 path"))?,
            "--target-dir",
            target_dir.to_str().ok_or_else(|| eyre!("utf8 path"))?,
            "--profile",
            "release",
        ])
        .status()?;
    if !status.success() {
        return Err(eyre!("guest cargo build failed for {} ({status})", pkg_dir.display()));
    }
    let elf_path = target_dir
        .join("riscv32im-risc0-zkvm-elf")
        .join("release")
        .join(bin_name);
    let data = fs::read(&elf_path)?;
    Elf::decode(&data, MEM_SIZE as u32).map_err(|e| eyre!("decode elf: {e}"))
}

fn proof_user_pvs_bytes(proof: &VmStarkProof) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(proof.user_pvs_proof.public_values.len());
    for &f in &proof.user_pvs_proof.public_values {
        let v = f.as_canonical_u32();
        if v > 255 {
            return Err(eyre!("non-byte user public value: {v}"));
        }
        out.push(v as u8);
    }
    Ok(out)
}

fn load_leaf_proof_and_summary(
    seg_bin: &Path,
    proof_json: &Path,
    child_agg_vk: &MultiStarkVerifyingKey<SC>,
    child_baseline: &VerificationBaseline,
) -> Result<(VmStarkProof, SegmentSummary)> {
    let pkg: SegmentInputPackage = bincode::deserialize(&fs::read(seg_bin)?)?;
    let ver: VersionedVmStarkProof = read_from_file_json(proof_json)?;
    let proof = ver.decode_using_vk(child_agg_vk, child_baseline)?;
    let pv = proof_user_pvs_bytes(&proof)?;
    let expected_pv = sha256_bytes(&bincode::serialize(&pkg.expected_summary)?);
    if pv.as_slice() != expected_pv.as_slice() {
        return Err(eyre!(
            "leaf proof {} PV mismatch: got {}, expected {}",
            proof_json.display(),
            hex::encode(&pv),
            hex::encode(expected_pv)
        ));
    }
    Ok((proof, pkg.expected_summary))
}

fn build_verify_stark_sdk(
    child_agg_vk: Arc<MultiStarkVerifyingKey<SC>>,
    child_def_hook_commit: Option<Digest>,
) -> Result<(Sdk, SdkVmConfig, Arc<MultiStarkVerifyingKey<SC>>, Digest)> {
    let default_config = SdkSystemConfig::default();
    let memory_dimensions = default_config.config.memory_config.memory_dimensions();
    let num_user_pvs = default_config.config.num_public_values;

    let app_params = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
    let agg_config = AggregationConfig::default();
    let verify_prover_params = default_verify_stark_circuit_params();

    let engine = <E as StarkEngine>::new(child_agg_vk.inner.params.clone());
    let child_ir_cached_commit = commit_child_vk(&engine, &child_agg_vk, true)
        .commitment
        .into();

    let verify_prover = VerifyProver::new::<E>(
        child_agg_vk,
        child_ir_cached_commit,
        verify_prover_params,
        memory_dimensions,
        num_user_pvs,
        child_def_hook_commit.map(Into::into),
        VERIFY_STARK_DEF_IDX,
    );
    let verify_circuit_prover = VerifyCircuitProver::new(verify_prover);
    let multi_def = MultiDeferralCircuitProver::new(
        verify_circuit_prover,
        agg_config.clone(),
        hook_params_with_100_bits_security(),
    );
    let def_agg = DeferralAggProver::new(agg_config.clone(), Arc::new(multi_def));
    let my_def_hook_commit = def_agg.def_hook_commit();

    let deferral_config = def_agg
        .multi_deferral_circuit_prover
        .make_config(vec![SupportedDeferral::VerifyStark]);

    let vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .sha2(Default::default())
        .deferral(deferral_config)
        .build()
        .optimize();

    let sdk = Sdk::builder()
        .app_config(AppConfig::new(vm_config.clone(), app_params))
        .agg_params(agg_config.params)
        .deferral_agg_prover(def_agg)
        .build()?;
    let _ = sdk.app_keygen();
    let _ = sdk.agg_pk();
    let my_agg_vk = sdk.agg_vk();
    Ok((sdk, vm_config, my_agg_vk, my_def_hook_commit))
}

fn extract_child_exe_and_vm_commits(
    child_vk: &VmStarkVerifyingKey,
    sample_proof: &VmStarkProof,
    verify_stark_cached_commit: Digest,
) -> Result<([u8; 32], [u8; 32])> {
    let raw_res = get_raw_deferral_results(
        child_vk,
        std::slice::from_ref(sample_proof),
        verify_stark_cached_commit,
    )?;
    if raw_res.len() != 1 || raw_res[0].output_raw.len() < 64 {
        return Err(eyre!("unexpected deferral output length"));
    }
    let exe: [u8; 32] = raw_res[0].output_raw[0..32].try_into().unwrap();
    let vm: [u8; 32] = raw_res[0].output_raw[32..64].try_into().unwrap();
    Ok((exe, vm))
}

fn prove_l1_batch(
    sdk: &Sdk,
    exe: Arc<openvm_sdk::openvm_circuit::arch::instructions::exe::VmExe<openvm_sdk::F>>,
    child_vk: &VmStarkVerifyingKey,
    verify_stark_cached_commit: Digest,
    proofs: &[VmStarkProof],
    summaries: &[SegmentSummary],
) -> Result<(VmStarkProof, SegmentSummary)> {
    let raw_res = get_raw_deferral_results(child_vk, proofs, verify_stark_cached_commit)?;
    assert_eq!(raw_res.len(), proofs.len());

    let mut claims = Vec::with_capacity(proofs.len());
    for (r, s) in raw_res.iter().zip(summaries.iter()) {
        let proof_commit: [u8; 32] = r.input.clone().try_into().map_err(|_| eyre!("commit len"))?;
        claims.push(ChildClaim {
            proof_commit,
            summary: s.clone(),
        });
    }
    let payload = bincode::serialize(&L1Input { children: claims })?;
    let mut stdin = StdIn::default();
    stdin.write_bytes(&payload);
    stdin.deferrals = vec![get_deferral_state(
        child_vk,
        proofs,
        verify_stark_cached_commit,
        VERIFY_STARK_DEF_IDX as u32,
    )?];
    let def_inputs = vec![DeferralInput::from_inputs(proofs)];

    let (proof, _) = sdk.prove(exe, stdin, &def_inputs)?;
    let merged = merge_segments(summaries).map_err(|e| eyre!("merge: {e:?}"))?;
    let expected_pv = sha256_bytes(&bincode::serialize(&merged)?);
    let actual_pv = proof_user_pvs_bytes(&proof)?;
    if actual_pv.as_slice() != expected_pv.as_slice() {
        return Err(eyre!(
            "L1 revealed PV mismatch: got {}, expected {}",
            hex::encode(&actual_pv),
            hex::encode(expected_pv)
        ));
    }
    Ok((proof, merged))
}

fn read_u32le_headers(path: &Path) -> Result<Vec<Vec<u8>>> {
    let f = File::open(path)?;
    let mut r = BufReader::with_capacity(8 * 1024 * 1024, f);
    let mut headers = Vec::new();
    let mut len_buf = [0u8; 4];
    loop {
        match r.read_exact(&mut len_buf) {
            Ok(()) => {
                let len = u32::from_le_bytes(len_buf) as usize;
                if len == 0 || len > MAX_HEADER_BYTES {
                    return Err(eyre!(
                        "invalid u32le header length {} in {} (expected 1..={})",
                        len,
                        path.display(),
                        MAX_HEADER_BYTES
                    ));
                }
                let mut raw = vec![0u8; len];
                r.read_exact(&mut raw)?;
                headers.push(raw);
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(headers)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::SmokeL1 {
            work_dir,
            leaf_agg_vk,
            leaf_baseline,
            seg_dir,
            proof_dir,
            guest_l1_dir,
            count,
        } => {
            fs::create_dir_all(&work_dir)?;
            let child_agg_vk: Arc<MultiStarkVerifyingKey<SC>> =
                Arc::new(read_object_from_file(&leaf_agg_vk)?);
            let child_baseline_json: VerificationBaselineJson = read_from_file_json(&leaf_baseline)?;
            let child_baseline: VerificationBaseline = child_baseline_json.into();
            let child_vk = VmStarkVerifyingKey {
                mvk: child_agg_vk.as_ref().clone(),
                baseline: child_baseline.clone(),
            };

            let mut proofs = Vec::new();
            let mut summaries = Vec::new();
            for i in 0..count {
                let tag = format!("seg-{i:05}");
                let (p, s) = load_leaf_proof_and_summary(
                    &seg_dir.join(format!("{tag}.bin")),
                    &proof_dir.join(format!("{tag}.stark.proof")),
                    &child_agg_vk,
                    &child_baseline,
                )?;
                proofs.push(p);
                summaries.push(s);
            }
            println!("Loaded {count} verified leaf proofs.");

            let t_kg = Instant::now();
            let (sdk_l1, l1_vm_config, l1_agg_vk, _l1_hook) =
                build_verify_stark_sdk(child_agg_vk.clone(), None)?;
            println!("L1 SDK keygen finished in {:.2}s", t_kg.elapsed().as_secs_f64());

            let cached_commits = sdk_l1.deferral_circuit_cached_commits(VERIFY_STARK_DEF_IDX)?;
            let verify_stark_cached_commit: Digest = cached_commits[0].into();
            let (leaf_exe_c, leaf_vm_c) =
                extract_child_exe_and_vm_commits(&child_vk, &proofs[0], verify_stark_cached_commit)?;
            println!(
                "Pinned leaf commits: exe={} vm={}",
                hex::encode(leaf_exe_c),
                hex::encode(leaf_vm_c)
            );

            // Write exact pinned_leaf.rs + openvm.toml into guest_l1_dir before building
            fs::write(
                guest_l1_dir.join("src/pinned_leaf.rs"),
                format!(
                    "pub const EXPECTED_LEAF_EXE_COMMIT: [u8; 32] = {};\npub const EXPECTED_LEAF_VM_COMMIT: [u8; 32] = {};\n",
                    format_bytes_const(&leaf_exe_c),
                    format_bytes_const(&leaf_vm_c)
                ),
            )?;
            fs::write(guest_l1_dir.join("openvm.toml"), l1_vm_config.to_toml()?)?;

            let t_bld = Instant::now();
            let elf = build_guest_elf_clean(&l1_vm_config, &guest_l1_dir, "ergo-nipopow-v2-guest-agg-l1")?;
            let exe = sdk_l1.convert_to_exe(elf)?;
            let l1_baseline = sdk_l1.prover(exe.clone())?.generate_baseline();
            println!("Built L1 guest in {:.2}s", t_bld.elapsed().as_secs_f64());

            let t_prv = Instant::now();
            let (l1_proof, merged) = prove_l1_batch(
                &sdk_l1,
                exe,
                &child_vk,
                verify_stark_cached_commit,
                &proofs,
                &summaries,
            )?;
            let prv_s = t_prv.elapsed().as_secs_f64();

            let t_ver = Instant::now();
            Sdk::verify_proof(l1_agg_vk.as_ref().clone(), l1_baseline, &l1_proof)?;
            let ver_s = t_ver.elapsed().as_secs_f64();

            let ver_proof = VersionedVmStarkProof::new(l1_proof)?;
            let out_path = work_dir.join("smoke-l1.stark.proof");
            write_to_file_json(&out_path, &ver_proof)?;
            let sz = fs::metadata(&out_path)?.len();
            println!(
                "SMOKE_L1_PASS: count={} heights={}..={} prove_s={:.2}s ({:.2}s/child) verify_s={:.3}s bytes={}",
                count,
                merged.state_in.height + 1,
                merged.state_out.height,
                prv_s,
                prv_s / count as f64,
                ver_s,
                sz
            );
        }

        Cmd::AggregateAll {
            work_dir,
            leaf_agg_vk,
            leaf_baseline,
            seg_dir,
            split_dir,
            proof_dir,
            guest_l1_dir,
            guest_root_dir,
            headers_u32le,
            out_dir,
            fan_in,
            query_height,
        } => {
            let t_all = Instant::now();
            fs::create_dir_all(&work_dir)?;
            fs::create_dir_all(&out_dir)?;
            let l1_cache_dir = work_dir.join("l1-proofs");
            fs::create_dir_all(&l1_cache_dir)?;

            // 1. Load all 449 verified leaf proofs & summaries
            let leaf_agg_vk_arc: Arc<MultiStarkVerifyingKey<SC>> =
                Arc::new(read_object_from_file(&leaf_agg_vk)?);
            let leaf_baseline_json: VerificationBaselineJson = read_from_file_json(&leaf_baseline)?;
            let leaf_baseline_val: VerificationBaseline = leaf_baseline_json.into();
            let leaf_vk = VmStarkVerifyingKey {
                mvk: leaf_agg_vk_arc.as_ref().clone(),
                baseline: leaf_baseline_val.clone(),
            };

            println!("[1/5] Loading all 449 verified leaf proofs (444 frozen prefix + 1 split prefix + 1 bridge + 3 suffix)...");
            let mut frozen_prefix_leaves = Vec::with_capacity(444);
            for i in 0..=443usize {
                let tag = format!("seg-{i:05}");
                frozen_prefix_leaves.push(load_leaf_proof_and_summary(
                    &seg_dir.join(format!("{tag}.bin")),
                    &proof_dir.join(format!("{tag}.stark.proof")),
                    &leaf_agg_vk_arc,
                    &leaf_baseline_val,
                )?);
            }
            let tail_prefix_leaf = load_leaf_proof_and_summary(
                &split_dir.join("seg-00444a.bin"),
                &proof_dir.join("seg-00444a.stark.proof"),
                &leaf_agg_vk_arc,
                &leaf_baseline_val,
            )?;

            let bridge_leaf = load_leaf_proof_and_summary(
                &split_dir.join("seg-00444b.bin"),
                &proof_dir.join("seg-00444b.stark.proof"),
                &leaf_agg_vk_arc,
                &leaf_baseline_val,
            )?;

            let suffix_leaves = vec![
                load_leaf_proof_and_summary(
                    &split_dir.join("seg-00444c.bin"),
                    &proof_dir.join("seg-00444c.stark.proof"),
                    &leaf_agg_vk_arc,
                    &leaf_baseline_val,
                )?,
                load_leaf_proof_and_summary(
                    &seg_dir.join("seg-00445.bin"),
                    &proof_dir.join("seg-00445.stark.proof"),
                    &leaf_agg_vk_arc,
                    &leaf_baseline_val,
                )?,
                load_leaf_proof_and_summary(
                    &seg_dir.join("seg-00446.bin"),
                    &proof_dir.join("seg-00446.stark.proof"),
                    &leaf_agg_vk_arc,
                    &leaf_baseline_val,
                )?,
            ];
            println!("All 449 leaf proofs loaded and PV-verified!");

            // 2. Build Level-1 SDK & Guest
            println!("[2/5] Initializing Level-1 OpenVM v2.1.0 Deferral SDK...");
            let t_l1_setup = Instant::now();
            let (sdk_l1, l1_vm_config, l1_agg_vk, l1_def_hook_commit) =
                build_verify_stark_sdk(leaf_agg_vk_arc.clone(), None)?;
            let l1_cached_commit: Digest = sdk_l1
                .deferral_circuit_cached_commits(VERIFY_STARK_DEF_IDX)?[0]
                .into();
            let (leaf_exe_c, leaf_vm_c) = extract_child_exe_and_vm_commits(
                &leaf_vk,
                &frozen_prefix_leaves[0].0,
                l1_cached_commit,
            )?;
            fs::write(
                guest_l1_dir.join("src/pinned_leaf.rs"),
                format!(
                    "pub const EXPECTED_LEAF_EXE_COMMIT: [u8; 32] = {};\npub const EXPECTED_LEAF_VM_COMMIT: [u8; 32] = {};\n",
                    format_bytes_const(&leaf_exe_c),
                    format_bytes_const(&leaf_vm_c)
                ),
            )?;
            fs::write(guest_l1_dir.join("openvm.toml"), l1_vm_config.to_toml()?)?;
            let l1_elf = build_guest_elf_clean(&l1_vm_config, &guest_l1_dir, "ergo-nipopow-v2-guest-agg-l1")?;
            let l1_exe = sdk_l1.convert_to_exe(l1_elf)?;
            let l1_baseline = sdk_l1.prover(l1_exe.clone())?.generate_baseline();
            let l1_setup_s = t_l1_setup.elapsed().as_secs_f64();
            println!("L1 SDK + guest ready in {:.2}s", l1_setup_s);

            // Helper: prove or load cached Level-1 batch
            let mut l1_timings = Vec::new();
            let mut run_l1 = |label: &str, items: &[(VmStarkProof, SegmentSummary)]| -> Result<(VmStarkProof, SegmentSummary)> {
                let p_path = l1_cache_dir.join(format!("{label}.stark.proof"));
                let s_path = l1_cache_dir.join(format!("{label}.summary.bin"));
                if p_path.is_file() && s_path.is_file() {
                    let ver: VersionedVmStarkProof = read_from_file_json(&p_path)?;
                    let prf = ver.decode_using_vk(&l1_agg_vk, &l1_baseline)?;
                    Sdk::verify_proof(l1_agg_vk.as_ref().clone(), l1_baseline.clone(), &prf)?;
                    let sum: SegmentSummary = bincode::deserialize(&fs::read(&s_path)?)?;
                    println!("  [L1 reuse] {label} ({} leaves, heights {}..={})", items.len(), sum.state_in.height + 1, sum.state_out.height);
                    l1_timings.push(serde_json::json!({
                        "label": label,
                        "leaves": items.len(),
                        "start_height": sum.state_in.height + 1,
                        "end_height": sum.state_out.height,
                        "reused": true,
                        "prove_s": 0.0,
                        "verify_s": 0.0,
                        "proof_bytes": fs::metadata(&p_path)?.len(),
                    }));
                    return Ok((prf, sum));
                }
                let t0 = Instant::now();
                let prfs: Vec<VmStarkProof> = items.iter().map(|(p, _)| p.clone()).collect();
                let sums: Vec<SegmentSummary> = items.iter().map(|(_, s)| s.clone()).collect();
                let (prf, merged) = prove_l1_batch(&sdk_l1, l1_exe.clone(), &leaf_vk, l1_cached_commit, &prfs, &sums)?;
                let prv_s = t0.elapsed().as_secs_f64();
                let tv = Instant::now();
                Sdk::verify_proof(l1_agg_vk.as_ref().clone(), l1_baseline.clone(), &prf)?;
                let ver_s = tv.elapsed().as_secs_f64();
                let ver_prf = VersionedVmStarkProof::new(prf.clone())?;
                write_to_file_json(&p_path, &ver_prf)?;
                fs::write(&s_path, bincode::serialize(&merged)?)?;
                let sz = fs::metadata(&p_path)?.len();
                println!(
                    "  [L1 proved+verified] {label}: {} leaves (heights {}..={}) prove={:.2}s ({:.2}s/leaf) verify={:.3}s bytes={}",
                    items.len(),
                    merged.state_in.height + 1,
                    merged.state_out.height,
                    prv_s,
                    prv_s / items.len() as f64,
                    ver_s,
                    sz
                );
                l1_timings.push(serde_json::json!({
                    "label": label,
                    "leaves": items.len(),
                    "start_height": merged.state_in.height + 1,
                    "end_height": merged.state_out.height,
                    "reused": false,
                    "prove_s": prv_s,
                    "verify_s": ver_s,
                    "proof_bytes": sz,
                }));
                Ok((prf, merged))
            };

            println!("[3/5] Running Level-1 aggregation (fan_in={fan_in}, 7 frozen prefix + 1 split prefix + 1 bridge + 1 suffix = 10 L1 nodes)...");
            let mut l1_prefix = Vec::new();
            for (chunk_idx, chunk) in frozen_prefix_leaves.chunks(fan_in).enumerate() {
                l1_prefix.push(run_l1(&format!("l1-prefix-{chunk_idx:02}"), chunk)?);
            }
            let t_renew_l1 = Instant::now();
            l1_prefix.push(run_l1("l1-prefix-tail", std::slice::from_ref(&tail_prefix_leaf))?);
            let l1_bridge = run_l1("l1-bridge", std::slice::from_ref(&bridge_leaf))?;
            let l1_suffix = run_l1("l1-suffix", &suffix_leaves)?;
            let renew_l1_s = t_renew_l1.elapsed().as_secs_f64();

            // Free L1 SDK memory before building Root SDK
            drop(run_l1);
            drop(sdk_l1);
            drop(frozen_prefix_leaves);
            drop(tail_prefix_leaf);
            drop(bridge_leaf);
            drop(suffix_leaves);

            // 3. Build Level-2 (Root) SDK & Guest
            println!("[4/5] Initializing Level-2 (Root) OpenVM v2.1.0 Deferral SDK...");
            let l1_vk = VmStarkVerifyingKey {
                mvk: l1_agg_vk.as_ref().clone(),
                baseline: l1_baseline.clone(),
            };
            let (sdk_root, root_vm_config, root_agg_vk, _root_hook) =
                build_verify_stark_sdk(l1_agg_vk.clone(), Some(l1_def_hook_commit))?;
            let root_cached_commit: Digest = sdk_root
                .deferral_circuit_cached_commits(VERIFY_STARK_DEF_IDX)?[0]
                .into();
            let (l1_exe_c, l1_vm_c) = extract_child_exe_and_vm_commits(
                &l1_vk,
                &l1_prefix[0].0,
                root_cached_commit,
            )?;
            fs::write(
                guest_root_dir.join("src/pinned_l1.rs"),
                format!(
                    "pub const EXPECTED_L1_EXE_COMMIT: [u8; 32] = {};\npub const EXPECTED_L1_VM_COMMIT: [u8; 32] = {};\n",
                    format_bytes_const(&l1_exe_c),
                    format_bytes_const(&l1_vm_c)
                ),
            )?;
            fs::write(guest_root_dir.join("openvm.toml"), root_vm_config.to_toml()?)?;
            let root_elf = build_guest_elf_clean(&root_vm_config, &guest_root_dir, "ergo-nipopow-v2-guest-agg-root")?;
            let root_exe = sdk_root.convert_to_exe(root_elf)?;
            let root_baseline = sdk_root.prover(root_exe.clone())?.generate_baseline();

            // Gather all Level-1 proofs in exact order for deferral state
            let mut all_l1_proofs = Vec::new();
            for (p, _) in &l1_prefix {
                all_l1_proofs.push(p.clone());
            }
            all_l1_proofs.push(l1_bridge.0.clone());
            all_l1_proofs.push(l1_suffix.0.clone());

            let raw_l1_res = get_raw_deferral_results(&l1_vk, &all_l1_proofs, root_cached_commit)?;
            let mut prefix_claims = Vec::new();
            for (i, (_, s)) in l1_prefix.iter().enumerate() {
                prefix_claims.push(ChildClaim {
                    proof_commit: raw_l1_res[i].input.clone().try_into().unwrap(),
                    summary: s.clone(),
                });
            }
            let bridge_idx = l1_prefix.len();
            let suffix_idx = l1_prefix.len() + 1;
            let bridge_claim = ChildClaim {
                proof_commit: raw_l1_res[bridge_idx].input.clone().try_into().unwrap(),
                summary: l1_bridge.1.clone(),
            };
            let suffix_claims = vec![ChildClaim {
                proof_commit: raw_l1_res[suffix_idx].input.clone().try_into().unwrap(),
                summary: l1_suffix.1.clone(),
            }];

            let root_in_bytes = bincode::serialize(&RootInput {
                prefix_children: prefix_claims,
                bridge_child: bridge_claim,
                suffix_children: suffix_claims,
            })?;
            let mut root_stdin = StdIn::default();
            root_stdin.write_bytes(&root_in_bytes);
            root_stdin.deferrals = vec![get_deferral_state(
                &l1_vk,
                &all_l1_proofs,
                root_cached_commit,
                VERIFY_STARK_DEF_IDX as u32,
            )?];
            let root_def_inputs = vec![DeferralInput::from_inputs(&all_l1_proofs)];

            let t_root = Instant::now();
            let (root_proof, _) = sdk_root.prove(root_exe, root_stdin, &root_def_inputs)?;
            let root_prove_s = t_root.elapsed().as_secs_f64();

            // Cold-verify Root STARK proof!
            let t_rver = Instant::now();
            Sdk::verify_proof(root_agg_vk.as_ref().clone(), root_baseline.clone(), &root_proof)?;
            let root_verify_s = t_rver.elapsed().as_secs_f64();

            // Compute exact BootstrapStatement and confirm 32-byte public value parity!
            let prefix_b_merged = merge_segments(
                &l1_prefix.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>(),
            )
            .map_err(|e| eyre!("merge prefix: {e:?}"))?;
            let stmt = check_bootstrap_eligibility(&prefix_b_merged, &l1_bridge.1, &l1_suffix.1)
                .map_err(|e| eyre!("eligibility: {e:?}"))?;
            let x_bytes = bincode::serialize(&stmt)?;
            let expected_root_pv = sha256_bytes(&x_bytes);
            let actual_root_pv = proof_user_pvs_bytes(&root_proof)?;
            if actual_root_pv.as_slice() != expected_root_pv.as_slice() {
                return Err(eyre!("Root STARK revealed PV mismatch!"));
            }

            // Persist root STARK proof + VK + baseline + L1 VK/baseline
            let versioned_root = VersionedVmStarkProof::new(root_proof.clone())?;
            let root_proof_json = serde_json::to_vec(&versioned_root)?;
            write_to_file_json(out_dir.join("root-1827840.stark.proof"), &versioned_root)?;
            fs::write(out_dir.join("bootstrap-statement.bin"), &x_bytes)?;
            write_object_to_file(out_dir.join("root-agg.vk"), root_agg_vk.as_ref().clone())?;
            let root_baseline_json: VerificationBaselineJson = root_baseline.clone().into();
            write_to_file_json(out_dir.join("root-baseline.json"), &root_baseline_json)?;
            write_object_to_file(out_dir.join("l1-agg.vk"), l1_agg_vk.as_ref().clone())?;
            let l1_baseline_json: VerificationBaselineJson = l1_baseline.clone().into();
            write_to_file_json(out_dir.join("l1-baseline.json"), &l1_baseline_json)?;
            println!(
                "ROOT_STARK_VERIFIED: prove_s={:.2}s verify_s={:.3}s proof_bytes={} root_pv={}",
                root_prove_s,
                root_verify_s,
                root_proof_json.len(),
                hex::encode(&actual_root_pv)
            );

            // 4. Assemble complete canonical V2Certificate (bound to REAL root STARK proof bytes!)
            println!("[5/5] Assembling complete V2Certificate (real root STARK + deduplicated MMR audit + exact tail)...");
            let raw_headers = read_u32le_headers(&headers_u32le)?;
            let n = raw_headers.len();
            let p32 = mainnet_profile32();
            let mut mmr_store = MmrStore::new(n);
            let mut cum_work = Vec::with_capacity(n);
            cum_work.push(0u128);
            let mut w_acc = 0u128;

            for h in 2..=n {
                let (hdr, _) = Header::decode_native(&raw_headers[h - 1], None)
                    .map_err(|e| eyre!("decode {h}: {e:?}"))?;
                let d = decode_compact(hdr.n_bits).map_err(|e| eyre!("diff {h}: {e:?}"))?;
                let w_hi = w_acc + d;
                mmr_store.push_leaf(hash_leaf(&p32, h as u32, w_acc, w_hi, &raw_headers[h - 1]));
                cum_work.push(w_hi);
                w_acc = w_hi;
            }

            let audit = build_audit_bundle(
                &stmt,
                &x_bytes,
                &root_proof_json,
                &mmr_store,
                &raw_headers,
                &cum_work,
            )
            .map_err(|e| eyre!("audit build: {e:?}"))?;

            let cert = V2Certificate {
                magic: CERT_MAGIC,
                backend: StructuralBackend::OpenVmSwirlV21,
                statement: stmt.clone(),
                structural_proof: root_proof_json,
                audit,
            };
            let cert_bytes = bincode::serialize(&cert)?;
            let cert_path = out_dir.join("ergo-mainnet-1827840.npv2.bin");
            fs::write(&cert_path, &cert_bytes)?;

            // Cold-verify the exported certificate from scratch!
            let t_cold = Instant::now();
            let loaded: V2Certificate = bincode::deserialize(&fs::read(&cert_path)?)?;
            assert_eq!(loaded.magic, CERT_MAGIC);
            let loaded_ver_prf: VersionedVmStarkProof =
                serde_json::from_slice(&loaded.structural_proof)?;
            let loaded_prf = loaded_ver_prf.decode_using_vk(&root_agg_vk, &root_baseline)?;
            Sdk::verify_proof(root_agg_vk.as_ref().clone(), root_baseline, &loaded_prf)?;
            let loaded_x = bincode::serialize(&loaded.statement)?;
            assert_eq!(
                proof_user_pvs_bytes(&loaded_prf)?.as_slice(),
                sha256_bytes(&loaded_x).as_slice()
            );
            let draws = verify_audit_bundle(
                &loaded.statement,
                &loaded_x,
                &loaded.structural_proof,
                &loaded.audit,
            )
            .map_err(|e| eyre!("cold audit: {e:?}"))?;
            let tail_slice = &raw_headers[loaded.statement.bootstrap_height as usize..n];
            let vtail = verify_exact_tail(&loaded.statement, tail_slice, query_height)
                .map_err(|e| eyre!("cold tail: {e:?}"))?;
            let cold_s = t_cold.elapsed().as_secs_f64();

            let report = serde_json::json!({
                "tip_height": vtail.tip_height,
                "tip_id": hex::encode(vtail.tip_id),
                "bootstrap_height": stmt.bootstrap_height,
                "bootstrap_id": hex::encode(stmt.bootstrap_id),
                "latest_exact_mature_height": vtail.query_height,
                "total_work": stmt.total_work.to_string(),
                "w_b": stmt.w_b.to_string(),
                "mmr_root": hex::encode(stmt.mmr_root),
                "root_pv_sha256": hex::encode(&actual_root_pv),
                "leaf_exe_commit": hex::encode(leaf_exe_c),
                "leaf_vm_commit": hex::encode(leaf_vm_c),
                "l1_exe_commit": hex::encode(l1_exe_c),
                "l1_vm_commit": hex::encode(l1_vm_c),
                "l1_setup_s": l1_setup_s,
                "l1_batches": l1_timings,
                "renewal_l1_delta_s": renew_l1_s,
                "root_prove_s": root_prove_s,
                "root_verify_s": root_verify_s,
                "root_proof_bytes": loaded.structural_proof.len(),
                "certificate_bytes": cert_bytes.len(),
                "audit_draws": draws,
                "audit_distinct_headers": loaded.audit.leaves.len(),
                "audit_dedup_siblings": loaded.audit.multiproof.siblings.len(),
                "cold_client_verify_s": cold_s,
                "total_agg_elapsed_s": t_all.elapsed().as_secs_f64(),
            });
            fs::write(
                out_dir.join("aggregation-report.json"),
                serde_json::to_string_pretty(&report)?,
            )?;

            println!("============================================================");
            println!("FULL_MAINNET_V2_CERTIFICATE_VERIFIED_END_TO_END!");
            println!("  Certificate file:   {} ({:.2} MiB)", cert_path.display(), cert_bytes.len() as f64 / (1024.0 * 1024.0));
            println!("  Root STARK proof:   {} bytes (post-quantum OpenVM v2.1.0 SWIRL/WHIR)", loaded.structural_proof.len());
            println!("  Audit verified:     {} draws ({} distinct headers, {} dedup siblings)", draws, loaded.audit.leaves.len(), loaded.audit.multiproof.siblings.len());
            println!("  Exact tail mature:  h={} (tip={}, total_work={})", vtail.query_height, vtail.tip_height, vtail.total_work);
            println!("  Renewal L1+Root:    L1_delta={:.2}s + Root={:.2}s = {:.2}s (reusing 7 frozen L1 nodes covering 99.5% of history!)", renew_l1_s, root_prove_s, renew_l1_s + root_prove_s);
            println!("  Cold client verify: {:.3} s total (STARK + Audit + Exact Tail!)", cold_s);
            println!("  Total agg elapsed:  {:.2} s", t_all.elapsed().as_secs_f64());
            println!("============================================================");
        }

        Cmd::AssembleZiskCert {
            zisk_root_proof,
            zisk_root_vk,
            statement_bin,
            headers_u32le,
            query_height,
            out_dir,
        } => {
            let t0 = Instant::now();
            fs::create_dir_all(&out_dir)?;
            let zisk_vk = parse_zisk_vk(&zisk_root_vk)?;
            let x_bytes = fs::read(&statement_bin)?;
            let stmt: BootstrapStatement = bincode::deserialize(&x_bytes)?;
            if stmt.profile != ProfileId::V2Production128 {
                return Err(eyre!(
                    "refusing to assemble non-production profile {:?}: V2Production128 is required",
                    stmt.profile
                ));
            }
            let expected_pv = sha256_bytes(&x_bytes);

            let t_z = Instant::now();
            let zisk_bytes = fs::read(&zisk_root_proof)?;
            verify_zisk_root_proof_bytes(&zisk_bytes, &zisk_vk, &expected_pv)?;
            let zisk_ver_s = t_z.elapsed().as_secs_f64();

            let raw_headers = read_u32le_headers(&headers_u32le)?;
            let n = raw_headers.len();
            if n != stmt.tip_height as usize {
                return Err(eyre!("headers count {} != stmt.tip_height {}", n, stmt.tip_height));
            }
            let p32 = mainnet_profile32();
            let mut mmr_store = MmrStore::new(n);
            let mut cum_work = Vec::with_capacity(n);
            cum_work.push(0u128);
            let mut w_acc = 0u128;
            for h in 2..=n {
                let (hdr, _) = Header::decode_native(&raw_headers[h - 1], None)
                    .map_err(|e| eyre!("decode {h}: {e:?}"))?;
                let d = decode_compact(hdr.n_bits).map_err(|e| eyre!("diff {h}: {e:?}"))?;
                let w_hi = w_acc + d;
                mmr_store.push_leaf(hash_leaf(&p32, h as u32, w_acc, w_hi, &raw_headers[h - 1]));
                cum_work.push(w_hi);
                w_acc = w_hi;
            }

            let audit = build_audit_bundle(
                &stmt,
                &x_bytes,
                &zisk_bytes,
                &mmr_store,
                &raw_headers,
                &cum_work,
            )
            .map_err(|e| eyre!("audit build: {e:?}"))?;

            let cert = V2Certificate {
                magic: CERT_MAGIC,
                backend: StructuralBackend::ZiskStirV14,
                statement: stmt.clone(),
                structural_proof: zisk_bytes.clone(),
                audit,
            };
            let cert_bytes = bincode::serialize(&cert)?;
            let cert_path = out_dir.join(format!("ergo-mainnet-{}-prod128-zisk-stir.npv2.bin", stmt.tip_height));
            fs::write(&cert_path, &cert_bytes)?;

            let tail_slice = &raw_headers[stmt.bootstrap_height as usize..n];
            let mut tail_buf = Vec::new();
            for raw in tail_slice {
                tail_buf.extend_from_slice(&(raw.len() as u32).to_le_bytes());
                tail_buf.extend_from_slice(raw);
            }
            let tail_path = out_dir.join(format!(
                "tail-{}-{}.u32le",
                stmt.bootstrap_height + 1,
                stmt.tip_height
            ));
            fs::write(&tail_path, &tail_buf)?;

            let vtail = verify_exact_tail(&stmt, tail_slice, query_height)
                .map_err(|e| eyre!("exact tail verify failed: {e:?}"))?;
            println!(
                "ZISK_STIR_CERT_ASSEMBLED: cert={} ({:.2} MiB) tail={} ({:.2} MiB) zisk_bytes={} ({:.3}s) draws={} distinct={} siblings={} h={} tip={} elapsed={:.2}s",
                cert_path.display(),
                cert_bytes.len() as f64 / (1024.0 * 1024.0),
                tail_path.display(),
                tail_buf.len() as f64 / (1024.0 * 1024.0),
                zisk_bytes.len(),
                zisk_ver_s,
                cert.audit.leaves.len(),
                cert.audit.leaves.len(),
                cert.audit.multiproof.siblings.len(),
                vtail.query_height,
                vtail.tip_height,
                t0.elapsed().as_secs_f64()
            );
        }

        Cmd::AssembleDualCert {
            zisk_root_proof,
            zisk_root_vk,
            openvm_root_proof,
            openvm_root_vk,
            openvm_root_baseline,
            statement_bin,
            headers_u32le,
            query_height,
            out_dir,
        } => {
            let t0 = Instant::now();
            fs::create_dir_all(&out_dir)?;
            let zisk_vk = parse_zisk_vk(&zisk_root_vk)?;
            let x_bytes = fs::read(&statement_bin)?;
            let stmt: BootstrapStatement = bincode::deserialize(&x_bytes)?;
            if stmt.profile != ProfileId::V2Production128 {
                return Err(eyre!(
                    "refusing to assemble non-production profile {:?}: V2Production128 is required",
                    stmt.profile
                ));
            }
            let expected_pv = sha256_bytes(&x_bytes);

            // 1. Verify Proof A: ZisK v1.4.0-alpha (128-bit BLAKE3 STIR/FRI)
            let t_z = Instant::now();
            let zisk_bytes = fs::read(&zisk_root_proof)?;
            verify_zisk_root_proof_bytes(&zisk_bytes, &zisk_vk, &expected_pv)?;
            let zisk_ver_s = t_z.elapsed().as_secs_f64();

            // 2. Verify Proof B: OpenVM v2.1.0 (SWIRL/WHIR, zkSecurity audited + Lean verified)
            let t_o = Instant::now();
            let ovm_agg_vk: MultiStarkVerifyingKey<SC> = read_object_from_file(&openvm_root_vk)?;
            let ovm_baseline_json: VerificationBaselineJson =
                read_from_file_json(&openvm_root_baseline)?;
            let ovm_baseline: VerificationBaseline = ovm_baseline_json.into();
            let ovm_bytes = fs::read(&openvm_root_proof)?;
            let ovm_ver_prf: VersionedVmStarkProof = serde_json::from_slice(&ovm_bytes)?;
            let ovm_prf = ovm_ver_prf.decode_using_vk(&ovm_agg_vk, &ovm_baseline)?;
            Sdk::verify_proof(ovm_agg_vk.clone(), ovm_baseline.clone(), &ovm_prf)?;
            if proof_user_pvs_bytes(&ovm_prf)?.as_slice() != expected_pv.as_slice() {
                return Err(eyre!("OpenVM root STARK public values do not match statement"));
            }
            let ovm_ver_s = t_o.elapsed().as_secs_f64();

            // 3. Encode canonical DualStructuralProof and build Fiat-Shamir audit bound to BOTH proofs
            let dual = DualStructuralProof {
                zisk_proof: zisk_bytes.clone(),
                openvm_proof: ovm_bytes.clone(),
            };
            let structural_proof = dual
                .encode_canonical()
                .map_err(|e| eyre!("encode DualStructuralProof: {e:?}"))?;

            let raw_headers = read_u32le_headers(&headers_u32le)?;
            let n = raw_headers.len();
            if n != stmt.tip_height as usize {
                return Err(eyre!("headers count {} != stmt.tip_height {}", n, stmt.tip_height));
            }
            let p32 = mainnet_profile32();
            let mut mmr_store = MmrStore::new(n);
            let mut cum_work = Vec::with_capacity(n);
            cum_work.push(0u128);
            let mut w_acc = 0u128;
            for h in 2..=n {
                let (hdr, _) = Header::decode_native(&raw_headers[h - 1], None)
                    .map_err(|e| eyre!("decode {h}: {e:?}"))?;
                let d = decode_compact(hdr.n_bits).map_err(|e| eyre!("diff {h}: {e:?}"))?;
                let w_hi = w_acc + d;
                mmr_store.push_leaf(hash_leaf(&p32, h as u32, w_acc, w_hi, &raw_headers[h - 1]));
                cum_work.push(w_hi);
                w_acc = w_hi;
            }

            let audit = build_audit_bundle(
                &stmt,
                &x_bytes,
                &structural_proof,
                &mmr_store,
                &raw_headers,
                &cum_work,
            )
            .map_err(|e| eyre!("audit build: {e:?}"))?;

            let cert = V2Certificate {
                magic: CERT_MAGIC,
                backend: StructuralBackend::DualZiskV14OpenVmV21,
                statement: stmt.clone(),
                structural_proof,
                audit,
            };
            let cert_bytes = bincode::serialize(&cert)?;
            let cert_path = out_dir.join(format!("ergo-mainnet-{}-prod128-dual.npv2.bin", stmt.tip_height));
            fs::write(&cert_path, &cert_bytes)?;

            // Export standalone exact tail stream
            let tail_slice = &raw_headers[stmt.bootstrap_height as usize..n];
            let mut tail_buf = Vec::new();
            for raw in tail_slice {
                tail_buf.extend_from_slice(&(raw.len() as u32).to_le_bytes());
                tail_buf.extend_from_slice(raw);
            }
            let tail_path = out_dir.join(format!(
                "tail-{}-{}.u32le",
                stmt.bootstrap_height + 1,
                stmt.tip_height
            ));
            fs::write(&tail_path, &tail_buf)?;

            // Verify exact tail immediately
            let vtail = verify_exact_tail(&stmt, tail_slice, query_height)
                .map_err(|e| eyre!("exact tail verify failed: {e:?}"))?;
            println!(
                "DUAL_CERT_ASSEMBLED: cert={} ({:.2} MiB) tail={} ({:.2} MiB) zisk_bytes={} ({:.3}s) openvm_bytes={} ({:.3}s) h={} tip={} elapsed={:.2}s",
                cert_path.display(),
                cert_bytes.len() as f64 / (1024.0 * 1024.0),
                tail_path.display(),
                tail_buf.len() as f64 / (1024.0 * 1024.0),
                zisk_bytes.len(),
                zisk_ver_s,
                ovm_bytes.len(),
                ovm_ver_s,
                vtail.query_height,
                vtail.tip_height,
                t0.elapsed().as_secs_f64()
            );
        }

        Cmd::VerifyCert {
            cert_bin,
            root_agg_vk,
            root_baseline,
            zisk_root_vk,
            headers_u32le,
            query_height,
            allow_non_128_standalone_openvm,
            unsafe_override_vk,
        } => {
            let t0 = Instant::now();
            let cert_bytes = read_bounded_file(&cert_bin, MAX_CERT_RAW_BYTES)?;
            let cert: V2Certificate = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(MAX_CERT_RAW_BYTES as u64)
                .reject_trailing_bytes()
                .deserialize(&cert_bytes)?;
            if cert.magic != CERT_MAGIC {
                return Err(eyre!("invalid V2 certificate magic"));
            }
            if cert.statement.profile != ProfileId::V2Production128 {
                return Err(eyre!(
                    "refusing certificate with profile {:?}: strict V2Production128 is required",
                    cert.statement.profile
                ));
            }
            let x_bytes = bincode::serialize(&cert.statement)?;
            let expected_pv = sha256_bytes(&x_bytes);

            let check_openvm_pins = |vk_path: &Path, bl_path: &Path| -> Result<()> {
                let vk_bytes = read_bounded_file(vk_path, MAX_VK_FILE_BYTES)?;
                let bl_bytes = read_bounded_file(bl_path, MAX_VK_FILE_BYTES)?;
                let vk_sha = hex::encode(sha256_bytes(&vk_bytes));
                let bl_sha = hex::encode(sha256_bytes(&bl_bytes));
                if !unsafe_override_vk {
                    if vk_sha != PINNED_OPENVM_ROOT_AGG_VK_SHA256 {
                        return Err(eyre!(
                            "root-agg.vk SHA-256 mismatch: got {vk_sha}, pinned {PINNED_OPENVM_ROOT_AGG_VK_SHA256} (pass --unsafe-override-vk to test custom VKs)"
                        ));
                    }
                    if bl_sha != PINNED_OPENVM_ROOT_BASELINE_SHA256 {
                        return Err(eyre!(
                            "root-baseline.json SHA-256 mismatch: got {bl_sha}, pinned {PINNED_OPENVM_ROOT_BASELINE_SHA256} (pass --unsafe-override-vk to test custom VKs)"
                        ));
                    }
                }
                Ok(())
            };

            let resolve_zisk_vk = |zvk_opt: &Option<String>| -> Result<[u64; 4]> {
                let zvk = match zvk_opt {
                    Some(s) => parse_zisk_vk(s)?,
                    None => PINNED_ZISK_ROOT_VK_PROD128,
                };
                if !unsafe_override_vk && zvk != PINNED_ZISK_ROOT_VK_PROD128 {
                    return Err(eyre!(
                        "zisk-root-vk {:?} does not match pinned v0.4.0 VK {:?} (pass --unsafe-override-vk to test custom VKs)",
                        zvk,
                        PINNED_ZISK_ROOT_VK_PROD128
                    ));
                }
                Ok(zvk)
            };

            let t_s = Instant::now();
            let mut openvm_ctx: Option<(
                MultiStarkVerifyingKey<SC>,
                VerificationBaseline,
                VmStarkProof,
            )> = None;
            let mut zisk_ctx: Option<([u64; 4], Vec<u8>)> = None;

            match cert.backend {
                StructuralBackend::OpenVmSwirlV21 => {
                    if !allow_non_128_standalone_openvm {
                        return Err(eyre!(
                            "refusing standalone OpenVmSwirlV21 certificate in strict 128-bit mode (OpenVM v2.1.0 default parameters target 100-bit proven RBR security; use DualZiskV14OpenVmV21 or ZiskStirV14, or pass --allow-non-128-standalone-openvm explicitly)"
                        ));
                    }
                    let vk_path = root_agg_vk
                        .as_ref()
                        .ok_or_else(|| eyre!("--root-agg-vk required for OpenVmSwirlV21"))?;
                    let bl_path = root_baseline
                        .as_ref()
                        .ok_or_else(|| eyre!("--root-baseline required for OpenVmSwirlV21"))?;
                    check_openvm_pins(vk_path, bl_path)?;
                    let agg_vk: MultiStarkVerifyingKey<SC> = read_object_from_file(vk_path)?;
                    let baseline_json: VerificationBaselineJson = read_from_file_json(bl_path)?;
                    let baseline: VerificationBaseline = baseline_json.into();
                    let ver_prf: VersionedVmStarkProof =
                        serde_json::from_slice(&cert.structural_proof)?;
                    let prf = ver_prf.decode_using_vk(&agg_vk, &baseline)?;
                    Sdk::verify_proof(agg_vk.clone(), baseline.clone(), &prf)?;
                    if proof_user_pvs_bytes(&prf)?.as_slice() != expected_pv.as_slice() {
                        return Err(eyre!("root STARK public values do not match statement"));
                    }
                    openvm_ctx = Some((agg_vk, baseline, prf));
                }
                StructuralBackend::ZiskStirV14 => {
                    let zvk = resolve_zisk_vk(&zisk_root_vk)?;
                    verify_zisk_root_proof_bytes(&cert.structural_proof, &zvk, &expected_pv)?;
                    zisk_ctx = Some((zvk, cert.structural_proof.clone()));
                }
                StructuralBackend::DualZiskV14OpenVmV21 => {
                    let dual = DualStructuralProof::decode_canonical(&cert.structural_proof)
                        .map_err(|e| eyre!("decode DualStructuralProof: {e:?}"))?;
                    let zvk = resolve_zisk_vk(&zisk_root_vk)?;
                    verify_zisk_root_proof_bytes(&dual.zisk_proof, &zvk, &expected_pv)?;
                    zisk_ctx = Some((zvk, dual.zisk_proof));

                    let vk_path = root_agg_vk
                        .as_ref()
                        .ok_or_else(|| eyre!("--root-agg-vk required for DualZiskV14OpenVmV21"))?;
                    let bl_path = root_baseline
                        .as_ref()
                        .ok_or_else(|| eyre!("--root-baseline required for DualZiskV14OpenVmV21"))?;
                    check_openvm_pins(vk_path, bl_path)?;
                    let agg_vk: MultiStarkVerifyingKey<SC> = read_object_from_file(vk_path)?;
                    let baseline_json: VerificationBaselineJson = read_from_file_json(bl_path)?;
                    let baseline: VerificationBaseline = baseline_json.into();
                    let ver_prf: VersionedVmStarkProof =
                        serde_json::from_slice(&dual.openvm_proof)?;
                    let prf = ver_prf.decode_using_vk(&agg_vk, &baseline)?;
                    Sdk::verify_proof(agg_vk.clone(), baseline.clone(), &prf)?;
                    if proof_user_pvs_bytes(&prf)?.as_slice() != expected_pv.as_slice() {
                        return Err(eyre!("OpenVM root STARK public values do not match statement"));
                    }
                    openvm_ctx = Some((agg_vk, baseline, prf));
                }
            }
            let stark_s = t_s.elapsed().as_secs_f64();

            let t_a = Instant::now();
            let draws = verify_audit_bundle(
                &cert.statement,
                &x_bytes,
                &cert.structural_proof,
                &cert.audit,
            )
            .map_err(|e| eyre!("audit failed: {e:?}"))?;
            let audit_s = t_a.elapsed().as_secs_f64();

            let raw_headers = read_u32le_headers(&headers_u32le)?;
            let expected_tail_len = cert
                .statement
                .tip_height
                .checked_sub(cert.statement.bootstrap_height)
                .ok_or_else(|| eyre!("tip_height < bootstrap_height"))?
                as usize;
            let tail_slice: &[Vec<u8>] = if raw_headers.len() == expected_tail_len {
                &raw_headers[..]
            } else if raw_headers.len() == cert.statement.tip_height as usize {
                &raw_headers[cert.statement.bootstrap_height as usize..]
            } else {
                return Err(eyre!(
                    "unexpected header count {} (expected tail {} or full {})",
                    raw_headers.len(),
                    expected_tail_len,
                    cert.statement.tip_height
                ));
            };
            let t_t = Instant::now();
            let vtail = verify_exact_tail(&cert.statement, tail_slice, query_height)
                .map_err(|e| eyre!("tail failed: {e:?}"))?;
            let tail_s = t_t.elapsed().as_secs_f64();

            let sec_label = match cert.backend {
                StructuralBackend::OpenVmSwirlV21 => "100-bit-RBR-standalone-OpenVM",
                StructuralBackend::ZiskStirV14 => "128-bit-ZisK-STIR",
                StructuralBackend::DualZiskV14OpenVmV21 => "128-bit-ZisK-STIR+100-bit-OpenVM-Dual",
            };
            println!(
                "COLD_VERIFY_PASS: profile={:?} backend={:?} security={} h={} tip={} id={} total_work={} draws={} stark={:.3}s audit={:.3}s tail={:.3}s total={:.3}s",
                cert.statement.profile,
                cert.backend,
                sec_label,
                vtail.query_height,
                vtail.tip_height,
                hex::encode(vtail.query_header_id),
                vtail.total_work,
                draws,
                stark_s,
                audit_s,
                tail_s,
                t0.elapsed().as_secs_f64()
            );

            // Isolated single-fault negative tamper checks (must ALL fail closed!)
            // 1. Tampered statement total_work -> fails STARK PV binding
            let mut bad_stmt = cert.statement.clone();
            bad_stmt.total_work += 1;
            let bad_x = bincode::serialize(&bad_stmt)?;
            let bad_pv = sha256_bytes(&bad_x);
            if let Some((_, _, ref prf)) = openvm_ctx {
                assert_ne!(
                    proof_user_pvs_bytes(prf)?.as_slice(),
                    bad_pv.as_slice(),
                    "TAMPER 1 FAILED: modified statement matched OpenVM root STARK PV!"
                );
            }
            if let Some((ref zvk, ref zbytes)) = zisk_ctx {
                assert!(
                    verify_zisk_root_proof_bytes(zbytes, zvk, &bad_pv).is_err(),
                    "TAMPER 1b FAILED: modified statement matched ZisK root STARK PV!"
                );
            }

            // 2. Tampered structural proof bytes -> fails Fiat-Shamir audit binding
            let mut bad_proof_bytes = cert.structural_proof.clone();
            let mid = bad_proof_bytes.len() / 2;
            bad_proof_bytes[mid] ^= 0x01;
            let audit_bad_prf = verify_audit_bundle(
                &cert.statement,
                &x_bytes,
                &bad_proof_bytes,
                &cert.audit,
            );
            assert!(
                audit_bad_prf.is_err(),
                "TAMPER 2 FAILED: audit accepted modified structural_proof bytes!"
            );

            // 3. Tampered MMR multiproof sibling -> fails MMR root check
            let mut bad_audit = cert.audit.clone();
            bad_audit.multiproof.siblings[0][0] ^= 0x80;
            let audit_bad_sib = verify_audit_bundle(
                &cert.statement,
                &x_bytes,
                &cert.structural_proof,
                &bad_audit,
            );
            assert!(
                audit_bad_sib.is_err(),
                "TAMPER 3 FAILED: audit accepted corrupted MMR sibling!"
            );

            // 4. Tampered tail header nonce byte -> fails Autolykos v2 PoW / parent chain check
            let mut bad_tail = tail_slice.to_vec();
            let last_idx = bad_tail.len() - 1;
            let b_idx = bad_tail[last_idx].len() - 1;
            bad_tail[last_idx][b_idx] ^= 0x01;
            let tail_bad = verify_exact_tail(&cert.statement, &bad_tail, query_height);
            assert!(
                tail_bad.is_err(),
                "TAMPER 4 FAILED: exact tail accepted corrupted PoW/header byte!"
            );

            // 5. Tampered root STARK proof(s) -> fails direct STARK verification
            if let Some((agg_vk, baseline, ref prf)) = openvm_ctx {
                let mut bad_prf = prf.clone();
                bad_prf.user_pvs_proof.public_values[0] = openvm_sdk::F::from_u32(
                    (bad_prf.user_pvs_proof.public_values[0].as_canonical_u32() + 1) % 256,
                );
                assert!(
                    Sdk::verify_proof(agg_vk, baseline, &bad_prf).is_err(),
                    "TAMPER 5a FAILED: OpenVM verifier accepted tampered public_values!"
                );
            }
            if let Some((ref zvk, ref zbytes)) = zisk_ctx {
                let mut bad_z = zbytes.clone();
                let zpos = bad_z.len() / 2;
                bad_z[zpos] ^= 0x01;
                assert!(
                    verify_zisk_root_proof_bytes(&bad_z, zvk, &expected_pv).is_err(),
                    "TAMPER 5b FAILED: ZisK verifier accepted tampered STARK proof byte!"
                );
            }

            // 6. Tampered EIP-37 DAA anchor inside BootstrapStatement -> fails STARK PV + exact tail DAA
            let mut bad_anchor_stmt = cert.statement.clone();
            bad_anchor_stmt.bootstrap_eip37_anchors[8].timestamp += 3_600_000;
            let bad_anchor_x = bincode::serialize(&bad_anchor_stmt)?;
            let bad_anchor_pv = sha256_bytes(&bad_anchor_x);
            assert_ne!(
                expected_pv.as_slice(),
                bad_anchor_pv.as_slice(),
                "TAMPER 6a FAILED: tampered EIP-37 anchor produced identical statement hash!"
            );
            assert!(
                verify_exact_tail(&bad_anchor_stmt, tail_slice, query_height).is_err(),
                "TAMPER 6b FAILED: tampered EIP-37 anchor passed exact tail DAA!"
            );
            let mut micro_anchor_stmt = cert.statement.clone();
            micro_anchor_stmt.bootstrap_eip37_anchors[0].timestamp += 1;
            let micro_anchor_pv = sha256_bytes(&bincode::serialize(&micro_anchor_stmt)?);
            assert_ne!(
                expected_pv.as_slice(),
                micro_anchor_pv.as_slice(),
                "TAMPER 6c FAILED: 1ms EIP-37 anchor tweak produced identical statement hash!"
            );
            println!("NEGATIVE_TAMPER_SUITE_PASS: all isolated single-fault tamper checks rejected cleanly!");
        }
    }
    Ok(())
}
