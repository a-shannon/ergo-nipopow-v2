//! The exact tail must end at the tip the certified statement commits to.
//!
//! Needs the v0.2.0 release assets (not in the repository), so the test is ignored by default:
//!
//! ```text
//! NPV2_CERT_BIN=release-assets/ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin \
//! NPV2_TAIL_U32LE=release-assets/tail-1819645-1827840.u32le \
//! cargo test --release -p ergo-nipopow-v2-core --test tail_binds_statement -- --ignored --nocapture
//! ```
//!
//! Only the statement inside the certificate is used here; the structural proof and the audit
//! bundle are not verified by this test. The wrong statements are made by editing fields of the
//! genuine one; no second chain is constructed.

use ergo_nipopow_v2_core::certificate::{V2Certificate, CERT_MAGIC};
use ergo_nipopow_v2_core::tail::{verify_exact_tail, TailError};

const QUERY_HEIGHT: u32 = 1_823_986;

fn env_path(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} to the v0.2.0 release asset"))
}

fn read_u32le_headers(path: &str) -> Vec<Vec<u8>> {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        out.push(data[pos..pos + len].to_vec());
        pos += len;
    }
    out
}

#[test]
#[ignore = "needs the v0.4.0 release assets: NPV2_CERT_BIN and NPV2_TAIL_U32LE"]
fn exact_tail_must_end_at_the_statement_tip() {
    let cert_path = env_path("NPV2_CERT_BIN");
    let cert_bytes = std::fs::read(&cert_path).unwrap_or_else(|e| panic!("read {cert_path}: {e}"));
    let cert: V2Certificate = bincode::deserialize(&cert_bytes).expect("decode V2Certificate");
    assert_eq!(cert.magic, CERT_MAGIC);
    let stmt = cert.statement;
    let tail = read_u32le_headers(&env_path("NPV2_TAIL_U32LE"));
    assert_eq!(tail.len() as u32, stmt.tip_height - stmt.bootstrap_height);

    // The genuine pair verifies, and the tail ends exactly where the statement says.
    let good = verify_exact_tail(&stmt, &tail, QUERY_HEIGHT).expect("genuine statement and tail");
    println!(
        "genuine: tail tip_height={} total_work={} | statement tip_height={} total_work={}",
        good.tip_height, good.total_work, stmt.tip_height, stmt.total_work
    );
    assert_eq!(good.tip_height, stmt.tip_height);
    assert_eq!(good.tip_id, stmt.tip_id);
    assert_eq!(good.total_work, stmt.total_work);

    let mut wrong: Vec<&str> = Vec::new();

    // A statement committing to a different tip id must not accept this tail.
    let mut wrong_id = stmt.clone();
    wrong_id.tip_id[0] ^= 0x01;
    let r = verify_exact_tail(&wrong_id, &tail, QUERY_HEIGHT);
    println!("statement.tip_id changed       -> {}", outcome(&r));
    if r != Err(TailError::StatementTipMismatch) {
        wrong.push("statement with a different tip_id: expected StatementTipMismatch");
    }

    // A statement committing to a different total work must not accept this tail.
    let mut wrong_work = stmt.clone();
    wrong_work.total_work += 1;
    let r = verify_exact_tail(&wrong_work, &tail, QUERY_HEIGHT);
    println!("statement.total_work changed   -> {}", outcome(&r));
    if r != Err(TailError::StatementTipMismatch) {
        wrong.push("statement with a different total_work: expected StatementTipMismatch");
    }

    // A statement committing to a different tip height must not accept this tail.
    let mut wrong_height = stmt.clone();
    wrong_height.tip_height += 1;
    let r = verify_exact_tail(&wrong_height, &tail, QUERY_HEIGHT);
    println!("statement.tip_height changed   -> {}", outcome(&r));
    if r != Err(TailError::StatementTipMismatch) {
        wrong.push("statement with a different tip_height: expected StatementTipMismatch");
    }

    // A tail that stops one header short of the statement's tip must not be accepted. At
    // QUERY_HEIGHT the maturity guard already rejects it, so query the bootstrap height, where
    // the guard has room.
    let r = verify_exact_tail(&stmt, &tail[..tail.len() - 1], stmt.bootstrap_height);
    println!("tail one header short          -> {}", outcome(&r));
    if r != Err(TailError::StatementTipMismatch) {
        wrong.push("tail ending before the statement's tip: expected StatementTipMismatch");
    }

    assert!(wrong.is_empty(), "{wrong:#?}");
}

fn outcome(
    r: &Result<ergo_nipopow_v2_core::tail::VerifiedTail, ergo_nipopow_v2_core::tail::TailError>,
) -> String {
    match r {
        Ok(v) => format!("Ok(tip_height={}, total_work={})", v.tip_height, v.total_work),
        Err(e) => format!("Err({e:?})"),
    }
}
