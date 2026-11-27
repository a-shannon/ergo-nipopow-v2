//! Consensus-exact Ergo transaction Merkle inclusion proof verification.
//!
//! Matches Ergo reference node `BlockTransactions.scala` and
//! `scorex.crypto.authds.merkle.MerkleProof` (BLAKE2b-256 with `0x00` leaf
//! prefix and `0x01` internal node prefix).

use alloc::vec::Vec;

use crate::header::blake2b256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateProofError {
    InvalidSideByte(u8),
    RootMismatch {
        computed: [u8; 32],
        expected: [u8; 32],
    },
    EmptyProof,
}

/// Scorex/Ergo Merkle membership proof for a transaction ID inside a block's
/// `transactionsRoot` Merkle tree.
///
/// Each level is `(sibling_digest, side)` matching Ergo node `/blocks/{id}/proofFor/{txId}`:
/// - `side == 0` (`Left`): current hash is the left child -> `BLAKE2b-256(0x01 || current || sibling)`
/// - `side == 1` (`Right`): current hash is the right child -> `BLAKE2b-256(0x01 || sibling || current)`
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErgoTxMerkleProof {
    pub leaf_data: [u8; 32],
    pub levels: Vec<([u8; 32], u8)>,
}

impl ErgoTxMerkleProof {
    pub fn compute_root(&self) -> Result<[u8; 32], StateProofError> {
        let mut leaf_buf = [0u8; 33];
        leaf_buf[0] = 0x00;
        leaf_buf[1..33].copy_from_slice(&self.leaf_data);
        let mut cur = blake2b256(&leaf_buf);

        let mut node_buf = [0u8; 65];
        node_buf[0] = 0x01;
        for &(sibling, side) in &self.levels {
            match side {
                0 => {
                    node_buf[1..33].copy_from_slice(&cur);
                    node_buf[33..65].copy_from_slice(&sibling);
                }
                1 => {
                    node_buf[1..33].copy_from_slice(&sibling);
                    node_buf[33..65].copy_from_slice(&cur);
                }
                other => return Err(StateProofError::InvalidSideByte(other)),
            }
            cur = blake2b256(&node_buf);
        }
        Ok(cur)
    }

    pub fn verify_against_header(
        &self,
        expected_transactions_root: &[u8; 32],
    ) -> Result<(), StateProofError> {
        if self.levels.is_empty() {
            return Err(StateProofError::EmptyProof);
        }
        let computed = self.compute_root()?;
        if &computed != expected_transactions_root {
            return Err(StateProofError::RootMismatch {
                computed,
                expected: *expected_transactions_root,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn real_mainnet_block_1823985_tx_merkle_proof_and_tamper_negatives() {
        // Real Ergo mainnet block 1,823,985 (cca7520d...3aa4) tx0 proof from Ergo node /proofFor
        let expected_tx_root =
            hex32("886512056798ab59bc60703fae73ce0c0a6e0c7d23b5f10210e4fcdc90985988");
        let proof = ErgoTxMerkleProof {
            leaf_data: hex32("c03f2bea96c4838e3c11cedee978a589b486716c5c42a780ccde8b44b830a98c"),
            levels: alloc::vec![
                (hex32("9f71a3d40a2810ab1677326ccd49f197b1421c97d58f08352de42a4b59a3b12d"), 0),
                (hex32("135223f5f09cbfa9518e7346fa7e6b40b56a6dc9a6fcb41c245f5a9633857cdd"), 0),
                (hex32("6cfe49a3abd3db5866a3beaef8d1ad664c6eb6edd2063ce71bded9436f56a128"), 0),
                (hex32("598802eaa51864e870ac1782d3f1be3e845188bdf181a3c5ca7181155029d4fb"), 0),
                (hex32("d6a37ee1b92a02a4b7130dabc76d2294621630bb285f3fbe3ea002d2a3bc59e5"), 0),
            ],
        };
        assert_eq!(proof.verify_against_header(&expected_tx_root), Ok(()));

        // 1-bit flip in txId -> fail closed
        let mut bad_leaf = proof.clone();
        bad_leaf.leaf_data[0] ^= 0x01;
        assert!(matches!(
            bad_leaf.verify_against_header(&expected_tx_root),
            Err(StateProofError::RootMismatch { .. })
        ));

        // 1-bit flip in sibling -> fail closed
        let mut bad_sib = proof.clone();
        bad_sib.levels[2].0[15] ^= 0x80;
        assert!(matches!(
            bad_sib.verify_against_header(&expected_tx_root),
            Err(StateProofError::RootMismatch { .. })
        ));

        // Invalid side byte -> fail closed
        let mut bad_side = proof.clone();
        bad_side.levels[0].1 = 2;
        assert_eq!(
            bad_side.verify_against_header(&expected_tx_root),
            Err(StateProofError::InvalidSideByte(2))
        );
    }
}
