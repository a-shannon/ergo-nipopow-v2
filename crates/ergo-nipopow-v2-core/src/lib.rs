#![cfg_attr(not(feature = "std"), no_std)]

//! Production incremental Ergo NiPoPoW V2 core library.
//!
//! Shared identically between:
//! - Standalone CPU light-client / node verifier (`ergo-nipopow-v2-cli`)
//! - Transparent post-quantum OpenVM v2.1.0 recursive STARK guests (`guest-leaf`, `guest-agg`)

extern crate alloc;

pub mod audit;
pub mod certificate;
pub mod daa;
pub mod header;
pub mod mmr;
pub mod monoid;
pub mod pow;
pub mod profile;
pub mod secp256k1;
pub mod segment;
#[cfg(feature = "std")]
pub mod state_proof;
pub mod tail;
