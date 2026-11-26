//! Compile-time pinned child Level-1 aggregator program VK (ROM root of `ergo-nipopow-v2-zisk-agg-l1`).
//! Pinned from `cargo-zisk setup` on the release RV64IMA ELF
//! (Hash ID: 119cf8a54967013841d5478ecb8a0795063bb6eea138e5801461891db514e766).

pub const EXPECTED_L1_PROGRAM_VK: [u64; 4] = [
    5319951898812481023,
    12834882460020413992,
    8904808812702811473,
    9762453858803393301,
];
pub const EXPECT_COMPRESSED_L1: bool = false;
