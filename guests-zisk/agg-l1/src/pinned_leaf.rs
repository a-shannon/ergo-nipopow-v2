//! Compile-time pinned child leaf program VK (ROM root of `ergo-nipopow-v2-zisk-leaf`).
//! Pinned from `cargo-zisk setup` on the release RV64IMA ELF
//! (Hash ID: 356c591724cd06ff688944356da3d4beb6e5f2ab4812cf1076c46fc85f309230).

pub const EXPECTED_LEAF_PROGRAM_VK: [u64; 4] = [
    9110326089375293727,
    2656454419186733083,
    1581716303455200999,
    11820023294815474883,
];
pub const EXPECT_COMPRESSED_LEAF: bool = false;
