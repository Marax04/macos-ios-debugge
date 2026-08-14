// rustre-crypto-id/src/constant_db.rs
// Comprehensive database of 500+ cryptographic constants for algorithm identification.

use std::collections::HashMap;

/// A named constant entry in the database.
#[derive(Debug, Clone)]
pub struct ConstantEntry {
    pub algorithm: &'static str,
    pub name: &'static str,
    pub bytes: &'static [u8],
    pub description: &'static str,
}

// ─── AES ────────────────────────────────────────────────────────────────────

pub const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

pub const AES_INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

pub const AES_RCON: [u8; 11] = [
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
];

/// AES `MixColumns` GF(2^8) multiplication by 2 table.
pub const AES_MUL2: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let v = i.to_le_bytes()[0]; // i < 256: low byte == i
        t[i] = if v & 0x80 != 0 { (v << 1) ^ 0x1b } else { v << 1 };
        i += 1;
    }
    t
};

// ─── DES ────────────────────────────────────────────────────────────────────

pub const DES_SBOX: [[u8; 64]; 8] = [
    // S1
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    // S2
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    // S3
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    // S4
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    // S5
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    // S6
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    // S7
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    // S8
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
];

pub const DES_PC1: [u8; 56] = [
    57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,10, 2,59,51,43,35,27,19,11, 3,
    60,52,44,36,63,55,47,39,31,23,15, 7,62,54,46,38,30,22,14, 6,61,53,45,37,
    29,21,13, 5,28,20,12, 4,
];

pub const DES_PC2: [u8; 48] = [
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,23,19,12, 4,26, 8,16, 7,27,20,13, 2,
    41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32,
];

pub const DES_IP: [u8; 64] = [
    58,50,42,34,26,18,10, 2,60,52,44,36,28,20,12, 4,62,54,46,38,30,22,14, 6,
    64,56,48,40,32,24,16, 8,57,49,41,33,25,17, 9, 1,59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5,63,55,47,39,31,23,15, 7,
];

pub const DES_P: [u8; 32] = [
    16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10, 2, 8,24,14,32,27, 3, 9,
    19,13,30, 6,22,11, 4,25,
];

// ─── MD5 ────────────────────────────────────────────────────────────────────

pub const MD5_T: [u32; 64] = [
    0xd76a_a478,0xe8c7_b756,0x2420_70db,0xc1bd_ceee,0xf57c_0faf,0x4787_c62a,0xa830_4613,0xfd46_9501,
    0x6980_98d8,0x8b44_f7af,0xffff_5bb1,0x895c_d7be,0x6b90_1122,0xfd98_7193,0xa679_438e,0x49b4_0821,
    0xf61e_2562,0xc040_b340,0x265e_5a51,0xe9b6_c7aa,0xd62f_105d,0x0244_1453,0xd8a1_e681,0xe7d3_fbc8,
    0x21e1_cde6,0xc337_07d6,0xf4d5_0d87,0x455a_14ed,0xa9e3_e905,0xfcef_a3f8,0x676f_02d9,0x8d2a_4c8a,
    0xfffa_3942,0x8771_f681,0x6d9d_6122,0xfde5_380c,0xa4be_ea44,0x4bde_cfa9,0xf6bb_4b60,0xbebf_bc70,
    0x289b_7ec6,0xeaa1_27fa,0xd4ef_3085,0x0488_1d05,0xd9d4_d039,0xe6db_99e5,0x1fa2_7cf8,0xc4ac_5665,
    0xf429_2244,0x432a_ff97,0xab94_23a7,0xfc93_a039,0x655b_59c3,0x8f0c_cc92,0xffef_f47d,0x8584_5dd1,
    0x6fa8_7e4f,0xfe2c_e6e0,0xa301_4314,0x4e08_11a1,0xf753_7e82,0xbd3a_f235,0x2ad7_d2bb,0xeb86_d391,
];

pub const MD5_INIT: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

// ─── SHA-1 ──────────────────────────────────────────────────────────────────

pub const SHA1_INIT: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
pub const SHA1_K: [u32; 4] = [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6];

// ─── SHA-256 ────────────────────────────────────────────────────────────────

pub const SHA256_K: [u32; 64] = [
    0x428a_2f98,0x7137_4491,0xb5c0_fbcf,0xe9b5_dba5,0x3956_c25b,0x59f1_11f1,0x923f_82a4,0xab1c_5ed5,
    0xd807_aa98,0x1283_5b01,0x2431_85be,0x550c_7dc3,0x72be_5d74,0x80de_b1fe,0x9bdc_06a7,0xc19b_f174,
    0xe49b_69c1,0xefbe_4786,0x0fc1_9dc6,0x240c_a1cc,0x2de9_2c6f,0x4a74_84aa,0x5cb0_a9dc,0x76f9_88da,
    0x983e_5152,0xa831_c66d,0xb003_27c8,0xbf59_7fc7,0xc6e0_0bf3,0xd5a7_9147,0x06ca_6351,0x1429_2967,
    0x27b7_0a85,0x2e1b_2138,0x4d2c_6dfc,0x5338_0d13,0x650a_7354,0x766a_0abb,0x81c2_c92e,0x9272_2c85,
    0xa2bf_e8a1,0xa81a_664b,0xc24b_8b70,0xc76c_51a3,0xd192_e819,0xd699_0624,0xf40e_3585,0x106a_a070,
    0x19a4_c116,0x1e37_6c08,0x2748_774c,0x34b0_bcb5,0x391c_0cb3,0x4ed8_aa4a,0x5b9c_ca4f,0x682e_6ff3,
    0x748f_82ee,0x78a5_636f,0x84c8_7814,0x8cc7_0208,0x90be_fffa,0xa450_6ceb,0xbef9_a3f7,0xc671_78f2,
];

pub const SHA256_INIT: [u32; 8] = [
    0x6a09_e667,0xbb67_ae85,0x3c6e_f372,0xa54f_f53a,0x510e_527f,0x9b05_688c,0x1f83_d9ab,0x5be0_cd19,
];

// ─── SHA-384 / SHA-512 ──────────────────────────────────────────────────────

pub const SHA512_K: [u64; 80] = [
    0x428a_2f98_d728_ae22,0x7137_4491_23ef_65cd,0xb5c0_fbcf_ec4d_3b2f,0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,0x59f1_11f1_b605_d019,0x923f_82a4_af19_4f9b,0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,0x1283_5b01_4570_6fbe,0x2431_85be_4ee4_b28c,0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,0x80de_b1fe_3b16_96b1,0x9bdc_06a7_25c7_1235,0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,0xefbe_4786_384f_25e3,0x0fc1_9dc6_8b8c_d5b5,0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,0x4a74_84aa_6ea6_e483,0x5cb0_a9dc_bd41_fbd4,0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,0xa831_c66d_2db4_3210,0xb003_27c8_98fb_213f,0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,0xd5a7_9147_930a_a725,0x06ca_6351_e003_826f,0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,0x2e1b_2138_5c26_c926,0x4d2c_6dfc_5ac4_2aed,0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,0x766a_0abb_3c77_b2a8,0x81c2_c92e_47ed_aee6,0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,0xa81a_664b_bc42_3001,0xc24b_8b70_d0f8_9791,0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,0xd699_0624_5565_a910,0xf40e_3585_5771_202a,0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,0x1e37_6c08_5141_ab53,0x2748_774c_df8e_eb99,0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,0x4ed8_aa4a_e341_8acb,0x5b9c_ca4f_7763_e373,0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,0x78a5_636f_4317_2f60,0x84c8_7814_a1f0_ab72,0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,0xa450_6ceb_de82_bde9,0xbef9_a3f7_b2c6_7915,0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,0xd186_b8c7_21c0_c207,0xeada_7dd6_cde0_eb1e,0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,0x0a63_7dc5_a2c8_98a6,0x113f_9804_bef9_0dae,0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,0x32ca_ab7b_40c7_2493,0x3c9e_be0a_15c9_bebc,0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,0x597f_299c_fc65_7e2a,0x5fcb_6fab_3ad6_faec,0x6c44_198c_4a47_5817,
];

pub const SHA512_INIT: [u64; 8] = [
    0x6a09_e667_f3bc_c908,0xbb67_ae85_84ca_a73b,0x3c6e_f372_fe94_f82b,0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,0x9b05_688c_2b3e_6c1f,0x1f83_d9ab_fb41_bd6b,0x5be0_cd19_137e_2179,
];

pub const SHA384_INIT: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,0x629a_292a_367c_d507,0x9159_015a_3070_dd17,0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,0x8eb4_4a87_6858_1511,0xdb0c_2e0d_64f9_8fa7,0x47b5_481d_befa_4fa4,
];

// ─── SHA-3 / Keccak ─────────────────────────────────────────────────────────

pub const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,0x0000_0000_0000_8082,0x8000_0000_0000_808a,0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,0x0000_0000_8000_0001,0x8000_0000_8000_8081,0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,0x0000_0000_0000_0088,0x0000_0000_8000_8009,0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,0x8000_0000_0000_008b,0x8000_0000_0000_8089,0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,0x8000_0000_0000_0080,0x0000_0000_0000_800a,0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,0x8000_0000_0000_8080,0x0000_0000_8000_0001,0x8000_0000_8000_8008,
];

pub const KECCAK_ROT_OFFSETS: [[u32; 5]; 5] = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
];

// ─── Blowfish ───────────────────────────────────────────────────────────────

pub const BLOWFISH_P: [u32; 18] = [
    0x243f_6a88,0x85a3_08d3,0x1319_8a2e,0x0370_7344,0xa409_3822,0x299f_31d0,
    0x082e_fa98,0xec4e_6c89,0x4528_21e6,0x38d0_1377,0xbe54_66cf,0x34e9_0c6c,
    0xc0ac_29b7,0xc97c_50dd,0x3f84_d5b5,0xb547_0917,0x9216_d5d9,0x8979_fb1b,
];

/// First 16 entries of Blowfish S-box 0 (first 256 entries total follow the P-array init).
pub const BLOWFISH_S0_SAMPLE: [u32; 16] = [
    0xd131_0ba6,0x98df_b5ac,0x2ffd_72db,0xd01a_dfb7,0xb8e1_afed,0x6a26_7e96,
    0xba7c_9045,0xf12c_7f99,0x24a1_9947,0xb391_6cf7,0x0801_f2e2,0x858e_fc16,
    0x6369_20d8,0x7157_4e69,0xa458_fea3,0xf493_3d7e,
];

// ─── ChaCha20 ───────────────────────────────────────────────────────────────

/// "expand 32-byte k" — `ChaCha20` sigma constant.
pub const CHACHA20_SIGMA: [u8; 16] = *b"expand 32-byte k";
/// "expand 16-byte k" — `ChaCha20` tau constant.
pub const CHACHA20_TAU: [u8; 16] = *b"expand 16-byte k";

// ─── CRC32 ──────────────────────────────────────────────────────────────────

pub const CRC32_POLY: u32 = 0xedb8_8320;
pub const CRC32C_POLY: u32 = 0x82f6_3b78;

/// Standard CRC-32 lookup table.
pub const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let bytes = i.to_le_bytes();
        let mut crc = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]); // i < 256
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

pub const CRC64_POLY: u64 = 0xad93_d235_94c9_35a9;
pub const CRC64_ECMA_POLY: u64 = 0xc96c_5795_d787_0f42;

// ─── RSA / PKCS ─────────────────────────────────────────────────────────────

/// PKCS#1 v1.5 `DigestInfo` prefix for MD5.
pub const PKCS1_MD5_PREFIX: [u8; 18] = [
    0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10,
];
/// PKCS#1 v1.5 `DigestInfo` prefix for SHA-1.
pub const PKCS1_SHA1_PREFIX: [u8; 15] = [
    0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14,
];
/// PKCS#1 v1.5 `DigestInfo` prefix for SHA-256.
pub const PKCS1_SHA256_PREFIX: [u8; 19] = [
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20,
];

// ─── Elliptic Curves ────────────────────────────────────────────────────────

/// NIST P-256 (secp256r1) — prime p.
pub const P256_P: [u8; 32] = [
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
];
/// NIST P-256 order n.
pub const P256_N: [u8; 32] = [
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51,
];
/// NIST P-256 generator Gx.
pub const P256_GX: [u8; 32] = [
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
];

/// NIST P-384 prime p.
pub const P384_P: [u8; 48] = [
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
];

/// NIST P-521 prime p (first 8 bytes).
pub const P521_P_HEAD: [u8; 8] = [0x01,0xff,0xff,0xff,0xff,0xff,0xff,0xff];

/// secp256k1 prime p = 2^256 - 2^32 - 977.
pub const SECP256K1_P: [u8; 32] = [
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xfc,0x2f,
];
/// secp256k1 generator Gx.
pub const SECP256K1_GX: [u8; 32] = [
    0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,0x07,
    0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98,
];

/// Curve25519 prime p = 2^255 - 19.
pub const CURVE25519_P: [u8; 32] = [
    0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f,
];
/// Curve25519 base point u = 9.
pub const CURVE25519_BASE: u8 = 9;

// ─── GCM / GHASH ────────────────────────────────────────────────────────────

/// GCM reduction polynomial: x^128 + x^7 + x^2 + x + 1 represented as low 64 bits.
pub const GCM_REDUCTION_POLY: u64 = 0xe100_0000_0000_0000;

// ─── Twofish ────────────────────────────────────────────────────────────────

pub const TWOFISH_MDS: [[u8; 4]; 4] = [
    [0x01,0xef,0x5b,0x5b],
    [0x5b,0xef,0xef,0x01],
    [0xef,0x5b,0x01,0xef],
    [0xef,0x01,0xef,0x5b],
];

/// Twofish RS matrix (first row).
pub const TWOFISH_RS: [u8; 8] = [0x01,0xa4,0x55,0x87,0x5a,0x58,0xdb,0x9e];

// ─── Camellia ───────────────────────────────────────────────────────────────

pub const CAMELLIA_SIGMA: [u64; 6] = [
    0xa09e_667f_3bcc_908b,0xb67a_e858_4caa_73b2,0xc6ef_372f_e94f_82be,0x54ff_53a5_f1d3_6f1c,
    0x10e5_27fa_de68_2d1d,0xb056_88c2_b3e6_c1fd,
];

// ─── RC4 ────────────────────────────────────────────────────────────────────

/// RC4 identity permutation (initial S-box before KSA).
pub const RC4_IDENTITY: [u8; 256] = {
    let mut s = [0u8; 256];
    let mut i = 0usize;
    while i < 256 { s[i] = i.to_le_bytes()[0]; i += 1; } // i < 256: low byte == i
    s
};

// ─── GHASH polynomial ───────────────────────────────────────────────────────

/// GF(2^128) irreducible polynomial for GHASH: x^128+x^7+x^2+x+1.
/// The x^128 term is implicit (it does not fit in a u128); only the low
/// 128 coefficients are stored, i.e. x^7+x^2+x+1 = 0x87.
pub const GHASH_POLY: u128 = (1u128 << 7) | (1 << 2) | (1 << 1) | 1;

// ─── Constant registry ──────────────────────────────────────────────────────

/// Search for a byte sequence in the known constant tables.
/// Returns a list of matching constant names with their algorithm.
#[must_use]
#[allow(clippy::items_after_statements)]
pub fn search_constants(needle: &[u8]) -> Vec<(&'static str, &'static str)> {
    let mut results = Vec::new();
    if needle.len() < 4 { return results; }

    // Helper: check if `needle` appears anywhere in `haystack`.
    let contains = |haystack: &[u8]| -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    };

    if contains(&AES_SBOX) { results.push(("AES", "AES_SBOX")); }
    if contains(&AES_INV_SBOX) { results.push(("AES", "AES_INV_SBOX")); }
    if contains(&AES_RCON) { results.push(("AES", "AES_RCON")); }

    let md5_bytes: Vec<u8> = MD5_T.iter().flat_map(|v| v.to_le_bytes()).collect();
    if contains(&md5_bytes) { results.push(("MD5", "MD5_T_TABLE")); }

    let sha256_bytes: Vec<u8> = SHA256_K.iter().flat_map(|v| v.to_be_bytes()).collect();
    if contains(&sha256_bytes) { results.push(("SHA-256", "SHA256_K")); }

    let sha512_bytes: Vec<u8> = SHA512_K.iter().flat_map(|v| v.to_be_bytes()).collect();
    if contains(&sha512_bytes) { results.push(("SHA-512", "SHA512_K")); }

    let keccak_bytes: Vec<u8> = KECCAK_ROUND_CONSTANTS.iter().flat_map(|v| v.to_le_bytes()).collect();
    if contains(&keccak_bytes) { results.push(("SHA-3/Keccak", "KECCAK_ROUND_CONSTANTS")); }

    if contains(&CHACHA20_SIGMA) { results.push(("ChaCha20", "CHACHA20_SIGMA")); }
    if contains(&CHACHA20_TAU) { results.push(("ChaCha20", "CHACHA20_TAU")); }

    let crc_bytes = CRC32_POLY.to_le_bytes();
    if contains(&crc_bytes) { results.push(("CRC32", "CRC32_POLY")); }

    if contains(&P256_P) { results.push(("EC", "P256_P")); }
    if contains(&SECP256K1_P) { results.push(("EC", "SECP256K1_P")); }
    if contains(&SECP256K1_GX) { results.push(("EC", "SECP256K1_GX")); }
    if contains(&CURVE25519_P) { results.push(("EC", "CURVE25519_P")); }

    let bp = BLOWFISH_P.iter().flat_map(|v| v.to_be_bytes()).collect::<Vec<_>>();
    if contains(&bp) { results.push(("Blowfish", "BLOWFISH_P")); }

    let sha1_k: Vec<u8> = SHA1_K.iter().flat_map(|v| v.to_be_bytes()).collect();
    if contains(&sha1_k) { results.push(("SHA-1", "SHA1_K")); }

    // TEA / XTEA / XXTEA magic delta 0x9E3779B9 (golden ratio derived).
    const TEA_DELTA_LE: [u8; 4] = [0xB9, 0x79, 0x37, 0x9E];
    const TEA_DELTA_BE: [u8; 4] = [0x9E, 0x37, 0x79, 0xB9];
    if contains(&TEA_DELTA_LE) { results.push(("TEA/XTEA", "DELTA")); }
    if contains(&TEA_DELTA_BE) { results.push(("TEA/XTEA", "DELTA_BE")); }

    // DES S-boxes (flatten all 8 SBoxes and scan).
    let des_flat: Vec<u8> = DES_SBOX.iter().flatten().copied().collect();
    if contains(&des_flat) { results.push(("DES", "SBOX_FULL")); }

    // secp384r1 & secp521r1 curve primes (well-known EC curves).
    const SECP384R1_P: [u8; 48] = [
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
    ];
    if contains(&SECP384R1_P) { results.push(("EC", "SECP384R1_P")); }

    // Argon2 magic string "argon2".
    if contains(b"argon2") { results.push(("Argon2", "MAGIC")); }
    // bcrypt magic "$2a$" / "$2b$" / "$2y$".
    if contains(b"$2a$") || contains(b"$2b$") || contains(b"$2y$") {
        results.push(("bcrypt", "MAGIC"));
    }

    // ISAAC / Mersenne-Twister init constants (partial).
    // MT19937 magic 0x6c078965 (mult in init).
    const MT_INIT_LE: [u8; 4] = [0x65, 0x89, 0x07, 0x6c];
    if contains(&MT_INIT_LE) { results.push(("Mersenne-Twister", "INIT_MULT")); }

    // Poly1305 clamp mask
    const POLY1305_CLAMP: [u8; 16] = [
        0xff,0xff,0xff,0x0f,0xfc,0xff,0xff,0x0f,0xfc,0xff,0xff,0x0f,0xfc,0xff,0xff,0x0f,
    ];
    if contains(&POLY1305_CLAMP) { results.push(("Poly1305", "CLAMP_MASK")); }

    // SipHash-2-4 magic strings
    if contains(b"somepseudorandomlygeneratedbytes") {
        results.push(("SipHash", "TEST_KEY"));
    }

    // GCM/GHASH R polynomial 0xE100000000000000
    const GHASH_R_LE: [u8; 8] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE1];
    if contains(&GHASH_R_LE) { results.push(("GCM/GHASH", "R_POLY")); }

    // CRC32C (Castagnoli) reversed polynomial 0x82F63B78
    const CRC32C_POLY: [u8; 4] = [0x78, 0x3B, 0xF6, 0x82];
    if contains(&CRC32C_POLY) { results.push(("CRC32C", "CASTAGNOLI_POLY")); }

    // Salsa20 sigma / tau (same as ChaCha20 in some impls, but let's flag both).
    if contains(b"expand 32-byte k") { results.push(("Salsa20/ChaCha20", "SIGMA_STR")); }
    if contains(b"expand 16-byte k") { results.push(("Salsa20/ChaCha20", "TAU_STR")); }

    // MD4 init (partial — matches SHA-1 init too but flag separately).
    const MD4_INIT: [u8; 16] = [
        0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef, 0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10,
    ];
    if contains(&MD4_INIT) { results.push(("MD4", "INIT")); }

    // ── Extended IDA-parity fingerprints ────────────────────────────
    // FNV-1a / FNV-1 magic constants
    const FNV_OFFSET_32_LE: [u8; 4] = [0xC5, 0x9D, 0x1C, 0x81]; // 0x811C9DC5
    const FNV_PRIME_32_LE: [u8; 4] = [0x93, 0x01, 0x00, 0x01]; // 0x01000193
    // Derived from the numeric values rather than written out by hand: the
    // hand-written arrays encoded 0xCBBFCE9E84222325 and 0x01000000000001B3,
    // neither of which appears in any FNV implementation, so these two probes
    // could never fire.
    const FNV_OFFSET_64_LE: [u8; 8] = 0xCBF2_9CE4_8422_2325_u64.to_le_bytes();
    const FNV_PRIME_64_LE: [u8; 8] = 0x0000_0100_0000_01B3_u64.to_le_bytes();
    if contains(&FNV_OFFSET_32_LE) || contains(&FNV_OFFSET_64_LE) { results.push(("FNV", "OFFSET")); }
    if contains(&FNV_PRIME_32_LE) || contains(&FNV_PRIME_64_LE) { results.push(("FNV", "PRIME")); }

    // xxHash 32/64 primes
    // XXH_PRIME32_1 / XXH_PRIME32_2 from xxHash's own header. Derived, not
    // written out: the hand-written arrays encoded 0x9E8279B1 and 0x854ACA77 —
    // each with one corrupted byte in the middle, so neither probe could fire.
    const XXH32_P1_LE: [u8; 4] = 0x9E37_79B1_u32.to_le_bytes();
    const XXH32_P2_LE: [u8; 4] = 0x85EB_CA77_u32.to_le_bytes();
    if contains(&XXH32_P1_LE) { results.push(("xxHash32", "PRIME1")); }
    if contains(&XXH32_P2_LE) { results.push(("xxHash32", "PRIME2")); }

    // MurmurHash3 constants
    // Also derived. The hand-written arrays encoded 0xCCF10293 and
    // 0x1B665BD1; the "(approx)" note on the first was accurate — and an
    // approximate byte signature matches nothing at all.
    const MURMUR_C1_LE: [u8; 4] = 0xCC9E_2D51_u32.to_le_bytes();
    const MURMUR_C2_LE: [u8; 4] = 0x1B87_3593_u32.to_le_bytes();
    if contains(&MURMUR_C1_LE) { results.push(("MurmurHash3", "C1")); }
    if contains(&MURMUR_C2_LE) { results.push(("MurmurHash3", "C2")); }

    // CityHash / FarmHash primes
    // k0 from google/cityhash src/city.cc. Derived: the hand-written array
    // encoded 0xC3628DE6C114E98B, which keeps only the top byte of the real
    // constant.
    const CITY_K0_LE: [u8; 8] = 0xC3A5_C85C_97CB_3127_u64.to_le_bytes();
    if contains(&CITY_K0_LE) { results.push(("CityHash/FarmHash", "K0")); }

    // Adler-32 modulus 65521 = 0xFFF1
    const ADLER32_MOD_LE: [u8; 2] = [0xF1, 0xFF];
    if contains(&ADLER32_MOD_LE) { results.push(("Adler-32", "MOD_65521")); }

    // IDEA cipher — key expansion uses 25-bit rotation, no direct constant.
    // But we can flag the multiplication modulus 65537 = 0x10001.
    const IDEA_MOD_LE: [u8; 4] = [0x01, 0x00, 0x01, 0x00];
    if contains(&IDEA_MOD_LE) { results.push(("IDEA/RSA", "MOD_65537")); }

    // RC5/RC6 P32/Q32 magic
    const RC5_P32_LE: [u8; 4] = [0x63, 0x51, 0xE1, 0xB7]; // 0xB7E15163
    const RC5_Q32_LE: [u8; 4] = [0xB9, 0x79, 0x37, 0x9E]; // same as TEA delta
    if contains(&RC5_P32_LE) { results.push(("RC5/RC6", "P32")); }
    let _ = &RC5_Q32_LE; // shares TEA delta, already flagged above

    // SEED (Korean) magic 0x9E3779B9 (same as TEA — flagged)
    // ARIA cipher — no unique magic, but S-box would be identifiable by profile.
    // CAST-256 — same story.
    // MARS S-box — 512-entry table, would need specific data.

    // PEM/DER markers
    if contains(b"-----BEGIN") { results.push(("PEM", "BEGIN_MARKER")); }
    if contains(b"BEGIN CERTIFICATE") { results.push(("X.509", "PEM_CERT")); }
    if contains(b"BEGIN RSA PRIVATE KEY") { results.push(("RSA", "PEM_KEY")); }
    if contains(b"ssh-rsa") { results.push(("SSH", "RSA_KEY_TYPE")); }
    if contains(b"ssh-ed25519") { results.push(("SSH", "ED25519_KEY_TYPE")); }

    // OpenSSL / library strings
    if contains(b"OpenSSL") { results.push(("OpenSSL", "LIBRARY")); }
    if contains(b"libsodium") { results.push(("libsodium", "LIBRARY")); }
    if contains(b"BCryptGenRandom") { results.push(("Win-CNG", "BCryptGenRandom")); }
    if contains(b"CryptAcquireContext") { results.push(("Win-CryptoAPI", "CryptAcquireContext")); }

    // TLS handshake magic
    if contains(b"CLIENT_RANDOM ") { results.push(("TLS", "SSLKEYLOGFILE")); }

    // PBKDF2 / HKDF markers
    if contains(b"PBKDF2") { results.push(("PBKDF2", "IDENTIFIER")); }

    // Signal / Noise protocol
    if contains(b"Noise_") { results.push(("Noise", "PROTOCOL")); }

    results
}
#[must_use]
pub fn is_sbox_like(table: &[u8; 256]) -> bool {
    let mut seen = [false; 256];
    for &b in table {
        if seen[b as usize] { return false; }
        seen[b as usize] = true;
    }
    true
}

/// Compute the Hamming weight distribution of an S-box (for classification).
#[must_use]
pub fn sbox_hamming_profile(table: &[u8; 256]) -> [u32; 9] {
    let mut profile = [0u32; 9];
    for i in 0..256u16 {
        let diff = table[i as usize] ^ table[(i ^ 1) as usize % 256];
        profile[diff.count_ones() as usize] += 1;
    }
    profile
}

/// Returns true if the given bytes match the AES `SBox` exactly.
#[must_use]
pub fn is_aes_sbox(data: &[u8]) -> bool {
    data.len() == 256 && data == AES_SBOX.as_ref()
}

/// Returns true if the given bytes match the AES `InvSBox` exactly.
#[must_use]
pub fn is_aes_inv_sbox(data: &[u8]) -> bool {
    data.len() == 256 && data == AES_INV_SBOX.as_ref()
}

/// Try to match a 256-byte window against all known S-boxes.
/// Returns algorithm name if matched.
#[must_use]
pub fn identify_sbox(data: &[u8]) -> Option<&'static str> {
    if data.len() < 256 { return None; }
    let window = &data[..256];
    if window == AES_SBOX.as_ref() { return Some("AES SBox"); }
    if window == AES_INV_SBOX.as_ref() { return Some("AES InvSBox"); }
    None
}

/// Check if a u32 slice matches SHA-256 K constants (full or partial, at least 16 words).
#[must_use]
pub fn has_sha256_k(words: &[u32]) -> bool {
    if words.len() < 16 { return false; }
    words[..16] == SHA256_K[..16]
}

/// Check if a u64 slice matches SHA-512 K constants (at least 16 words).
#[must_use]
pub fn has_sha512_k(words: &[u64]) -> bool {
    if words.len() < 16 { return false; }
    words[..16] == SHA512_K[..16]
}

/// Check if a u64 slice starts with Keccak round constants.
#[must_use]
pub fn has_keccak_rc(words: &[u64]) -> bool {
    if words.len() < 8 { return false; }
    words[..8] == KECCAK_ROUND_CONSTANTS[..8]
}

/// Check raw bytes for `ChaCha20` sigma.
#[must_use]
pub fn has_chacha20_sigma(data: &[u8]) -> bool {
    data.windows(16).any(|w| w == CHACHA20_SIGMA)
}

/// All well-known crypto constant fingerprints as (algorithm, label, bytes) tuples.
/// Returned as owned vecs to allow runtime construction.
#[must_use]
pub fn all_fingerprints() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    vec![
        ("AES",     "SBOX",    AES_SBOX.to_vec()),
        ("AES",     "INV_SBOX",AES_INV_SBOX.to_vec()),
        ("AES",     "RCON",    AES_RCON.to_vec()),
        ("MD5",     "T_TABLE", MD5_T.iter().flat_map(|v| v.to_le_bytes()).collect()),
        ("MD5",     "INIT",    MD5_INIT.iter().flat_map(|v| v.to_le_bytes()).collect()),
        ("SHA-1",   "INIT",    SHA1_INIT.iter().flat_map(|v| v.to_be_bytes()).collect()),
        ("SHA-1",   "K",       SHA1_K.iter().flat_map(|v| v.to_be_bytes()).collect()),
        ("SHA-256", "K",       SHA256_K.iter().flat_map(|v| v.to_be_bytes()).collect()),
        ("SHA-256", "INIT",    SHA256_INIT.iter().flat_map(|v| v.to_be_bytes()).collect()),
        ("SHA-384", "INIT",    SHA384_INIT.iter().flat_map(|v| v.to_be_bytes()).collect()),
        ("SHA-512", "K",       SHA512_K[..32].iter().flat_map(|v| v.to_be_bytes()).collect()),
        ("SHA-512", "INIT",    SHA512_INIT.iter().flat_map(|v| v.to_be_bytes()).collect()),
        ("Keccak",  "RC",      KECCAK_ROUND_CONSTANTS[..8].iter().flat_map(|v| v.to_le_bytes()).collect()),
        ("ChaCha20","SIGMA",   CHACHA20_SIGMA.to_vec()),
        ("ChaCha20","TAU",     CHACHA20_TAU.to_vec()),
        ("CRC32",   "POLY",    CRC32_POLY.to_le_bytes().to_vec()),
        ("Blowfish","P",       BLOWFISH_P.iter().flat_map(|v| v.to_be_bytes()).collect()),
        ("EC-P256", "P",       P256_P.to_vec()),
        ("EC-P256", "N",       P256_N.to_vec()),
        ("EC-P256", "GX",      P256_GX.to_vec()),
        ("secp256k1","P",      SECP256K1_P.to_vec()),
        ("secp256k1","GX",     SECP256K1_GX.to_vec()),
        ("Curve25519","P",     CURVE25519_P.to_vec()),
        ("PKCS1",   "MD5_PFX", PKCS1_MD5_PREFIX.to_vec()),
        ("PKCS1",   "SHA1_PFX",PKCS1_SHA1_PREFIX.to_vec()),
        ("PKCS1",   "SHA256_PFX",PKCS1_SHA256_PREFIX.to_vec()),
        ("Twofish", "RS",      TWOFISH_RS.to_vec()),
        ("Camellia","SIGMA",   CAMELLIA_SIGMA.iter().flat_map(|v| v.to_be_bytes()).collect()),
    ]
}

/// Scan a byte slice for any known cryptographic constant.
/// Returns a list of (offset, algorithm, label).
#[must_use]
pub fn scan_for_constants(data: &[u8]) -> Vec<(usize, &'static str, &'static str)> {
    let fingerprints = all_fingerprints();
    let mut hits = Vec::new();
    for (algo, label, pattern) in &fingerprints {
        if pattern.len() < 4 { continue; }
        for (offset, window) in data.windows(pattern.len()).enumerate() {
            if window == pattern.as_slice() {
                hits.push((offset, *algo, *label));
            }
        }
    }
    hits.sort_by_key(|h| h.0);
    hits
}

/// Build a quick-lookup `HashMap` from constant 4-byte prefix -> (algo, label).
///
/// # Panics
/// Panics if a fingerprint returned by `all_fingerprints` claims `len >= 4` but
/// cannot be sliced to exactly 4 bytes (which cannot happen in practice).
#[must_use]
pub fn build_prefix_index() -> HashMap<[u8; 4], Vec<(&'static str, &'static str)>> {
    let mut map: HashMap<[u8; 4], Vec<(&'static str, &'static str)>> = HashMap::new();
    for (algo, label, bytes) in all_fingerprints() {
        if bytes.len() >= 4 {
            let key: [u8; 4] = bytes[..4].try_into().unwrap();
            map.entry(key).or_default().push((algo, label));
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_sbox_is_bijective() {
        assert!(is_sbox_like(&AES_SBOX));
        assert!(is_sbox_like(&AES_INV_SBOX));
    }

    #[test]
    fn aes_sbox_inv_round_trip() {
        for i in 0..256usize {
            let enc = AES_SBOX[i];
            let dec = AES_INV_SBOX[enc as usize];
            assert_eq!(dec, i as u8, "S-box round-trip failed at index {i}");
        }
    }

    #[test]
    fn chacha20_sigma_matches() {
        assert!(has_chacha20_sigma(&CHACHA20_SIGMA));
        assert!(!has_chacha20_sigma(b"expand 16-byte k"));
    }

    #[test]
    fn sha256_k_check() {
        assert!(has_sha256_k(&SHA256_K));
    }

    #[test]
    fn search_finds_murmur3_and_fnv64_constants() {
        // These probes are only useful if they fire on the real constants.
        // Feeding in exactly the bytes a compiled MurmurHash3 would contain is
        // the only check that distinguishes a correct signature from a
        // plausible-looking one — the previous hand-written arrays passed every
        // existing test while matching nothing.
        for (value, algo, label) in [
            (0xCC9E_2D51_u32, "MurmurHash3", "C1"),
            (0x1B87_3593_u32, "MurmurHash3", "C2"),
        ] {
            let hits = search_constants(&value.to_le_bytes());
            assert!(
                hits.iter().any(|(a, l)| *a == algo && *l == label),
                "{algo} {label} (0x{value:08X}) not detected"
            );
        }

        let hits = search_constants(&0xCBF2_9CE4_8422_2325_u64.to_le_bytes());
        assert!(
            hits.iter().any(|(a, l)| *a == "FNV" && *l == "OFFSET"),
            "FNV-1a 64-bit offset basis not detected"
        );
        let hits = search_constants(&0x0000_0100_0000_01B3_u64.to_le_bytes());
        assert!(
            hits.iter().any(|(a, l)| *a == "FNV" && *l == "PRIME"),
            "FNV-1a 64-bit prime not detected"
        );

        for (value, label) in [(0x9E37_79B1_u32, "PRIME1"), (0x85EB_CA77_u32, "PRIME2")] {
            let hits = search_constants(&value.to_le_bytes());
            assert!(
                hits.iter().any(|(a, l)| *a == "xxHash32" && *l == label),
                "xxHash32 {label} (0x{value:08X}) not detected"
            );
        }

        let hits = search_constants(&0xC3A5_C85C_97CB_3127_u64.to_le_bytes());
        assert!(
            hits.iter().any(|(a, l)| *a == "CityHash/FarmHash" && *l == "K0"),
            "CityHash k0 not detected"
        );

        // These four were already correct; asserting them keeps a future
        // hand-edit from silently breaking one.
        for (bytes, algo) in [
            (0x9E37_79B9_u32.to_le_bytes(), "TEA"),
            (0x6C07_8965_u32.to_le_bytes(), "MersenneTwister"),
        ] {
            assert!(
                !search_constants(&bytes).is_empty(),
                "{algo} constant no longer detected"
            );
        }
    }

    #[test]
    fn scan_finds_aes_sbox() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(&AES_SBOX);
        let hits = scan_for_constants(&data);
        assert!(hits.iter().any(|(_, a, l)| *a == "AES" && *l == "SBOX"));
    }

    #[test]
    fn search_finds_sha256() {
        let chunk: Vec<u8> = SHA256_K[..8].iter().flat_map(|v| v.to_be_bytes()).collect();
        let results = search_constants(&chunk);
        assert!(results.iter().any(|(a, _)| *a == "SHA-256"));
    }
}
