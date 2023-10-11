// Poodle Labs' Bootable Security Tools (BST)
// Copyright (C) 2023 Isaac Beizsley (isaac@poodlelabs.com)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::{
    cryptography::asymmetric::secp256k1,
    hashing::{Hasher, Sha256, Sha512},
    integers::{BigUnsigned, NumericBase, NumericCollector, NumericCollectorRoundBase},
};
use alloc::vec::Vec;

// Serialized keys are prefixed with version bytes.
pub const MAIN_NET_PRIVATE_KEY_VERSION: u32 = 0x0488ADE4;
pub const TEST_NET_PRIVATE_KEY_VERSION: u32 = 0x04358394;

#[allow(dead_code)]
pub const MAIN_NET_PUBLIC_KEY_VERSION: u32 = 0x0488B21E;

#[allow(dead_code)]
pub const TEST_NET_PUBLIC_KEY_VERSION: u32 = 0x043587CF;

// The key used for HMAC-based BIP 32 master key derivation.
const KEY_DERIVATION_KEY_BYTES: &[u8] = "Bitcoin seed".as_bytes();

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum KeyType {
    #[allow(dead_code)]
    Private,

    #[allow(dead_code)]
    Public,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum Bip32KeyVersion {
    MainNet,
    TestNet,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct SerializedExtendedKey {
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: [u8; 4],
    chain_code: [u8; 32],
    key_material: [u8; 33],
}

impl SerializedExtendedKey {
    pub fn as_bytes(&self) -> [u8; 78] {
        let mut bytes = [0u8; 78];
        bytes[00..04].copy_from_slice(&self.version);
        bytes[000004] = self.depth;
        bytes[05..09].copy_from_slice(&self.parent_fingerprint);
        bytes[09..13].copy_from_slice(&self.child_number);
        bytes[13..45].copy_from_slice(&self.chain_code);
        bytes[45..78].copy_from_slice(&self.key_material);
        bytes
    }

    pub fn zero(mut self) {
        self.version.fill(0);
        self.depth = 0;
        self.parent_fingerprint.fill(0);
        self.child_number.fill(0);
        self.chain_code.fill(0);
        self.key_material.fill(0);
    }
}

pub fn base_58_encode_with_checksum(bytes: &[u8]) -> Vec<u16> {
    // Calculate the double SHA256 hash checksum.
    let checksum = Sha256::new().calculate_double_hash_checksum_for(&bytes);

    // Build a numeric collector for combining the bytes and their checksum.
    let mut numeric_collector = NumericCollector::with_byte_capacity(bytes.len() + 4);
    for byte in bytes {
        // Copy the bytes to the numeric collector.
        _ = numeric_collector.try_add_round(*byte, NumericCollectorRoundBase::WholeByte);
    }

    for byte in checksum {
        // Copy the checksum bytes to the numeric collector.
        _ = numeric_collector.try_add_round(byte, NumericCollectorRoundBase::WholeByte);
    }

    // Extract the underlying big unsigned integer.
    let integer = numeric_collector
        .extract_big_unsigned()
        .take_data_ownership();

    // Build a base-58 string from the big integer.
    NumericBase::BASE_58.build_string_from_big_unsigned(integer, false, 0)
}

pub fn try_derive_master_key(
    key_network: Bip32KeyVersion,
    bytes: &[u8],
) -> Option<SerializedExtendedKey> {
    if bytes.len() < 16 || bytes.len() > 64 {
        // BIP 32 defines a valid seed byte sequence S of length 128 to 512 bits.
        return None;
    }

    // BIP 32 master keys are derived via a SHA512 HMAC.
    let mut hasher = Sha512::new();
    let mut hmac = hasher.build_hmac(KEY_DERIVATION_KEY_BYTES);
    let mut hmac_result = hmac.get_hmac(bytes);

    let mut key_integer = BigUnsigned::from_be_bytes(&hmac_result[..32]);
    if !key_integer.is_non_zero() || &key_integer >= secp256k1::n() {
        // The key must be in the range: 0 < K < N. This shouldn't ever be hit in reality.
        return None;
    }

    // Zero out key integer copy of key.
    key_integer.zero();

    // Key is the first 32 bytes, Chain Code is the last 32 bytes.
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&hmac_result[32..]);

    // The serialized form of a private key is left-padded with a single 0 byte.
    let key_material = serialized_private_key_bytes(&hmac_result[..32]);

    // Fill HMAC copy of key & chain code.
    hmac_result.fill(0);

    Some(SerializedExtendedKey {
        version: match key_network {
            Bip32KeyVersion::MainNet => MAIN_NET_PRIVATE_KEY_VERSION.to_be_bytes(),
            Bip32KeyVersion::TestNet => TEST_NET_PRIVATE_KEY_VERSION.to_be_bytes(),
        },
        parent_fingerprint: [0, 0, 0, 0],
        child_number: [0, 0, 0, 0],
        key_material,
        chain_code,
        depth: 0,
    })
}

fn serialized_private_key_bytes(key: &[u8]) -> [u8; 33] {
    // Private keys are prefixed with a single 0 byte in the format.
    let mut bytes = [0u8; 33];
    bytes[1..].copy_from_slice(key);
    bytes
}
