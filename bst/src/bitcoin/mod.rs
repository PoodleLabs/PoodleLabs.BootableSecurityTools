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

pub mod hd_wallets;
pub mod mnemonics;

mod hash_160;

pub use hash_160::Hash160;

use crate::{
    hashing::{Hasher, Sha256},
    integers::{NumericBase, NumericCollector, NumericCollectorRoundBase},
};
use alloc::vec::Vec;

pub fn calculate_checksum_for(bytes: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    let mut checksum_buffer = [0u8; 4];
    checksum_buffer.copy_from_slice(&hasher.calculate_double_hash_checksum_for(bytes)[..4]);
    checksum_buffer
}

pub fn validate_checksum_in(bytes: &[u8]) -> (bool, Option<[u8; 4]>) {
    if bytes.len() < 5 {
        // The checksum is 4 bytes in length; if there's not at least 5 bytes, there can't possibly be a valid checksum.
        return (false, None);
    }

    // Calculate the expected checksum for the input bytes, excluding the last 4.
    let checksum_bytes = calculate_checksum_for(&bytes[..bytes.len() - 4]);

    // Check if the expected checksum matches the last 4 bytes of input.
    (
        checksum_bytes == &bytes[bytes.len() - 4..],
        Some(checksum_bytes),
    )
}

pub fn base_58_encode_with_checksum(bytes: &[u8]) -> Vec<u16> {
    // Calculate the double SHA256 hash checksum.
    let checksum = calculate_checksum_for(bytes);

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
    let mut integer = numeric_collector.extract_big_unsigned();

    // Build a base-58 string from the big integer.
    let base_58_string =
        NumericBase::BASE_58.build_string_from_big_unsigned(&mut integer, false, 0);

    // Zero the integer; we're done with it.
    integer.zero();

    base_58_string
}
