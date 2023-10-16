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

pub const fn try_get_bit_start_offset(bit_count: usize, byte_count: usize) -> Option<usize> {
    let available_bits = byte_count * 8;
    if available_bits < bit_count {
        None
    } else {
        // Read the trailing bits if we have more than we need.
        Some(available_bits - bit_count)
    }
}

pub const fn try_get_bit_at_index(bit_index: usize, bytes: &[u8]) -> Option<bool> {
    let byte_index = bit_index / 8;
    if byte_index >= bytes.len() {
        return None;
    }

    let byte = bytes[byte_index];
    let bit_index = bit_index % 8;
    let bit_mask = 0b10000000u8 >> bit_index;
    Some((bit_mask & byte) != 0)
}

pub fn try_set_bit_at_index(bit_index: usize, value: bool, bytes: &mut [u8]) -> bool {
    let byte_index = bit_index / 8;
    if byte_index >= bytes.len() {
        return false;
    }

    let byte = bytes[byte_index];
    let bit_index = bit_index % 8;
    let bit_mask = 0b10000000u8 >> bit_index;
    bytes[byte_index] = if value {
        byte | bit_mask
    } else {
        byte & (!bit_mask)
    };

    true
}
