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

pub mod bip_39;
pub mod electrum;

use crate::{
    hashing::{Hasher, Sha512},
    String16,
};
use alloc::vec::Vec;
use macros::s16;

pub const BLANK_STRING: String16 = s16!("");

pub fn format_mnemonic_string_utf8<'a>(
    mnemonic: &Vec<String16<'a>>,
    space: String16<'a>,
) -> Vec<u8> {
    // No words, no output.
    if mnemonic.len() == 0 {
        return Vec::with_capacity(0);
    }

    // Count the total number of characters required.
    let word_characters: usize = mnemonic.iter().map(|w| w.content_length_utf8()).sum();
    let space_characters = (mnemonic.len() - 1) * space.content_length_utf8();

    // Prepare a vec, then fill it one word at a time.
    let mut vec = Vec::with_capacity(space_characters + word_characters);
    for i in 0..(mnemonic.len() - 1) {
        mnemonic[i].extend_utf8_vec_with_content(&mut vec);

        // Space after every word but the last.
        space.extend_utf8_vec_with_content(&mut vec);
    }

    // Last word, no space.
    mnemonic[mnemonic.len() - 1].extend_utf8_vec_with_content(&mut vec);
    vec
}

pub fn derive_hd_wallet_seed(
    mut mnemonic: Vec<String16<'static>>,
    word_space: String16<'static>,
    extension_prefix: &[u8],
    passphrase: &mut [u16],
    iterations: u32,
) -> [u8; Sha512::HASH_SIZE] {
    // Prepare the output buffer.
    let mut output = [0u8; Sha512::HASH_SIZE];
    {
        let p = String16::from(&passphrase);

        // Get the UTF8 version of the mnemonic string.
        let mut mnemonic_string = format_mnemonic_string_utf8(&mnemonic, word_space);

        // Prepare a UTF8 buffer for the salt.
        let mut salt = Vec::with_capacity(extension_prefix.len() + p.content_length_utf8());

        // Salts are prefixed, eg: utf8'mnemonic', or utf8'electrum'.
        salt.extend(extension_prefix);

        // Write the extension phrase to the salt buffer. TODO: NORMALIZATION.
        p.extend_utf8_vec_with_content(&mut salt);

        // Prepare the HMAC.
        let mut hasher = Sha512::new();
        let mut hmac = hasher.build_hmac(&mnemonic_string);

        // We don't need the mnemonic string anymore, it was just the key, so pre-emptively fill it.
        mnemonic_string.fill(0);

        // Perform the PBKDF and write to the output buffer.
        hmac.pbkdf2(&salt, iterations, &mut output);

        // Pre-emptively fill all this sensitive material.
        mnemonic.fill(BLANK_STRING);
        passphrase.fill(0);
        hasher.reset();
        salt.fill(0);
    }

    output
}

const fn try_get_bit_start_offset(bit_count: usize, byte_count: usize) -> Option<usize> {
    let available_bits = byte_count * 8;
    if available_bits < bit_count {
        None
    } else {
        // Read the trailing bits if we have more than we need.
        Some(available_bits - bit_count)
    }
}

fn try_set_bit_at_index(bit_index: usize, value: bool, bytes: &mut [u8]) -> bool {
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

const fn try_get_bit_at_index(bit_index: usize, bytes: &[u8]) -> Option<bool> {
    let byte_index = bit_index / 8;
    if byte_index >= bytes.len() {
        return None;
    }

    let byte = bytes[byte_index];
    let bit_index = bit_index % 8;
    let bit_mask = 0b10000000u8 >> bit_index;
    Some((bit_mask & byte) != 0)
}

fn try_get_word_index(
    start_bit_offset: usize,
    word_number: usize,
    bits_per_word: u8,
    bytes: &[u8],
) -> Option<usize> {
    if bits_per_word > 64 {
        // We unwrap into a usize so we can index a word list; we can't support more than 64 bits per word.
        // It's OK though... there's not that many words.
        return None;
    }

    let start = start_bit_offset + (word_number * (bits_per_word as usize));
    let end = start + (bits_per_word as usize);
    if end > bytes.len() * 8 {
        return None;
    }

    let mut index = 0usize;
    for i in start..end {
        // Read the bits one at a time into the index; we're just building up a base 2 number.
        index *= 2;
        index += try_get_bit_at_index(i, bytes).unwrap() as usize;
    }

    Some(index)
}
