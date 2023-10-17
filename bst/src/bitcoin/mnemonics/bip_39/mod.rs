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

mod mnemonic_length;
mod parser;
mod word_list;

pub use mnemonic_length::MnemonicLength;
pub use parser::MnemonicParser;

use super::{
    Bip32DevivationSettings, MnemonicFormat, MnemonicTextNormalizationSettings, MnemonicWordList,
};
use crate::{
    bits::{try_get_bit_at_index, try_get_bit_start_offset, try_set_bit_at_index},
    hashing::{Hasher, Sha256},
    String16,
};
use alloc::{boxed::Box, vec, vec::Vec};
use macros::s16;

pub const WORD_LIST: MnemonicWordList = MnemonicWordList::from(
    &word_list::WORDS,
    word_list::LONGEST_WORD_LENGTH,
    s16!("BIP 39"),
    word_list::BITS_PER_WORD,
);

pub const MNEMONIC_FORMAT: MnemonicFormat<MnemonicLength> = MnemonicFormat::from(
    get_available_lengths_for_byte_count,
    s16!("16"),
    WORD_LIST,
    s16!("BIP 39"),
    24,
);

pub const BIP_32_DERIVATION_SETTINGS: Bip32DevivationSettings = Bip32DevivationSettings::from(
    MnemonicTextNormalizationSettings::from(false, false, false),
    s16!(" "),
    "mnemonic".as_bytes(),
    2048,
);

pub fn required_bits_of_entropy_for_mnemonic_length(mnemonic_length: MnemonicLength) -> usize {
    (Into::<usize>::into(mnemonic_length) * (word_list::BITS_PER_WORD)) / 33 * 32
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum MnemonicParsingResult<'a> {
    InvalidLength,
    InvalidWordEncountered(MnemonicLength, String16<'a>, usize),
    InvalidChecksum(MnemonicLength, Box<[u8]>, u8, u8),
    Valid(MnemonicLength, Box<[u8]>, u8),
}

pub fn try_generate_mnemonic(
    mnemonic_length: MnemonicLength,
    bytes: &[u8],
) -> Option<Vec<String16<'static>>> {
    // Calculate the required entropy bits and bytes.
    let entropy_bits = required_bits_of_entropy_for_mnemonic_length(mnemonic_length);

    // All required entropy bits for valid mnemonic lengths are multiples of 8.
    let required_bytes = entropy_bits / 8;
    let available_bits = bytes.len() * 8;
    if available_bits < entropy_bits {
        // We don't have enough bits; return None.
        return None;
    }

    // Grab the trailing bytes from the input.
    let entropy_bytes = &bytes[bytes.len() - required_bytes..];
    let mut hasher = Sha256::new();

    // Hash the bytes we'll use for the mnemonic's words.
    let hash = hasher.get_hash_of(entropy_bytes);
    hasher.reset();

    // Calculate the number of checksum bits we need; 4 for 12 words, 5 for 15 words, etc.
    let checksum_bits = entropy_bits / 32;
    let mnemonic_bits = entropy_bits + checksum_bits;

    // Write the mnemonic entropy bits to a buffer which will also have the checksum bits.
    let mut mnemonic_bytes = vec![0u8; required_bytes + 1];

    // Get the offset; we left-pad the mnemonic bytes to fit checksum bits below a mnemonic length of 24.
    // This is guaranteed to succeed because we've already checked we have the required length, so unwrap.
    let start_offset = try_get_bit_start_offset(mnemonic_bits, mnemonic_bytes.len()).unwrap();
    for i in 0..entropy_bits {
        try_set_bit_at_index(
            start_offset + i,
            // Guaranteed to succeed as we've already checked the lengths, so unwrap.
            try_get_bit_at_index(i, entropy_bytes).unwrap(),
            &mut mnemonic_bytes,
        );
    }

    // Write the checksum bits to the end of the mnemonic bits.
    for i in 0..checksum_bits {
        try_set_bit_at_index(
            start_offset + entropy_bits + i,
            // Guaranteed to succeed, so unwrap.
            try_get_bit_at_index(i, &hash).unwrap(),
            &mut mnemonic_bytes,
        );
    }

    // Get the number of words the mnemonic should have as an integer and allocate a word buffer.
    let word_count = Into::<usize>::into(mnemonic_length);
    let mut v = Vec::with_capacity(word_count);
    for i in 0..word_count {
        // Get the words one by one from the mnemnonic bits; guaranteed to succeed as we've already checked the length, so unwrap.
        v.push(
            WORD_LIST
                .try_get_word(start_offset, i, &mnemonic_bytes)
                .unwrap(),
        )
    }

    // We don't need the raw bytes anymore; pre-emptively overwrite it.
    mnemonic_bytes.fill(0);
    Some(v)
}

pub fn try_parse_bip39_mnemonic<'a>(words: &Vec<String16<'a>>) -> MnemonicParsingResult<'a> {
    // Get the mnemonic length.
    let mnemonic_length = match words.len() {
        24 => MnemonicLength::TwentyFour,
        21 => MnemonicLength::TwentyOne,
        18 => MnemonicLength::Eighteen,
        15 => MnemonicLength::Fifteen,
        12 => MnemonicLength::Twelve,
        // Words has an invalid length.
        _ => return MnemonicParsingResult::InvalidLength,
    };

    // Mnemonic constituent calculations.
    let entropy_bits = required_bits_of_entropy_for_mnemonic_length(mnemonic_length);
    let entropy_byte_count = entropy_bits / 8;
    let checksum_bits = entropy_bits / 32;

    // Read the bytes from the mnemonic.
    let mnemonic_bit_count = entropy_bits + checksum_bits;
    let mnemonic_byte_count = entropy_byte_count + 1;
    let (mnemonic_bit_start_offset, mut mnemonic_bytes) =
        match WORD_LIST.try_read_mnemonic_bytes(mnemonic_byte_count, mnemonic_bit_count, words) {
            Err((w, i)) => {
                return MnemonicParsingResult::InvalidWordEncountered(mnemonic_length, w, i)
            }
            Ok(b) => b,
        };

    // Initialize a buffer to read the entropy bytes into.
    let mut entropy_bytes = vec![0u8; entropy_byte_count];

    // Read the entropy bits from the mnemonic byte buffer into the entropy byte buffer.
    for i in 0..entropy_bits {
        assert!(try_set_bit_at_index(
            i,
            try_get_bit_at_index(mnemonic_bit_start_offset + i, &mnemonic_bytes).unwrap(),
            &mut entropy_bytes,
        ));
    }

    // Initialize a single byte buffer to read the actual checksum into.
    let mut checksum_bytes = [0u8];
    let checksum_start_bit_offset = try_get_bit_start_offset(checksum_bits, 1).unwrap();

    // Read the checksum bits from the mnemonic byte buffer into the checksum byte buffer.
    for i in 0..checksum_bits {
        assert!(try_set_bit_at_index(
            checksum_start_bit_offset + i,
            try_get_bit_at_index(
                mnemonic_bit_start_offset + entropy_bits + i,
                &mnemonic_bytes,
            )
            .unwrap(),
            &mut checksum_bytes,
        ));
    }

    // Overwrite the mnemonic byte buffer as we no longer need it.
    mnemonic_bytes.fill(0);

    // Hash the entropy bytes for the checksum.
    let mut hasher = Sha256::new();
    let hash = hasher.get_hash_of(&entropy_bytes);
    hasher.reset();

    // Initialize a single byte buffer to read the expected checksum into.
    let mut expected_checksum_bytes = [0u8];

    // Read the expected checksum bits from the hash into the expected checksum byte buffer.
    for i in 0..checksum_bits {
        try_set_bit_at_index(
            checksum_start_bit_offset + i,
            try_get_bit_at_index(i, &hash).unwrap(),
            &mut expected_checksum_bytes,
        );
    }

    return if expected_checksum_bytes == checksum_bytes {
        MnemonicParsingResult::Valid(mnemonic_length, entropy_bytes.into(), checksum_bytes[0])
    } else {
        MnemonicParsingResult::InvalidChecksum(
            mnemonic_length,
            entropy_bytes.into(),
            checksum_bytes[0],
            expected_checksum_bytes[0],
        )
    };
}

const AVAILABLE_MNEMONIC_LENGTHS: [MnemonicLength; 5] = [
    MnemonicLength::Twelve,
    MnemonicLength::Fifteen,
    MnemonicLength::Eighteen,
    MnemonicLength::TwentyOne,
    MnemonicLength::TwentyFour,
];

fn get_available_lengths_for_byte_count(byte_count: usize) -> &'static [MnemonicLength] {
    let mut count = 0;
    for i in 0..AVAILABLE_MNEMONIC_LENGTHS.len() {
        if required_bits_of_entropy_for_mnemonic_length(AVAILABLE_MNEMONIC_LENGTHS[i]) / 8
            <= byte_count
        {
            count += 1;
        } else {
            break;
        }
    }

    &AVAILABLE_MNEMONIC_LENGTHS[..count]
}
