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

mod word_list;

pub use word_list::{BITS_PER_WORD, LONGEST_WORD_LENGTH, WORD_LIST};

use super::{
    try_get_bit_at_index, try_get_bit_start_offset, try_get_word_index, try_set_bit_at_index,
    ExtensionPhraseNormalizationSettings,
};
use crate::{
    hashing::{Hasher, Sha256},
    String16,
};
use alloc::{boxed::Box, vec, vec::Vec};
use macros::s16;

pub const EXTENSION_PREFIX: &[u8] = "mnemonic".as_bytes();
pub const SEED_DERIVATION_PBKDF_ITERATIONS: u32 = 2048;
pub const NORMALIZATION_SETTINGS: ExtensionPhraseNormalizationSettings =
    ExtensionPhraseNormalizationSettings::from(false, false, false);

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum Bip39MnemonicLength {
    Twelve,
    Fifteen,
    Eighteen,
    TwentyOne,
    TwentyFour,
}

impl Into<usize> for Bip39MnemonicLength {
    fn into(self) -> usize {
        match self {
            Bip39MnemonicLength::Twelve => 12,
            Bip39MnemonicLength::Fifteen => 15,
            Bip39MnemonicLength::Eighteen => 18,
            Bip39MnemonicLength::TwentyOne => 21,
            Bip39MnemonicLength::TwentyFour => 24,
        }
    }
}

impl Into<String16<'static>> for Bip39MnemonicLength {
    fn into(self) -> String16<'static> {
        match self {
            Bip39MnemonicLength::Twelve => s16!("Twelve Word"),
            Bip39MnemonicLength::Fifteen => s16!("Fifteen Word"),
            Bip39MnemonicLength::Eighteen => s16!("Eighteen Word"),
            Bip39MnemonicLength::TwentyOne => s16!("Twenty One Word"),
            Bip39MnemonicLength::TwentyFour => s16!("Twenty Four Word"),
        }
    }
}

const AVAILABLE_MNEMONIC_LENGTHS: [Bip39MnemonicLength; 5] = [
    Bip39MnemonicLength::Twelve,
    Bip39MnemonicLength::Fifteen,
    Bip39MnemonicLength::Eighteen,
    Bip39MnemonicLength::TwentyOne,
    Bip39MnemonicLength::TwentyFour,
];

pub fn get_available_mnemonic_lengths(byte_count: usize) -> &'static [Bip39MnemonicLength] {
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

pub const MAX_WORD_COUNT: usize = 24;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum Bip39MnemonicParsingResult<'a> {
    InvalidLength,
    InvalidWordEncountered(Bip39MnemonicLength, String16<'a>, usize),
    InvalidChecksum(Bip39MnemonicLength, Box<[u8]>, u8, u8),
    Valid(Bip39MnemonicLength, Box<[u8]>, u8),
}

pub fn required_bits_of_entropy_for_mnemonic_length(mnemonic_length: Bip39MnemonicLength) -> usize {
    (Into::<usize>::into(mnemonic_length) * (BITS_PER_WORD as usize)) / 33 * 32
}

pub fn try_generate_bip_39_mnemonic(
    mnemonic_length: Bip39MnemonicLength,
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
        v.push(try_get_word(start_offset, i, &mnemonic_bytes).unwrap())
    }

    // We don't need the raw bytes anymore; pre-emptively overwrite it.
    mnemonic_bytes.fill(0);
    Some(v)
}

pub fn try_parse_bip39_mnemonic<'a>(words: &Vec<String16<'a>>) -> Bip39MnemonicParsingResult<'a> {
    // Get the mnemonic length.
    let mnemonic_length = match words.len() {
        24 => Bip39MnemonicLength::TwentyFour,
        21 => Bip39MnemonicLength::TwentyOne,
        18 => Bip39MnemonicLength::Eighteen,
        15 => Bip39MnemonicLength::Fifteen,
        12 => Bip39MnemonicLength::Twelve,
        // Words has an invalid length.
        _ => return Bip39MnemonicParsingResult::InvalidLength,
    };

    // Mnemonic constituent calculations.
    let entropy_bits = required_bits_of_entropy_for_mnemonic_length(mnemonic_length);
    let entropy_byte_count = entropy_bits / 8;
    let checksum_bits = entropy_bits / 32;

    // Read the bytes from the mnemonic.
    let mnemonic_bit_count = entropy_bits + checksum_bits;
    let mnemonic_byte_count = entropy_byte_count + 1;
    let (mnemonic_bit_start_offset, mut mnemonic_bytes) =
        match try_read_mnemonic_bytes(mnemonic_byte_count, mnemonic_bit_count, words) {
            Err((w, i)) => {
                return Bip39MnemonicParsingResult::InvalidWordEncountered(mnemonic_length, w, i)
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
        Bip39MnemonicParsingResult::Valid(mnemonic_length, entropy_bytes.into(), checksum_bytes[0])
    } else {
        Bip39MnemonicParsingResult::InvalidChecksum(
            mnemonic_length,
            entropy_bytes.into(),
            checksum_bytes[0],
            expected_checksum_bytes[0],
        )
    };
}

pub fn try_get_word(
    start_bit_offset: usize,
    word_number: usize,
    bytes: &[u8],
) -> Option<String16<'static>> {
    match try_get_word_index(start_bit_offset, word_number, BITS_PER_WORD, bytes) {
        Some(i) => Some(WORD_LIST[i]),
        None => None,
    }
}

pub fn try_read_mnemonic_bytes<'a>(
    mnemonic_byte_count: usize,
    mnemonic_bit_count: usize,
    words: &Vec<String16<'a>>,
) -> Result<(usize, Vec<u8>), (String16<'a>, usize)> {
    // Initialize a byte vector for reading the mnemonic into.
    let mut mnemonic_bytes = vec![0u8; mnemonic_byte_count];

    // Calculate the offset to write the mnemonic's bits at.
    let mnemonic_bit_start_offset =
        try_get_bit_start_offset(mnemonic_bit_count, mnemonic_byte_count).unwrap();

    // Iterate over the words in the mnemonic.
    for i in 0..words.len() {
        let word = words[i];

        // Look for the word in the word list.
        let word = match WORD_LIST
            .binary_search_by(|w| w.content_iterator().cmp(word.content_iterator()))
        {
            Ok(i) => i,
            Err(_) => {
                // We couldn't find the word in the word list; return an error.
                return Err((word, i));
            }
        }
        .to_be_bytes();

        // Get the start offset for the word's bits.
        let word_bit_start_offset =
            try_get_bit_start_offset(BITS_PER_WORD as usize, word.len()).unwrap();

        // Write the word's bits to the mnemonic byte buffer.
        for j in 0..BITS_PER_WORD {
            assert!(try_set_bit_at_index(
                mnemonic_bit_start_offset + (i * BITS_PER_WORD as usize) + (j as usize),
                try_get_bit_at_index(word_bit_start_offset + j as usize, &word).unwrap(),
                &mut mnemonic_bytes,
            ));
        }
    }

    Ok((mnemonic_bit_start_offset, mnemonic_bytes))
}
