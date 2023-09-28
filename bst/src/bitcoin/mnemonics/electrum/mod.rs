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

///////////
// NOTES //
///////////

// ENDIANNESS & BYTE PORTABILIY:
// Electrum's mnemonic generation handles entropy in an 11-bit word little-endian manner, while we handle entropy in a
// big-endian manner. This means that if you take the bytes from BST and just throw them in Electrum's source (because
// Electrum doesn't allow manual entropy input), you won't get the same result. The bytes should instead be converted
// to a binary string, broken into 11 bit words, and the words should be reversed (eg: '11 10 01' becomes '01 10 11').
// Electrum also increments starting entropy, rather than trying to generate, THEN incrementing on failure; this means
// a valid mnemonic will be missed if you put in a valid mnemonic's bits.
//
// The result of all of this is that the mnemonic format implementation is fully compatible with Electrum, but the byte
// representations of those mnemonics are not. This isn't a big problem, because again, Electrum doesn't do anything
// user-facing with bytes. Big-endian treatment is preferable when bytes ARE exposed, as it makes manual verification
// simpler; for example, a string of coinflips represented in binary can be directly translated into the resulting
// words in a mnemonic, save for checksums. In the Electrum mnemonic format, this means all of the words except
// those at the end affected by incrementing for matching HMAC version bits will be exactly what you would
// expect at a glance, given that string of coinflips:
//
// Ignoring the HMAC iterations, '00000000000 00000000001 00000000010...' will become 'abandon ability able...' in BST,
// while in Electrum, it becomes '...able ability abandon'.

// WORD LISTS:
// Electrum currently only generates mnemonics using the BIP 39 word list. We will always need to use SOME word list to
// generate mnemonics; we can add additional programs, or modify the existing program if we want to support other word lists.
// We may wish to support the Diceware wordlist(s) for Electrum mnemonic generation, for example.
//
// Technically any string, even without a defined word list, can be a valid Electrum mnemonic, as long as its hash
// results in valid version bits. Without a defined word list encoding, however, we cannot retrieve the entropy which
// was used to generate the mnemonic. We can support such mnemonics for seed derivation, but we can't extract the entropy.

mod legacy_word_list;
mod mnemonic_version;

pub use mnemonic_version::ElectrumMnemonicVersion;

use super::{
    bip_39::{try_read_mnemonic_bytes, BITS_PER_WORD},
    format_mnemonic_string_utf8, try_get_bit_start_offset,
};
use crate::{
    bitcoin::mnemonics::{
        bip_39::{try_get_word, try_parse_bip39_mnemonic, Bip39MnemonicParsingResult},
        electrum::mnemonic_version::{mnemonic_prefix_validator, MNEMONIC_VERSION_HMAC_KEY},
        try_get_bit_at_index, try_set_bit_at_index,
    },
    hashing::{Hasher, Hmac, Sha512},
    integers::ceil,
    String16,
};
use alloc::{boxed::Box, vec, vec::Vec};
use macros::s16;

pub const EXTENSION_PREFIX: &[u8] = "electrum".as_bytes();
pub const SEED_DERIVATION_PBKDF_ITERATIONS: u32 = 2048;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum ElectrumMnemonicLength {
    Twelve,
    Fifteen,
    Eighteen,
    TwentyOne,
    TwentyFour,
}

impl Into<usize> for ElectrumMnemonicLength {
    fn into(self) -> usize {
        match self {
            ElectrumMnemonicLength::Twelve => 12,
            ElectrumMnemonicLength::Fifteen => 15,
            ElectrumMnemonicLength::Eighteen => 18,
            ElectrumMnemonicLength::TwentyOne => 21,
            ElectrumMnemonicLength::TwentyFour => 24,
        }
    }
}

impl Into<String16<'static>> for ElectrumMnemonicLength {
    fn into(self) -> String16<'static> {
        match self {
            ElectrumMnemonicLength::Twelve => s16!("Twelve Word"),
            ElectrumMnemonicLength::Fifteen => s16!("Fifteen Word"),
            ElectrumMnemonicLength::Eighteen => s16!("Eighteen Word"),
            ElectrumMnemonicLength::TwentyOne => s16!("Twenty One Word"),
            ElectrumMnemonicLength::TwentyFour => s16!("Twenty Four Word"),
        }
    }
}

const AVAILABLE_MNEMONIC_LENGTHS: [ElectrumMnemonicLength; 5] = [
    ElectrumMnemonicLength::Twelve,
    ElectrumMnemonicLength::Fifteen,
    ElectrumMnemonicLength::Eighteen,
    ElectrumMnemonicLength::TwentyOne,
    ElectrumMnemonicLength::TwentyFour,
];

pub fn get_available_mnemonic_lengths(byte_count: usize) -> &'static [ElectrumMnemonicLength] {
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

#[allow(dead_code)]
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum ElectrumMnemonicParsingResult<'a> {
    InvalidLength,
    InvalidWordEncountered(ElectrumMnemonicLength, String16<'a>, usize),
    OldFormat(ElectrumMnemonicLength, Box<[u8]>),
    InvalidVersion(ElectrumMnemonicLength, Box<[u8]>, [u8; 2]),
    Bip39(ElectrumMnemonicLength, Box<[u8]>, ElectrumMnemonicVersion),
    Valid(ElectrumMnemonicLength, Box<[u8]>, ElectrumMnemonicVersion),
}

pub fn required_bits_of_entropy_for_mnemonic_length(
    mnemonic_length: ElectrumMnemonicLength,
) -> usize {
    Into::<usize>::into(mnemonic_length) * (BITS_PER_WORD as usize)
}

pub fn required_bytes_of_entropy_for_mnemonic_length(
    mnemonic_length: ElectrumMnemonicLength,
) -> usize {
    ceil(required_bits_of_entropy_for_mnemonic_length(mnemonic_length) as f64 / 8f64)
}

#[allow(dead_code)]
pub fn try_generate_electrum_mnemonic(
    bytes: &[u8],
    mnemonic_length: ElectrumMnemonicLength,
    mnemonic_version: ElectrumMnemonicVersion,
) -> Result<(Vec<String16<'static>>, usize), String16<'static>> {
    // Don't generate 2FA mnemonics.
    match mnemonic_version {
        ElectrumMnemonicVersion::Legacy | ElectrumMnemonicVersion::Segwit => {}
        _ => {
            return Err(s16!(
                "Electrum 2FA mnemonic generation is not supported; Electrum's 2FA is bad."
            ))
        }
    };

    // Calculate required bit and byte counts.
    let word_count: usize = mnemonic_length.into();
    let required_bits = required_bits_of_entropy_for_mnemonic_length(mnemonic_length);
    let required_bytes = required_bytes_of_entropy_for_mnemonic_length(mnemonic_length);

    if required_bytes > bytes.len() {
        return Err(s16!(
            "Not enough bytes of entropy were provided for the specified mnemonic length."
        ));
    }

    // Use the trailing bytes.
    let used_bytes = &bytes[bytes.len() - required_bytes..];

    // Create a buffer for iterative Electrum mnemonic generation.
    let mut increment_buffer = vec![0u8; used_bytes.len()];
    increment_buffer.copy_from_slice(&used_bytes);

    // Zero the unused bits at the beginning of the buffer.
    let start_bit_offset = try_get_bit_start_offset(required_bits, required_bytes).unwrap();
    for i in 0..start_bit_offset {
        assert!(try_set_bit_at_index(i, false, &mut increment_buffer))
    }

    let mut difference_from_entropy = 0;
    let mut hasher = Sha512::new();
    let mut words = Vec::with_capacity(word_count);
    let mut hmac = hasher.build_hmac(MNEMONIC_VERSION_HMAC_KEY);
    loop {
        // Read the words from the buffer.
        for i in 0..word_count {
            let word = try_get_word(start_bit_offset, i, &increment_buffer).unwrap();
            words.push(word);
        }

        match try_parse_bip39_mnemonic(&words) {
            // Electrum mnemonics can't also be valid BIP39 mnemonics.
            Bip39MnemonicParsingResult::Valid(_, _, _) => {}
            _ => {
                if !is_valid_in_old_electrum_format(&words)
                    && generated_mnemonic_is_valid(&words, &mut hmac, mnemonic_version).is_some()
                {
                    return Ok((words, difference_from_entropy));
                }
            }
        };

        // Reset the words and do another iteration.
        words.clear();

        // We need to change the entropy a little to have a chance at the next iteration succeeding;
        // Electrum achieves this by incrementing the entropy, so we'll do the same here.
        let mut i = required_bits + start_bit_offset;
        difference_from_entropy += 1;

        // Find the first zero bit from right to left.
        while i > start_bit_offset && try_get_bit_at_index(i - 1, &increment_buffer).unwrap() {
            // Zero all the bits leading up to the first zero bit.
            assert!(try_set_bit_at_index(i - 1, false, &mut increment_buffer));
            i -= 1;
        }

        if i == start_bit_offset {
            // We ran out of increment space; all the bits are 1. The user did something stupid.
            return Err(s16!(
                "Mnemonic generation failed due to integer overflow; your entropy was bad."
            ));
        }

        // Set the first zero bit to high; we've successfully incremented the buffer.
        assert!(try_set_bit_at_index(i - 1, true, &mut increment_buffer));
    }
}

#[allow(dead_code)]
pub fn try_parse_electrum_mnemonic<'a>(
    words: &Vec<String16<'a>>,
) -> ElectrumMnemonicParsingResult<'a> {
    // Get the mnemonic length.
    let mnemonic_length = match words.len() {
        24 => ElectrumMnemonicLength::TwentyFour,
        21 => ElectrumMnemonicLength::TwentyOne,
        18 => ElectrumMnemonicLength::Eighteen,
        15 => ElectrumMnemonicLength::Fifteen,
        12 => ElectrumMnemonicLength::Twelve,
        // Words has an invalid length.
        _ => return ElectrumMnemonicParsingResult::InvalidLength,
    };

    let bytes = match try_extract_mnemonic_bytes(mnemonic_length, &words) {
        Err((w, i)) => {
            return ElectrumMnemonicParsingResult::InvalidWordEncountered(mnemonic_length, w, i)
        }
        Ok(b) => b,
    };

    // Perform the verson-bits HMAC.
    let hmac = perform_hmac_on_electrum_mnemonic(
        &mut Sha512::new().build_hmac(MNEMONIC_VERSION_HMAC_KEY),
        &words,
    );

    for version in &[
        ElectrumMnemonicVersion::Legacy,
        ElectrumMnemonicVersion::Segwit,
        ElectrumMnemonicVersion::Legacy2FA,
        ElectrumMnemonicVersion::Segwit2FA,
    ] {
        let validator = mnemonic_prefix_validator(*version);
        if (validator)(&hmac) {
            return match try_parse_bip39_mnemonic(&words) {
                Bip39MnemonicParsingResult::Valid(..) => {
                    ElectrumMnemonicParsingResult::Bip39(mnemonic_length, bytes, *version)
                }
                _ => {
                    if is_valid_in_old_electrum_format(&words) {
                        ElectrumMnemonicParsingResult::OldFormat(mnemonic_length, bytes)
                    } else {
                        ElectrumMnemonicParsingResult::Valid(mnemonic_length, bytes, *version)
                    }
                }
            };
        }
    }

    let mut version_bytes = [0u8; 2];
    version_bytes.copy_from_slice(&hmac[..2]);
    ElectrumMnemonicParsingResult::InvalidVersion(mnemonic_length, bytes, version_bytes)
}

fn is_valid_in_old_electrum_format<'a>(words: &Vec<String16<'a>>) -> bool {
    // The old, deprecated Electrum mnemonic format has word overlap with the BIP 39 word list.
    // It's therefore possible for this process to accidentally generate an old Electrum mnemonic.
    // For an Electrum mnemonic to be valid according to the new format, it must not be a valid old format mnemonic.
    words.iter().all(|w| {
        legacy_word_list::WORDS
            .binary_search_by(|o| o.content_slice().cmp(w.content_slice()))
            .is_ok()
    })
}

fn perform_hmac_on_electrum_mnemonic<'a>(
    hmac: &mut Hmac<64, 128, Sha512>,
    words: &Vec<String16<'a>>,
) -> [u8; 64] {
    // Format a mnemonic string in UTF8.
    let mut mnemonic_string = format_mnemonic_string_utf8(&words, s16!(" "));

    // Get the HMAC result.
    let result = hmac.get_hmac(&mnemonic_string);

    // Pre-emptively fill the mnemonic string.
    mnemonic_string.fill(0);

    result
}

fn generated_mnemonic_is_valid(
    words: &Vec<String16<'static>>,
    hmac: &mut Hmac<64, 128, Sha512>,
    mnemonic_version: ElectrumMnemonicVersion,
) -> Option<[u8; 64]> {
    let hmac = perform_hmac_on_electrum_mnemonic(hmac, words);

    // Check the mnemonic's HMAC against the mnemonic version prefix.
    if (mnemonic_prefix_validator(mnemonic_version))(&hmac) {
        Some(hmac)
    } else {
        None
    }
}

fn try_extract_mnemonic_bytes<'a>(
    mnemonic_length: ElectrumMnemonicLength,
    words: &Vec<String16<'a>>,
) -> Result<Box<[u8]>, (String16<'a>, usize)> {
    let mnemonic_byte_count = required_bytes_of_entropy_for_mnemonic_length(mnemonic_length);
    let mnemonic_bit_count = required_bits_of_entropy_for_mnemonic_length(mnemonic_length);
    match try_read_mnemonic_bytes(mnemonic_byte_count, mnemonic_bit_count, words) {
        Err((w, i)) => return Err((w, i)),
        Ok((_, b)) => Ok(b.into()),
    }
}