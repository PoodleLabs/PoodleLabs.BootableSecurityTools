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

use super::{try_get_bit_at_index, try_get_bit_start_offset};
use crate::{bitcoin::mnemonics::try_set_bit_at_index, String16};
use alloc::{vec, vec::Vec};

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct MnemonicWordList {
    words: &'static [String16<'static>],
    longest_word_length: usize,
    name: String16<'static>,
    bits_per_word: usize,
}

impl MnemonicWordList {
    pub const fn from(
        words: &'static [String16<'static>],
        longest_word_length: usize,
        name: String16<'static>,
        bits_per_word: usize,
    ) -> Self {
        Self {
            longest_word_length,
            bits_per_word,
            words,
            name,
        }
    }

    pub const fn words(&self) -> &[String16<'static>] {
        self.words
    }

    pub const fn longest_word_length(&self) -> usize {
        self.longest_word_length
    }

    pub const fn bits_per_word(&self) -> usize {
        self.bits_per_word
    }

    pub const fn name(&self) -> String16 {
        self.name
    }

    pub fn try_get_word(
        &self,
        start_bit_offset: usize,
        word_number: usize,
        bytes: &[u8],
    ) -> Option<String16<'static>> {
        if self.bits_per_word > 64 {
            // We unwrap into a usize so we can index a word list; we can't support more than 64 bits per word.
            // It's OK though... there's not that many words.
            return None;
        }

        let start = start_bit_offset + (word_number * (self.bits_per_word));
        let end = start + (self.bits_per_word);
        if end > bytes.len() * 8 {
            return None;
        }

        let mut index = 0usize;
        for i in start..end {
            // Read the bits one at a time into the index; we're just building up a base 2 number.
            index *= 2;
            index += try_get_bit_at_index(i, bytes).unwrap() as usize;
        }

        Some(self.words[index])
    }

    pub fn try_read_mnemonic_bytes<'a>(
        &self,
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
            let word = match self
                .words
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
                try_get_bit_start_offset(self.bits_per_word, word.len()).unwrap();

            // Write the word's bits to the mnemonic byte buffer.
            for j in 0..self.bits_per_word {
                assert!(try_set_bit_at_index(
                    mnemonic_bit_start_offset + (i * self.bits_per_word) + j,
                    try_get_bit_at_index(word_bit_start_offset + j, &word).unwrap(),
                    &mut mnemonic_bytes,
                ));
            }
        }

        Ok((mnemonic_bit_start_offset, mnemonic_bytes))
    }
}
