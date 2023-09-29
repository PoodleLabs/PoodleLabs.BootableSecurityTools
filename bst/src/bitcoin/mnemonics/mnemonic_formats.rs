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

use super::MnemonicWordList;
use crate::String16;

pub trait MnemonicLength: Copy + Into<usize> + Into<String16<'static>> + 'static {}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct MnemonicFormat<TMnemonicLength: MnemonicLength> {
    get_available_lengths_for_byte_count: fn(usize) -> &'static [TMnemonicLength],
    minimum_bytes_of_entropy: String16<'static>,
    word_list: MnemonicWordList,
    name: String16<'static>,
    max_words: usize,
}

impl<TMnemonicLength: MnemonicLength> MnemonicFormat<TMnemonicLength> {
    pub const fn from(
        get_available_lengths_for_byte_count: fn(usize) -> &'static [TMnemonicLength],
        minimum_bytes_of_entropy: String16<'static>,
        word_list: MnemonicWordList,
        name: String16<'static>,
        max_words: usize,
    ) -> Self {
        Self {
            get_available_lengths_for_byte_count,
            minimum_bytes_of_entropy,
            word_list,
            max_words,
            name,
        }
    }

    pub const fn minimum_bytes_of_entropy(&self) -> String16 {
        self.minimum_bytes_of_entropy
    }

    pub const fn word_list(&self) -> MnemonicWordList {
        self.word_list
    }

    pub const fn max_words(&self) -> usize {
        self.max_words
    }

    pub const fn name(&self) -> String16 {
        self.name
    }

    pub fn get_available_lengths_for_byte_count(&self, byte_count: usize) -> &[TMnemonicLength] {
        (self.get_available_lengths_for_byte_count)(byte_count)
    }
}
