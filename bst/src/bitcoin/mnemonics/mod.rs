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

mod bip_32_derivation;
mod mnemonic_formats;
mod mnemonic_text_normalization;
mod word_lists;

pub use bip_32_derivation::Bip32DevivationSettings;
pub use mnemonic_formats::{MnemonicFormat, MnemonicLength};
pub use mnemonic_text_normalization::{
    allow_mnemonic_text_character, MnemonicTextNormalizationSettings,
};
pub use word_lists::MnemonicWordList;

use crate::String16;
use alloc::{boxed::Box, vec::Vec};

pub trait MnemonicParser {
    type TParseResult: MnemonicParseResult;
    type TMnemonicLength: MnemonicLength;

    fn try_parse_mnemonic(&self, words: &Vec<String16<'static>>) -> Self::TParseResult;

    fn mnemonic_format(&self) -> MnemonicFormat<Self::TMnemonicLength>;

    fn bip_32_derivation_settings(&self) -> Bip32DevivationSettings;
}

pub trait MnemonicParseResult {
    fn can_derive_bip_32_seed(&self) -> bool;

    fn get_bytes(self) -> Option<Box<[u8]>>;

    fn can_get_bytes(&self) -> bool;
}

fn build_utf8_mnemonic_string<'a>(
    word_space_characters: String16<'a>,
    mnemonic: &Vec<String16<'a>>,
) -> Vec<u8> {
    // No words, no output.
    if mnemonic.len() == 0 {
        return Vec::with_capacity(0);
    }

    // Count the total number of characters required.
    let words_character_count: usize = mnemonic.iter().map(|w| w.utf8_content_length()).sum();
    let space_character_count = (mnemonic.len() - 1) * word_space_characters.utf8_content_length();

    // Prepare a buffer, then fill it one word at a time.
    let mut mnemonic_string = Vec::with_capacity(space_character_count + words_character_count);
    for i in 0..(mnemonic.len() - 1) {
        // Copy the word into the buffer.
        mnemonic[i].write_content_to_utf8_vec(&mut mnemonic_string);

        // Space after every word but the last.
        word_space_characters.write_content_to_utf8_vec(&mut mnemonic_string);
    }

    // Last word, no space.
    mnemonic[mnemonic.len() - 1].write_content_to_utf8_vec(&mut mnemonic_string);
    mnemonic_string
}
