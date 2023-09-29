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

use crate::characters::Character;
use alloc::vec::Vec;
use macros::{c16, u16_array};

// Non-decomposing characters to avoid needing NKDF normalization implementation.
const ALLOWED_MNEMONIC_TEXT_CHARACTER: [u16; 102] =
    u16_array!("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ \"'()+=-_[]{};:#@~,.<>/\\|%^&*¬`!¡?¿₿€£$¥");

pub fn allow_mnemonic_text_character(character: u16) -> bool {
    ALLOWED_MNEMONIC_TEXT_CHARACTER
        .iter()
        .position(|c| *c == character)
        .is_some()
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct MnemonicTextNormalizationSettings {
    lowercase_characters: bool,
    collapse_whitespace: bool,
    trim_whitespace: bool,
}

impl MnemonicTextNormalizationSettings {
    pub const fn from(
        lowercase_characters: bool,
        collapse_whitespace: bool,
        trim_whitespace: bool,
    ) -> Self {
        Self {
            lowercase_characters,
            collapse_whitespace,
            trim_whitespace,
        }
    }

    pub fn normalize_text(&self, text: &mut Vec<u16>) {
        if self.trim_whitespace {
            // If we want to trim whitespace, start at the beginning, and remove any whitespace.
            while text.len() > 0 {
                if text[0].is_whitespace() {
                    text.remove(0);
                } else {
                    // If we encounter any non-whitespace character, we can stop.
                    break;
                }
            }

            if text.len() == 0 {
                // If we've emptied the vector by trimming whitespace (it was entirely filled with whitespace), we can return.
                return;
            }

            // Now we can check the end.
            while text[text.len() - 1].is_whitespace() {
                text.pop();
            }
        }

        let mut index = 0;
        while index < text.len() {
            let character = text[index];
            if !allow_mnemonic_text_character(character) {
                // If the character isn't allowed, get rid of it;
                // we shouldn't hit this in reality as we should sanitize at input time.
                text.remove(index);

                // We want to check this index again, because we just removed the character at this index, so continue.
                continue;
            }

            if self.collapse_whitespace && character.is_whitespace() {
                // We've encountered a whitespace character, and we want to collapse whitespace.
                while index < text.len() - 1 && text[index + 1].is_whitespace() {
                    // Collapse any whitespace immediately following this character until there's none left.
                    text.remove(index + 1);
                }
            }

            if self.lowercase_characters {
                // Swap the character at the current index with its lowercase variant.
                text[index] = if character >= c16!("A") && character <= c16!("Z") {
                    // UTF 8 'A' is 0x41, and 'a' is 0x61. A-Z and a-z are uninterrupted, and in order.
                    character + 0x20
                } else {
                    character
                }
            }

            index += 1;
        }
    }
}
