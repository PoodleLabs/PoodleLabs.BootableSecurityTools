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

use super::{build_utf8_mnemonic_string, MnemonicTextNormalizationSettings};
use crate::{
    hashing::{Hasher, Sha512},
    String16,
};
use alloc::vec::Vec;
use macros::s16;

// Used to 'zero' mnemonic word vectors.
const BLANK_STRING: String16 = s16!("");

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bip32DevivationSettings {
    text_normalization: MnemonicTextNormalizationSettings,
    word_space_characters: String16<'static>,
    salt_prefix: &'static [u8],
    pbkdf2_iterations: u32,
}

impl Bip32DevivationSettings {
    pub const fn from(
        text_normalization: MnemonicTextNormalizationSettings,
        word_space_characters: String16<'static>,
        salt_prefix: &'static [u8],
        pbkdf2_iterations: u32,
    ) -> Self {
        Self {
            word_space_characters,
            text_normalization,
            pbkdf2_iterations,
            salt_prefix,
        }
    }

    pub fn derive_hd_wallet_seed(
        &self,
        mut extension_phrase: Vec<u16>,
        mut mnemonic: Vec<String16<'static>>,
    ) -> [u8; Sha512::HASH_SIZE] {
        // Prepare the output buffer.
        let mut output = [0u8; Sha512::HASH_SIZE];
        {
            // Normalize the extension phrase.
            self.text_normalization
                .normalize_text(&mut extension_phrase);

            // String16 for operating on the extension phrase.
            let extension_string = String16::from(&extension_phrase);

            // Build a UTF8 encoded mnemonic string.
            let mut mnemonic_string =
                build_utf8_mnemonic_string(self.word_space_characters, &mnemonic);

            // Prepare a UTF8 buffer for the salt.
            let mut salt =
                Vec::with_capacity(self.salt_prefix.len() + extension_string.utf8_content_length());

            // Salts are prefixed, eg: utf8'mnemonic', or utf8'electrum'.
            salt.extend(self.salt_prefix);

            // Write the extension phrase to the salt buffer.
            extension_string.write_content_to_utf8_vec(&mut salt);
            extension_phrase.fill(0);

            // Prepare the HMAC.
            let mut hasher = Sha512::new();
            let mut hmac = hasher.build_hmac(&mnemonic_string);
            mnemonic_string.fill(0);

            // Perform the PBKDF and write to the output buffer.
            hmac.pbkdf2(&salt, self.pbkdf2_iterations, &mut output);

            // Pre-emptively fill all remaining sensitive material.
            mnemonic.fill(BLANK_STRING);
            hasher.reset();
            salt.fill(0);
        }

        output
    }
}
