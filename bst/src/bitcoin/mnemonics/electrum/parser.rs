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

use super::{
    try_parse_electrum_mnemonic, MnemonicLength, MnemonicParsingResult, BIP_32_DERIVATION_SETTINGS,
    MNEMONIC_FORMAT,
};
use crate::{
    bitcoin::mnemonics::{Bip32DevivationSettings, MnemonicFormat, MnemonicParseResult},
    String16,
};
use alloc::{boxed::Box, vec::Vec};

pub struct MnemonicParser;

impl crate::bitcoin::mnemonics::MnemonicParser for MnemonicParser {
    type TParseResult = MnemonicParsingResult<'static>;
    type TMnemonicLength = MnemonicLength;

    fn try_parse_mnemonic(&self, words: &Vec<String16<'static>>) -> Self::TParseResult {
        try_parse_electrum_mnemonic(&words)
    }

    fn mnemonic_format(&self) -> MnemonicFormat<Self::TMnemonicLength> {
        MNEMONIC_FORMAT
    }

    fn bip_32_derivation_settings(&self) -> Bip32DevivationSettings {
        BIP_32_DERIVATION_SETTINGS
    }
}

impl<'a> MnemonicParseResult for MnemonicParsingResult<'a> {
    fn can_derive_bip_32_seed(&self) -> bool {
        match self {
            MnemonicParsingResult::Valid(..) => true,
            _ => false,
        }
    }

    fn get_bytes(self) -> Option<Box<[u8]>> {
        match self {
            MnemonicParsingResult::InvalidVersion(_, bytes, _) => Some(bytes),
            MnemonicParsingResult::OldFormat(_, bytes) => Some(bytes),
            MnemonicParsingResult::Bip39(_, bytes, _) => Some(bytes),
            MnemonicParsingResult::Valid(_, bytes, _) => Some(bytes),
            _ => None,
        }
    }

    fn can_get_bytes(&self) -> bool {
        match self {
            MnemonicParsingResult::InvalidVersion(..) => true,
            MnemonicParsingResult::OldFormat(..) => true,
            MnemonicParsingResult::Bip39(..) => true,
            MnemonicParsingResult::Valid(..) => true,
            _ => false,
        }
    }
}
