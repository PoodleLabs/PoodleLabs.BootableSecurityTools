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

use crate::String16;
use macros::s16;

pub const MNEMONIC_VERSION_HMAC_KEY: &[u8] = "Seed version".as_bytes();

#[repr(u16)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum MnemonicVersion {
    Legacy = 0b0000000000000000,
    Segwit = 0b0000000000000001,
    Legacy2FA = 0b1000000000000000,
    Segwit2FA = 0b1000000000000001,
}

impl Into<String16<'static>> for MnemonicVersion {
    fn into(self) -> String16<'static> {
        match self {
            MnemonicVersion::Legacy => s16!("Legacy"),
            MnemonicVersion::Segwit => s16!("Segwit"),
            MnemonicVersion::Legacy2FA => s16!("Legacy 2FA"),
            MnemonicVersion::Segwit2FA => s16!("Segwit 2FA"),
        }
    }
}

pub const fn mnemonic_prefix_validator(
    mnemonic_version: MnemonicVersion,
) -> fn(bytes: &[u8]) -> bool {
    match mnemonic_version {
        MnemonicVersion::Legacy => legacy_prefix_validator,
        MnemonicVersion::Segwit => segwit_prefix_validator,
        MnemonicVersion::Legacy2FA => legacy_2fa_prefix_validator,
        MnemonicVersion::Segwit2FA => segwit_2fa_prefix_validator,
    }
}

fn legacy_prefix_validator(bytes: &[u8]) -> bool {
    bytes.len() > 0 && bytes[0] == 1
}

fn segwit_prefix_validator(bytes: &[u8]) -> bool {
    bytes.len() > 1 && bytes[0] == 16 && bytes[1] < 16
}

fn legacy_2fa_prefix_validator(bytes: &[u8]) -> bool {
    bytes.len() > 1 && bytes[0] == 16 && bytes[1] > 15 && bytes[1] < 32
}

fn segwit_2fa_prefix_validator(bytes: &[u8]) -> bool {
    bytes.len() > 1 && bytes[0] == 16 && bytes[1] > 31 && bytes[1] < 48
}
