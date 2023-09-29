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

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum MnemonicLength {
    Twelve,
    Fifteen,
    Eighteen,
    TwentyOne,
    TwentyFour,
}

impl Into<usize> for MnemonicLength {
    fn into(self) -> usize {
        match self {
            MnemonicLength::Twelve => 12,
            MnemonicLength::Fifteen => 15,
            MnemonicLength::Eighteen => 18,
            MnemonicLength::TwentyOne => 21,
            MnemonicLength::TwentyFour => 24,
        }
    }
}

impl Into<String16<'static>> for MnemonicLength {
    fn into(self) -> String16<'static> {
        match self {
            MnemonicLength::Twelve => s16!("Twelve Word"),
            MnemonicLength::Fifteen => s16!("Fifteen Word"),
            MnemonicLength::Eighteen => s16!("Eighteen Word"),
            MnemonicLength::TwentyOne => s16!("Twenty One Word"),
            MnemonicLength::TwentyFour => s16!("Twenty Four Word"),
        }
    }
}

impl crate::bitcoin::mnemonics::MnemonicLength for MnemonicLength {}
