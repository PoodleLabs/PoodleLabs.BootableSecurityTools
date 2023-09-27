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

use super::console::ConsoleWriteable;
use crate::{console_out::ConsoleOut, integers::BigInteger};
use alloc::vec::Vec;
use macros::s16;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum DataInputType {
    Text,
    Bytes,
    Number,
}

impl ConsoleWriteable for DataInputType {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console.output_utf16(match self {
            DataInputType::Text => s16!("Text"),
            DataInputType::Bytes => s16!("Bytes"),
            DataInputType::Number => s16!("Number"),
        });
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum DataInput {
    None,
    Text(Vec<u16>),
    Bytes(Vec<u8>),
    Number(BigInteger),
}
