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

use macros::c16;

pub trait Character: Clone + Copy + Eq + PartialEq {
    fn is_whitespace(self) -> bool;

    fn is_printable(self) -> bool;

    fn is_newline(self) -> bool;
}

impl Character for u16 {
    fn is_whitespace(self) -> bool {
        self.is_newline() || self == c16!("\t") || self == c16!(" ")
    }

    fn is_printable(self) -> bool {
        // Numeric value >= space character and it's not the delete character, or it's whitespace
        (self >= c16!(" ") && self != c16!("\u{007F}")) || self.is_whitespace()
    }

    fn is_newline(self) -> bool {
        self == c16!("\r") || self == c16!("\n")
    }
}
