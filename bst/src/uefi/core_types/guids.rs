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

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiGuid {
    time_low: u32,
    time_mid: u16,
    time_high_and_version: u16,
    clock_seq_high_and_reserved: u8,
    clock_seq_low: u8,
    node: [u8; 6],
}

impl UefiGuid {
    pub const fn from(
        time_low: u32,
        time_mid: u16,
        time_high_and_version: u16,
        clock_seq_high_and_reserved: u8,
        clock_seq_low: u8,
        node: [u8; 6],
    ) -> Self {
        Self {
            time_low,
            time_mid,
            time_high_and_version,
            clock_seq_high_and_reserved,
            clock_seq_low,
            node,
        }
    }
}
