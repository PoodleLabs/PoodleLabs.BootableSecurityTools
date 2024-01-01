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

use alloc::vec::Vec;
use macros::c16;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CaseFlags(u8);

impl CaseFlags {
    pub const fn extension_is_lowercase(&self) -> bool {
        (self.0 & 0x10) != 0
    }

    pub const fn name_is_lowercase(&self) -> bool {
        (self.0 & 0x08) != 0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FreeIndicator {
    NotFree,
    IsolatedFree,
    FreeAndAllSubsequentEntriesFree,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name([u8; 11]);

impl Name {
    pub const TAIL_PADDING_CHARACTER: u8 = 0x20;

    pub const fn free_indicator(&self) -> FreeIndicator {
        match self.0[0] {
            0x00 => FreeIndicator::FreeAndAllSubsequentEntriesFree,
            0xE5 => FreeIndicator::IsolatedFree,
            _ => FreeIndicator::NotFree,
        }
    }

    pub const fn get_characters(&self) -> Option<[u8; 11]> {
        match self.free_indicator() {
            FreeIndicator::NotFree => Some(self.0),
            _ => None,
        }
    }

    pub fn trim_trailing_padding(content: &[u8]) -> &[u8] {
        let mut len = content.len();
        while len > 0 {
            if content[len - 1] != Self::TAIL_PADDING_CHARACTER {
                break;
            }

            len -= 1;
        }

        &content[..len]
    }

    pub fn get_extension_characters(&self) -> Option<&[u8]> {
        match self.free_indicator() {
            FreeIndicator::NotFree => Some(&self.0[8..]),
            _ => None,
        }
    }

    pub fn get_name_characters(&self) -> Option<&[u8]> {
        match self.free_indicator() {
            FreeIndicator::NotFree => Some(&self.0[..8]),
            _ => None,
        }
    }

    pub fn is_valid(&self) -> bool {
        if self.free_indicator() != FreeIndicator::NotFree {
            return true;
        }

        let name = Self::trim_trailing_padding(self.get_name_characters().unwrap());
        let extension = Self::trim_trailing_padding(self.get_extension_characters().unwrap());
        if name.len() + extension.len() == 0 {
            return false;
        }

        // The complete file name must contain at least one character.
        (name.len() + extension.len() > 0)
            && Self::part_is_valid(name)
            && Self::part_is_valid(extension)
    }

    pub fn build_string(&self, null_terminate: bool) -> Option<Vec<u16>> {
        if self.free_indicator() != FreeIndicator::NotFree {
            return None;
        }

        let name = Self::trim_trailing_padding(self.get_name_characters().unwrap());
        let extension = Self::trim_trailing_padding(self.get_extension_characters().unwrap());

        // Prepare a vec with space for all characters, plus a null terminating character if necessary,
        // and a dot if there is a file extension.
        let mut vec = Vec::with_capacity(
            name.len()
                + extension.len()
                + if extension.len() > 0 { 1 } else { 0 }
                + if null_terminate { 1 } else { 0 },
        );

        vec.extend(name.iter().map(|c| *c as u16));
        if extension.len() > 0 {
            vec.push(c16!("."));
            vec.extend(extension.iter().map(|c| *c as u16));
        }

        if null_terminate {
            vec.push(0);
        }

        Some(vec)
    }

    pub fn checksum(&self) -> u8 {
        let mut sum = 0u8;
        for i in 0..11 {
            sum = (sum >> 1) + (sum << 7) + self.0[i];
        }

        sum
    }

    fn part_is_valid(value: &[u8]) -> bool {
        // The part must have a length of 0
        value.len() == 0
            // Or exclusively contain allowable characters.
            || value
                .iter()
                .all(|c| *c >= 0x80 || (b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()-@^_`{}~").contains(c))
    }
}
