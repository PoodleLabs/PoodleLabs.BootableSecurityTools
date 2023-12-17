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

use crate::file_systems::fat::objects::DirectoryEntryAttributes;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongFileNameOrdering(u8);

impl LongFileNameOrdering {
    pub const fn is_end(&self) -> bool {
        (self.0 & 0x40) != 0
    }

    pub const fn value(&self) -> u8 {
        self.0 & 0b00011111
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongFileNamePart1([u8; 10]); // Five UTF-16 characters.

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongFileNamePart2([u8; 12]); // Six UTF-16 characters.

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongFileNamePart3([u8; 4]); // Two UTF-16 characters.

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongFileNameDirectoryEntry {
    ordering: LongFileNameOrdering,
    part_1: LongFileNamePart1,
    attribute: DirectoryEntryAttributes, // Always 0x0F: Long File Name Entry.
    entry_type: u8,                      // Always 0.
    sfn_checksum: u8,                    // Checksum of associated SFN entry.
    part_2: LongFileNamePart2,
    cluster_low: [u8; 2], // Always 0
    part_3: LongFileNamePart3,
}

impl LongFileNameDirectoryEntry {
    pub const PADDING_CHARACTER: u16 = 0xFFFF;

    pub const fn ordering(&self) -> &LongFileNameOrdering {
        &self.ordering
    }

    pub fn content_characters_from_raw_characters(characters: &[u16; 13]) -> &[u16] {
        match characters.iter().enumerate().find(|(_, c)| **c == 0) {
            Some((i, _)) => &characters[..i],
            None => &characters[..],
        }
    }

    pub fn is_valid(&self, expected_sfn_checksum: u8, expected_order_value: u8) -> bool {
        let raw_characters = self.raw_characters();
        let content_slice = Self::content_characters_from_raw_characters(&raw_characters);
        // The SFN checksum must be correct.
        self.sfn_checksum == expected_sfn_checksum
            // The ordering value must be correct.
            && self.ordering.value() == expected_order_value
            // The attribute must be correct.
            && self.attribute.is_long_file_name_entry()
            // The entry type must be zero.
            && self.entry_type == 0
            // The cluster_low value must be zero.
            && u16::from_le_bytes(self.cluster_low) == 0
            // Entry is either filled with content, or with content and a single null terminating character.
            && (content_slice.len() >= raw_characters.len() - 1
            // Or all of the characters after the null terminator are the correct padding character.
                || raw_characters[content_slice.len() + 1..]
                    .iter()
                    .all(|c| Self::PADDING_CHARACTER.eq(c)))
    }

    pub fn raw_characters(&self) -> [u16; 13] {
        let mut characters = [0u16; 13];
        Self::extract_chars_from_part(&mut characters, &self.part_1.0, 0);
        Self::extract_chars_from_part(&mut characters, &self.part_2.0, 5);
        Self::extract_chars_from_part(&mut characters, &self.part_3.0, 11);
        characters
    }

    fn extract_chars_from_part<const N: usize>(
        characters: &mut [u16; 13],
        part: &[u8; N],
        offset: usize,
    ) {
        let mut single_character_buffer = [0u8; 2];
        for i in 0..N {
            single_character_buffer[0] = part[i * 2];
            single_character_buffer[1] = part[(i * 2) + 1];
            characters[i + offset] = u16::from_le_bytes(single_character_buffer);
        }
    }
}
