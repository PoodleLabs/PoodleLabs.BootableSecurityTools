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

use crate::bits::bit_field;
use alloc::vec::Vec;
use macros::c16;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FatDate([u8; 2]);

impl FatDate {
    pub const fn year(&self) -> u16 {
        (((self.0[0] & 0b11111110) >> 1) as u16) + 1980
    }

    pub const fn month(&self) -> u8 {
        ((self.0[0] & 0b00000001) << 3) | ((self.0[1] & 0b11100000) >> 5)
    }

    pub const fn day(&self) -> u8 {
        self.0[1] & 0b00011111
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FatTime2sResolution([u8; 2]);

impl FatTime2sResolution {
    pub const fn hour(&self) -> u8 {
        (self.0[0] & 0b11111000) >> 3
    }

    pub const fn minute(&self) -> u8 {
        ((self.0[0] & 0b00000111) << 3) | ((self.0[1] & 0b11100000) >> 5)
    }

    pub const fn second(&self) -> u8 {
        (self.0[1] & 0b00011111) * 2
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FatTime {
    sub_2s: u8, // Resolution of 10 milliseconds, 0-199 where 0 = 0, and 199 = 1.99s.
    main: FatTime2sResolution,
}

impl FatTime {
    pub const fn hour(&self) -> u8 {
        self.main.hour()
    }

    pub const fn minute(&self) -> u8 {
        self.main.minute()
    }

    pub const fn second(&self) -> u8 {
        self.main.second() + (self.sub_2s / 100)
    }

    pub const fn millisecond(&self) -> u16 {
        (self.sub_2s as u16 % 100) * 10
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DirectoryEntryAttributes(u8);

impl DirectoryEntryAttributes {
    pub const LONG_FILE_NAME_ENTRY: Self = Self(0x0F);
    pub const READ_ONLY: Self = Self(0x01);
    pub const HIDDEN: Self = Self(0x02);
    pub const SYSTEM: Self = Self(0x04);
    /// An entry with this attribute is the volume label. Only one entry can have this flag, in the root directory. Cluster and filesize values must all be set to zero.
    pub const VOLUME_LABEL: Self = Self(0x08);
    pub const DIRECTORY: Self = Self(0x10);
    /// A flag for backup utilities to detect changes. Should be set to 1 on any change, 0 by the backup utility on backup.
    pub const ARCHIVE: Self = Self(0x20);

    pub const fn is_long_file_name_entry(&self) -> bool {
        self.0 == Self::LONG_FILE_NAME_ENTRY.0
    }

    pub const fn is_read_only(&self) -> bool {
        self.encompasses(Self::READ_ONLY)
    }

    pub const fn is_hidden(&self) -> bool {
        self.overlaps(Self::HIDDEN)
    }

    pub const fn is_system_entry(&self) -> bool {
        self.overlaps(Self::SYSTEM)
    }

    pub const fn is_volume_label(&self) -> bool {
        self.overlaps(Self::VOLUME_LABEL)
    }

    pub const fn is_directory(&self) -> bool {
        self.overlaps(Self::DIRECTORY)
    }

    pub const fn updated_since_last_archive(&self) -> bool {
        self.overlaps(Self::ARCHIVE)
    }
}

bit_field!(DirectoryEntryAttributes);

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DirectoryEntryNameCaseFlags(u8);

impl DirectoryEntryNameCaseFlags {
    pub const fn extension_is_lowercase(&self) -> bool {
        (self.0 & 0x10) != 0
    }

    pub const fn name_is_lowercase(&self) -> bool {
        (self.0 & 0x08) != 0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ShortFileNameFreeIndicator {
    NotFree,
    IsolatedFree,
    FreeAndAllSubsequentEntriesFree,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortFileName([u8; 11]);

impl ShortFileName {
    pub const TAIL_PADDING_CHARACTER: u8 = 0x20;

    pub const fn free_indicator(&self) -> ShortFileNameFreeIndicator {
        match self.0[0] {
            0x00 => ShortFileNameFreeIndicator::FreeAndAllSubsequentEntriesFree,
            0xE5 => ShortFileNameFreeIndicator::IsolatedFree,
            _ => ShortFileNameFreeIndicator::NotFree,
        }
    }

    pub const fn get_characters(&self) -> Option<[u8; 11]> {
        match self.free_indicator() {
            ShortFileNameFreeIndicator::NotFree => Some(self.0),
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

    pub fn get_file_extension_characters(&self) -> Option<&[u8]> {
        match self.free_indicator() {
            ShortFileNameFreeIndicator::NotFree => Some(&self.0[8..]),
            _ => None,
        }
    }

    pub fn get_file_name_characters(&self) -> Option<&[u8]> {
        match self.free_indicator() {
            ShortFileNameFreeIndicator::NotFree => Some(&self.0[..8]),
            _ => None,
        }
    }

    pub fn is_valid(&self) -> bool {
        if self.free_indicator() != ShortFileNameFreeIndicator::NotFree {
            return true;
        }

        let name = Self::trim_trailing_padding(self.get_file_name_characters().unwrap());
        let extension = Self::trim_trailing_padding(self.get_file_extension_characters().unwrap());
        if name.len() + extension.len() == 0 {
            return false;
        }

        // The complete file name must contain at least one character.
        (name.len() + extension.len() > 0)
            && Self::part_is_valid(name)
            && Self::part_is_valid(extension)
    }

    pub fn build_name(&self, null_terminate: bool) -> Option<Vec<u16>> {
        if self.free_indicator() != ShortFileNameFreeIndicator::NotFree {
            return None;
        }

        let name = Self::trim_trailing_padding(self.get_file_name_characters().unwrap());
        let extension = Self::trim_trailing_padding(self.get_file_extension_characters().unwrap());

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

    fn part_is_valid(value: &[u8]) -> bool {
        // The part must have a length of 0
        value.len() == 0
            // Or exclusively contain allowable characters.
            || value
                .iter()
                .all(|c| *c >= 0x80 || (b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()-@^_`{}~").contains(c))
    }
}

impl ShortFileName {
    pub fn checksum(&self) -> u8 {
        let mut sum = 0u8;
        for i in 0..11 {
            sum = (sum >> 1) + (sum << 7) + self.0[i];
        }

        sum
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    name: ShortFileName,
    attributes: DirectoryEntryAttributes,
    name_case_flags: DirectoryEntryNameCaseFlags,
    creation_time: FatTime,
    creation_date: FatDate,
    last_access_date: FatDate,
    cluster_high: [u8; 2], // Upper bytes of the cluster number, always 0x00, 0x00 on FAT12/16
    last_write_time: FatTime2sResolution,
    last_write_date: FatDate,
    cluster_low: [u8; 2], // Lower bytes of the cluster number.
    file_size: [u8; 4],
}

impl DirectoryEntry {
    pub const fn attributes(&self) -> &DirectoryEntryAttributes {
        &self.attributes
    }

    pub const fn file_name(&self) -> &ShortFileName {
        &self.name
    }

    pub const fn file_size(&self) -> u32 {
        u32::from_le_bytes(self.file_size)
    }

    pub fn is_empty_file(&self) -> bool {
        self.file_size() == 0 && self.first_cluster() == 0
    }

    pub fn first_cluster(&self) -> u32 {
        let mut bytes = [0u8; 4];
        bytes[..2].copy_from_slice(&self.cluster_high);
        bytes[2..].copy_from_slice(&self.cluster_low);
        u32::from_le_bytes(bytes)
    }

    pub fn is_invalid(&self) -> bool {
        ((self.file_size() == 0) != (self.first_cluster() == 0)) || (self.first_cluster() == 1)
    }
}

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
