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

use super::{bios_parameters_blocks::FatBiosParameterBlock, boot_sectors::FatBootSector};
use crate::bits::bit_field;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};

#[repr(C)]
pub struct FatDate([u8; 2]);
// Bit 15-9: Year 0-127 (1980-2107)
// Bit 8-5: Month 1-12
// Bit 4-0: Day 1-31

#[repr(C)]
pub struct FatTime2sResolution([u8; 2]);
// Bit 15-11: Hour 0-23
// Bit 10-5: Minute 0-59
// Bit 4-0: 2 second increment 0-29 (equalling 0-58s)

#[repr(C)]
pub struct FatTime {
    sub_2s: u8, // Resolution of 10 milliseconds, 0-199 where 0 = 0, and 199 = 1.99s.
    main: FatTime2sResolution,
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
        self.has_all_flags_of(Self::READ_ONLY)
    }

    pub const fn is_hidden(&self) -> bool {
        self.has_any_flag_of(Self::HIDDEN)
    }

    pub const fn is_system_entry(&self) -> bool {
        self.has_any_flag_of(Self::SYSTEM)
    }

    pub const fn is_volume_label(&self) -> bool {
        self.has_any_flag_of(Self::VOLUME_LABEL)
    }

    pub const fn is_directory(&self) -> bool {
        self.has_any_flag_of(Self::DIRECTORY)
    }

    pub const fn updated_since_last_archive(&self) -> bool {
        self.has_any_flag_of(Self::ARCHIVE)
    }
}

bit_field!(DirectoryEntryAttributes);

#[repr(C)]
pub struct DirectoryEntryNameCaseFlags(u8);
// 0x10: File extension part is all lowercase
// 0x08: File name part is all lowercase

#[repr(C)]
pub struct ShortFileName([u8; 11]);
// First byte:
// 0xE5: Free
// 0x00: Free, and all following directory entries are free
// First 8 bytes are file name
// Last 3 bytes are extension
// Pad with spaces (0x20)
// Allowable characters are 0-9 A-Z ! # $ % & ' ( ) - @ ^ _ ` { } ~
// No spaces besides automatic padding are allowed.

#[repr(C)]
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

    pub fn try_get_start_byte_offset<
        const N: usize,
        TBiosParameterBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParameterBlock>,
    >(
        &self,
        boot_sector: &TBootSector,
    ) -> Option<usize> {
        if self.is_empty_file() || self.is_invalid() {
            None
        } else {
            boot_sector
                .body()
                .bios_parameters_block()
                .get_byte_offset_for_cluster(self.first_cluster() as usize)
        }
    }
}

#[repr(C)]
pub struct LongFileNameOrdering(u8);
// Bit 0x40 indicated end of LFN when high.
// Bits 0-4 represent the ordering index from (1-20).

#[repr(C)]
pub struct LongFileNamePart1([u8; 10]); // Five UTF-16 characters.

#[repr(C)]
pub struct LongFileNamePart2([u8; 12]); // Six UTF-16 characters.

#[repr(C)]
pub struct LongFileNamePart3([u8; 4]); // Two UTF-16 characters.

#[repr(C)]
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
    pub const fn is_valid(&self) -> bool {
        // TODO: Checksum?
        self.attribute.is_long_file_name_entry()
            && self.entry_type == 0
            && u16::from_le_bytes(self.cluster_low) == 0
    }

    pub const fn ordering(&self) -> &LongFileNameOrdering {
        &self.ordering
    }

    pub fn characters(&self) -> [u16; 13] {
        let mut characters = [0u16; 13];
        Self::extract_chars_from_part(&mut characters, &self.part_1.0, 0);
        Self::extract_chars_from_part(&mut characters, &self.part_2.0, 5);
        Self::extract_chars_from_part(&mut characters, &self.part_3.0, 11);
        characters
    }

    pub fn content_slice(characters: &[u16; 13]) -> &[u16] {
        match characters.iter().enumerate().find(|(_, c)| **c == 0) {
            Some((i, _)) => &characters[..i],
            None => &characters[..],
        }
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
