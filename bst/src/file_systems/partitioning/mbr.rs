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

use core::mem::size_of;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MbrPartitionBootIndicator(u8);

impl MbrPartitionBootIndicator {
    pub const NON_BOOTABLE: Self = Self(Self::NON_BOOTABLE_VALUE);
    pub const BOOTABLE: Self = Self(Self::BOOTABLE_VALUE);

    const NON_BOOTABLE_VALUE: u8 = 0x00;
    const BOOTABLE_VALUE: u8 = 0x80;

    pub const fn is_bootable(&self) -> bool {
        self.0 == Self::BOOTABLE_VALUE
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MbrPartitionTypeValue(u8);

impl MbrPartitionTypeValue {
    pub const BLANK: Self = Self(0x00);
    pub const FAT12_MIXED: Self = Self(0x01); // < 65536 Sectors, CHS/LBA
    pub const FAT16_MIXED: Self = Self(0x04); // < 65536 Sectors, CHS/LBA
    pub const EXTENDED_MIXED: Self = Self(0x05); // CHS/LBA
    pub const SMALL_FAT_MIXED: Self = Self(0x06); // FAT12/16 >= 65536 Sectors, CHS/LBA
    pub const EXTENDED_FAT: Self = Self(0x07); // HPFS/NTFS/exFAT, CHS/LBA
    pub const FAT32_MIXED: Self = Self(0x0B); // FAT32, CHS/LBA
    pub const FAT32: Self = Self(0x0C); // FAT32, LBA
    pub const SMALL_FAT: Self = Self(0x0E); // FAT12/16, LBA
    pub const EXTENDED: Self = Self(0x0F); // LBA
    pub const GPT_PROTECTIVE: Self = Self(0xEE); // GPT partition table Indicator
}

#[repr(C)]
pub struct MbrPartitionTableEntry {
    boot_indicator: MbrPartitionBootIndicator,
    start_head: u8,          // Head number (0-254) of starting sector in CHS format.
    start_cylinder: [u8; 2], // Cylinder number (bits 0-9, value 0-1023) | Sector number (bits 10-15, value 0-63) of starting sector in CHS format.
    partition_type: MbrPartitionTypeValue,
    end_head: u8,          // Head number (0-254) of end sector in CHS format.
    end_cylinder: [u8; 2], // Cylinder number (bits 0-9, value 0-1023) | Sector number (bits 10-15, value 0-63) of end sector in CHS format.
    lba_offset: [u8; 4],   // The start sector (>=1) of the partition in LBA format.
    lba_size: [u8; 4],     // The size in sectors (>=1) of the partition in LBA format.
}

impl MbrPartitionTableEntry {
    pub const EMPTY: Self = Self {
        boot_indicator: MbrPartitionBootIndicator::NON_BOOTABLE,
        start_head: 0,
        start_cylinder: [0, 0],
        partition_type: MbrPartitionTypeValue::BLANK,
        end_head: 0,
        end_cylinder: [0, 0],
        lba_offset: [0, 0, 0, 0],
        lba_size: [0, 0, 0, 0],
    };

    pub const fn is_empty(&self) -> bool {
        self.partition_type.0 == MbrPartitionTypeValue::BLANK.0
    }
}

#[repr(C)]
pub struct MasterBootRecord {
    partition_1: MbrPartitionTableEntry,
    partition_2: MbrPartitionTableEntry,
    partition_3: MbrPartitionTableEntry,
    partition_4: MbrPartitionTableEntry,
    signature: [u8; 2],
}

impl MasterBootRecord {
    const VALID_SIGNATURE: u16 = 0xAA55;

    pub const fn get_offset(block_size: usize) -> usize {
        block_size - size_of::<MasterBootRecord>()
    }

    pub const fn signature_is_valid(&self) -> bool {
        u16::from_le_bytes(self.signature) == Self::VALID_SIGNATURE
    }

    pub const fn partitions(&self) -> [&MbrPartitionTableEntry; 4] {
        [
            &self.partition_1,
            &self.partition_2,
            &self.partition_3,
            &self.partition_4,
        ]
    }
}
