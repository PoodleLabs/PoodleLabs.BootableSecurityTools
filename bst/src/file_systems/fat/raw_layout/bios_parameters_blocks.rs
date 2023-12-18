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

use crate::{file_systems::fat, integers};

pub trait BiosParameterBlock: Sized {
    fn root_directory_entries(&self) -> u16;

    fn sectors_per_cluster(&self) -> u8;

    fn sectors_per_track(&self) -> u16;

    fn active_map(&self) -> Option<u8>;

    fn reserved_sectors(&self) -> u16;

    fn bytes_per_sector(&self) -> u16;

    fn number_of_heads(&self) -> u16;

    fn sectors_per_map(&self) -> u32;

    fn hidden_sectors(&self) -> u32;

    fn total_sectors(&self) -> u32;

    fn media_type(&self) -> u8;

    fn map_count(&self) -> u8;

    fn map_start_sector(&self) -> u32 {
        self.reserved_sectors() as u32
    }

    fn map_sector_count(&self) -> u32 {
        self.sectors_per_map() * self.map_count() as u32
    }

    fn root_directory_start_sector(&self) -> u32 {
        self.map_start_sector() + self.map_sector_count()
    }

    fn root_directory_sector_count(&self) -> u32 {
        integers::ceil_div(
            32 * self.root_directory_entries() as usize,
            self.bytes_per_sector() as usize,
        ) as u32
    }

    fn data_start_sector(&self) -> u32 {
        self.root_directory_start_sector() + self.root_directory_sector_count()
    }

    fn data_sector_count(&self) -> u32 {
        self.total_sectors() - self.data_start_sector()
    }

    fn cluster_count(&self) -> u32 {
        self.data_sector_count() / self.sectors_per_cluster() as u32
    }

    fn variant(&self) -> fat::Variant {
        let cluster_count = self.cluster_count();
        if cluster_count <= 4085 {
            fat::Variant::Fat12
        } else if cluster_count <= 65525 {
            fat::Variant::Fat16
        } else {
            fat::Variant::Fat32
        }
    }
}

#[repr(C)]
pub struct FatBiosParameterBlockCommonFields {
    // The number of bytes per logical sector. Must be > 0, and, realistically speaking pow2 meeting criteria:
    // 32 <= sector_size <= 32768 for practically useful values
    // 128 <= sector_size <= 8192 for wide DOS compatibility
    // Default should be 512 for maximum compatibility.
    bytes_per_sector: [u8; 2],
    // Must be pow2; a cluster is FAT's minimum allocation unit.
    // For maximum compatibility, sectors_per_cluster * bytes_per_sector should be <=32KB.
    sectors_per_cluster: u8,
    // Must be > 0 given the BSB containing this value.
    reserved_sectors: [u8; 2],
    // >=1 technically valid, but 2 is STRONGLY recommended.
    // 1 is acceptable for non-disk memory, with a cost of reduced compatibility.
    map_count: u8,
    // For FAT12/16 file systems, the root directory is stored separately in a block of 32 byte entries of this length.
    // The value should be set so that root_directory_entry_count * 32 % bytes_per_sector % 2 == 0.
    // For maximum compatibility, 512 for FAT12/16.
    // For FAT32, this MUST be 0.
    root_directory_entries: [u8; 2],
    // The total number of sectors in the volume for FAT12/16. When the total number of sectors is >= 0x10000,
    // this should be set to an invalid value of 0. For FAT32, this MUST be 0.
    total_sectors: [u8; 2],
    // Obsolete flag for identifying media type; don't need to support it. The first byte of the file access tables
    // should match this value.
    media_type: u8,
    // The number of sectors occupied by each FAT, for FAT12/16. The length of the file access tables block becomes
    // sectors_per_fat * fat_count. For FAT32, this MUST be 0.
    sectors_per_fat: [u8; 2],
    // The number of sectors per track on media with tracks. We don't need to support this.
    sectors_per_track: [u8; 2],
    // The number of heads on media with tracks. We don't need to support this.
    number_of_heads: [u8; 2],
    // The number of hidden sectors preceding the FAT volume. For unpartitioned media, this should be 0.
    hidden_sectors: [u8; 4],
    // The total number of sectors for FAT32, or FAT12/16 where the number of sectors is >= 0x10000.
    // This value will be used when total_sector_count == 0.
    large_total_sectors: [u8; 4],
}

impl BiosParameterBlock for FatBiosParameterBlockCommonFields {
    fn root_directory_entries(&self) -> u16 {
        u16::from_le_bytes(self.root_directory_entries)
    }

    fn reserved_sectors(&self) -> u16 {
        u16::from_le_bytes(self.reserved_sectors)
    }

    fn hidden_sectors(&self) -> u32 {
        u32::from_le_bytes(self.hidden_sectors)
    }

    fn sectors_per_cluster(&self) -> u8 {
        self.sectors_per_cluster
    }

    fn total_sectors(&self) -> u32 {
        let small = u16::from_le_bytes(self.total_sectors);
        match small {
            0 => u32::from_be_bytes(self.large_total_sectors),
            _ => small as u32,
        }
    }

    fn sectors_per_track(&self) -> u16 {
        u16::from_le_bytes(self.sectors_per_track)
    }

    fn bytes_per_sector(&self) -> u16 {
        u16::from_le_bytes(self.bytes_per_sector)
    }

    fn sectors_per_map(&self) -> u32 {
        u16::from_le_bytes(self.sectors_per_fat) as u32
    }

    fn number_of_heads(&self) -> u16 {
        u16::from_le_bytes(self.number_of_heads)
    }

    fn media_type(&self) -> u8 {
        self.media_type
    }

    fn map_count(&self) -> u8 {
        self.map_count
    }

    fn active_map(&self) -> Option<u8> {
        None
    }
}

#[repr(C)]
pub struct Fat32BiosParameterBlock {
    common_fields: FatBiosParameterBlockCommonFields,
    // The number of sectors occupied by each FAT.
    sectors_per_fat: [u8; 4],
    extended_flags: [u8; 2],
    // Upper byte is major version, lower byte is minor version. Expect 0.
    file_system_version: [u8; 2],
    // The first cluster for the root directory, usually, but not always, 2.
    root_cluster: [u8; 4],
    // The sector number for the start of the file system info structutre. Usually 1.
    file_system_info_sector: [u8; 2],
    // The sector number for the start of the backup boot sector. Strongly recommend 6.
    backup_boot_sector: [u8; 2],
    // Reserved bytes.
    reserved: [u8; 12],
}

#[repr(C)]
pub struct Fat32Mirroring(u16);

impl Fat32Mirroring {
    pub const fn all_fats_active_and_mirrored(&self) -> bool {
        (self.0 & (1 << 7)) == 0
    }

    pub const fn active_fat(&self) -> Option<u8> {
        if self.all_fats_active_and_mirrored() {
            None
        } else {
            Some((self.0 as u8) & 0b1111)
        }
    }
}

impl Fat32BiosParameterBlock {
    pub const fn mirroring(&self) -> Fat32Mirroring {
        Fat32Mirroring(u16::from_le_bytes(self.extended_flags))
    }

    pub const fn root_cluster(&self) -> u32 {
        u32::from_le_bytes(self.root_cluster)
    }
}

impl BiosParameterBlock for Fat32BiosParameterBlock {
    fn root_directory_entries(&self) -> u16 {
        self.common_fields.root_directory_entries()
    }

    fn reserved_sectors(&self) -> u16 {
        self.common_fields.reserved_sectors()
    }

    fn hidden_sectors(&self) -> u32 {
        self.common_fields.hidden_sectors()
    }

    fn sectors_per_cluster(&self) -> u8 {
        self.common_fields.sectors_per_cluster()
    }

    fn total_sectors(&self) -> u32 {
        self.common_fields.total_sectors()
    }

    fn sectors_per_track(&self) -> u16 {
        self.common_fields.sectors_per_track()
    }

    fn bytes_per_sector(&self) -> u16 {
        self.common_fields.bytes_per_sector()
    }

    fn sectors_per_map(&self) -> u32 {
        u32::from_le_bytes(self.sectors_per_fat)
    }

    fn number_of_heads(&self) -> u16 {
        self.common_fields.number_of_heads()
    }

    fn media_type(&self) -> u8 {
        self.common_fields.media_type()
    }

    fn map_count(&self) -> u8 {
        self.common_fields.map_count()
    }

    fn active_map(&self) -> Option<u8> {
        self.mirroring().active_fat()
    }
}
