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

use super::{
    boot_sectors::Fat32BootSector, fat_entries::FatEntry, file_system_info::FileSystemInfo,
    FatErrors, FatType,
};
use core::{mem::size_of, slice};

pub trait FatBiosParameterBlock: Sized {
    fn root_directory_entry_count(&self) -> u16;

    fn reserved_sector_count(&self) -> u16;

    fn hidden_sector_count(&self) -> u32;

    fn should_mirror_fats(&self) -> bool;

    fn sectors_per_cluster(&self) -> u8;

    fn total_sector_count(&self) -> u32;

    fn sectors_per_track(&self) -> u16;

    fn bytes_per_sector(&self) -> u16;

    fn sectors_per_fat(&self) -> u32;

    fn number_of_heads(&self) -> u16;

    fn media_type(&self) -> u8;

    fn active_fat(&self) -> u8;

    fn fat_count(&self) -> u8;

    fn fat_start_sector(&self) -> u32 {
        self.reserved_sector_count() as u32
    }

    fn fat_sector_count(&self) -> u32 {
        self.sectors_per_fat() * self.fat_count() as u32
    }

    fn root_directory_start_sector(&self) -> u32 {
        self.fat_start_sector() + self.fat_sector_count()
    }

    fn root_directory_sector_count(&self) -> u32 {
        ((32 * self.root_directory_entry_count() as u32) + self.bytes_per_sector() as u32 - 1)
            / self.bytes_per_sector() as u32
    }

    fn data_start_sector(&self) -> u32 {
        self.root_directory_start_sector() + self.root_directory_sector_count()
    }

    fn data_sector_count(&self) -> u32 {
        self.total_sector_count() - self.data_start_sector()
    }

    fn cluster_count(&self) -> u32 {
        self.data_sector_count() / self.sectors_per_cluster() as u32
    }

    fn fat_type(&self) -> FatType {
        let cluster_count = self.cluster_count();
        if cluster_count <= 4085 {
            FatType::Fat12
        } else if cluster_count <= 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        }
    }

    fn active_fat_bytes(&self, root: *const u8) -> &[u8] {
        let bytes_per_fat = self.sectors_per_fat() as usize * self.bytes_per_sector() as usize;
        unsafe {
            slice::from_raw_parts(
                root.add(self.active_fat() as usize * bytes_per_fat),
                bytes_per_fat,
            )
        }
    }

    fn active_fat_bytes_mut(&self, root: *mut u8) -> &mut [u8] {
        let bytes_per_fat = self.sectors_per_fat() as usize * self.bytes_per_sector() as usize;
        unsafe {
            slice::from_raw_parts_mut(
                root.add(self.active_fat() as usize * bytes_per_fat),
                bytes_per_fat,
            )
        }
    }

    fn get_byte_offset_for_cluster(&self, cluster: usize) -> Option<usize> {
        if cluster < 2 {
            None
        } else {
            let start_sector = (self.data_start_sector() as usize)
                + ((cluster - 2) * (self.sectors_per_cluster() as usize));
            let end_sector =
                (self.data_start_sector() as usize) + (self.data_sector_count() as usize);
            if start_sector >= end_sector {
                None
            } else {
                Some(start_sector * (self.bytes_per_sector() as usize))
            }
        }
    }

    fn error_check<TFatEntry: FatEntry>(&self, root: *const u8) -> FatErrors {
        let active_fat_bytes = self.active_fat_bytes(root);
        let first_entry = match TFatEntry::try_read_from(active_fat_bytes, 0) {
            Some(e) => e,
            None => return FatErrors::Unreadable,
        };

        let second_entry = match TFatEntry::try_read_from(active_fat_bytes, 1) {
            Some(e) => e,
            None => return FatErrors::Unreadable,
        };

        if !first_entry.check_media_bits(self.media_type()) {
            return FatErrors::InvalidMediaFatEntry;
        }

        return second_entry.check_error_bits();
    }

    fn try_clear_volume_dirty<TFatEntry: FatEntry>(&mut self, root: *mut u8) -> bool {
        try_set_flag_high(self, root, TFatEntry::volume_dirty_flag())
    }

    fn try_set_volume_dirty<TFatEntry: FatEntry>(&mut self, root: *mut u8) -> bool {
        try_set_flag_low(self, root, TFatEntry::volume_dirty_flag())
    }

    fn try_clear_hard_error<TFatEntry: FatEntry>(&mut self, root: *mut u8) -> bool {
        try_set_flag_high(self, root, TFatEntry::hard_error_flag())
    }

    fn try_set_hard_error<TFatEntry: FatEntry>(&mut self, root: *mut u8) -> bool {
        try_set_flag_low(self, root, TFatEntry::hard_error_flag())
    }

    fn update_mirrored_fats(&mut self, root: *mut u8) -> bool {
        let fat_count = self.fat_count() as usize;
        if !self.should_mirror_fats() || fat_count < 2 {
            return false;
        }

        let bytes_per_sector = self.bytes_per_sector() as usize;
        let fat_size = (self.sectors_per_fat() as usize) * bytes_per_sector;
        let start_offset = (self.fat_start_sector() as usize) * bytes_per_sector;
        let source = unsafe { slice::from_raw_parts(root.add(start_offset), fat_size) };
        for i in 1..fat_count {
            unsafe { slice::from_raw_parts_mut(root.add(start_offset + (i * fat_size)), fat_size) }
                .copy_from_slice(source)
        }

        true
    }
}

fn try_set_flag_high<TFatBiosParameterBlock: FatBiosParameterBlock, TFatEntry: FatEntry>(
    parameters: &TFatBiosParameterBlock,
    root: *mut u8,
    flag: TFatEntry,
) -> bool {
    let active_fat_bytes = parameters.active_fat_bytes_mut(root);
    let current_value = match TFatEntry::try_read_from(active_fat_bytes, 1) {
        Some(e) => e,
        None => return false,
    };

    (current_value | flag).try_write_to(active_fat_bytes, 1)
}

fn try_set_flag_low<TFatBiosParameterBlock: FatBiosParameterBlock, TFatEntry: FatEntry>(
    parameters: &TFatBiosParameterBlock,
    root: *mut u8,
    flag: TFatEntry,
) -> bool {
    let active_fat_bytes = parameters.active_fat_bytes_mut(root);
    let current_value = match TFatEntry::try_read_from(active_fat_bytes, 1) {
        Some(e) => e,
        None => return false,
    };

    (current_value & (!flag)).try_write_to(active_fat_bytes, 1)
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
    reserved_sector_count: [u8; 2],
    // >=1 technically valid, but 2 is STRONGLY recommended.
    // 1 is acceptable for non-disk memory, with a cost of reduced compatibility.
    fat_count: u8,
    // For FAT12/16 file systems, the root directory is stored separately in a block of 32 byte entries of this length.
    // The value should be set so that root_directory_entry_count * 32 % bytes_per_sector % 2 == 0.
    // For maximum compatibility, 512 for FAT12/16.
    // For FAT32, this MUST be 0.
    root_directory_entry_count: [u8; 2],
    // The total number of sectors in the volume for FAT12/16. When the total number of sectors is >= 0x10000,
    // this should be set to an invalid value of 0. For FAT32, this MUST be 0.
    total_sector_count: [u8; 2],
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
    hidden_sector_count: [u8; 4],
    // The total number of sectors for FAT32, or FAT12/16 where the number of sectors is >= 0x10000.
    // This value will be used when total_sector_count == 0.
    large_total_sector_count: [u8; 4],
}

impl FatBiosParameterBlock for FatBiosParameterBlockCommonFields {
    fn root_directory_entry_count(&self) -> u16 {
        u16::from_le_bytes(self.root_directory_entry_count)
    }

    fn reserved_sector_count(&self) -> u16 {
        u16::from_le_bytes(self.reserved_sector_count)
    }

    fn hidden_sector_count(&self) -> u32 {
        u32::from_le_bytes(self.hidden_sector_count)
    }

    fn should_mirror_fats(&self) -> bool {
        todo!()
    }

    fn sectors_per_cluster(&self) -> u8 {
        self.sectors_per_cluster
    }

    fn total_sector_count(&self) -> u32 {
        let small = u16::from_le_bytes(self.total_sector_count);
        match small {
            0 => u32::from_be_bytes(self.large_total_sector_count),
            _ => small as u32,
        }
    }

    fn sectors_per_track(&self) -> u16 {
        u16::from_le_bytes(self.sectors_per_track)
    }

    fn bytes_per_sector(&self) -> u16 {
        u16::from_le_bytes(self.bytes_per_sector)
    }

    fn sectors_per_fat(&self) -> u32 {
        u16::from_le_bytes(self.sectors_per_fat) as u32
    }

    fn number_of_heads(&self) -> u16 {
        u16::from_le_bytes(self.number_of_heads)
    }

    fn media_type(&self) -> u8 {
        self.media_type
    }

    fn fat_count(&self) -> u8 {
        self.fat_count
    }

    fn active_fat(&self) -> u8 {
        0
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

    pub const fn file_system_version(&self) -> u16 {
        u16::from_le_bytes(self.file_system_version)
    }

    pub const fn root_cluster(&self) -> u32 {
        u32::from_le_bytes(self.root_cluster)
    }

    pub fn file_system_info(&self, root: *const u8) -> Option<&FileSystemInfo> {
        let sector = self.file_system_info_sector();
        let bytes_per_sector = self.bytes_per_sector();
        if sector >= self.reserved_sector_count() || bytes_per_sector < 512 {
            return None;
        }

        let offset = (sector as usize) * (bytes_per_sector as usize);
        let fs_info = match unsafe { (root.add(offset) as *const FileSystemInfo).as_ref() } {
            Some(fs_info) => fs_info,
            None => {
                return None;
            }
        };

        if fs_info.signature_is_valid() {
            Some(fs_info)
        } else {
            None
        }
    }

    pub fn backup_boot_sector(&self, root: *const u8) -> Option<&Fat32BootSector> {
        let sector = self.backup_boot_sector_start();
        if sector >= self.reserved_sector_count() {
            return None;
        }

        let offset = (sector as usize) * (self.bytes_per_sector() as usize);
        match unsafe { (root.add(offset) as *const Fat32BootSector).as_ref() } {
            Some(fs_info) => Some(fs_info),
            None => None,
        }
    }

    pub fn update_reserved_sector_backups(&mut self, root: *mut u8) -> bool {
        let bytes_per_sector = self.bytes_per_sector() as usize;
        let start_sector = self.backup_boot_sector_start() as usize;
        let boot_sector_count =
            (size_of::<Fat32BootSector>() + bytes_per_sector - 1) / bytes_per_sector;

        let mut total_sector_count = boot_sector_count;
        let filesystem_info = self.file_system_info(root);
        if filesystem_info.is_none() {
            // FS Info requires a sector size >= 512, and the structure size is 512, so if present, it needs exactly one sector.
            total_sector_count += 1;
        }

        if start_sector + total_sector_count > (self.reserved_sector_count() as usize) {
            return false;
        }

        let backup_start_byte = start_sector * bytes_per_sector;
        let boot_sector_bytes = boot_sector_count * bytes_per_sector;
        let boot_sector_source = unsafe { slice::from_raw_parts(root, boot_sector_bytes) };
        let boot_sector_destination =
            unsafe { slice::from_raw_parts_mut(root.add(backup_start_byte), boot_sector_bytes) };

        boot_sector_destination.copy_from_slice(boot_sector_source);
        match filesystem_info {
            Some(v) => unsafe {
                *(root.add(backup_start_byte + boot_sector_bytes) as *mut FileSystemInfo) =
                    v.clone();
            },
            None => {}
        }

        true
    }

    fn file_system_info_sector(&self) -> u16 {
        u16::from_le_bytes(self.file_system_info_sector)
    }

    fn backup_boot_sector_start(&self) -> u16 {
        u16::from_le_bytes(self.backup_boot_sector)
    }
}

impl FatBiosParameterBlock for Fat32BiosParameterBlock {
    fn root_directory_entry_count(&self) -> u16 {
        self.common_fields.root_directory_entry_count()
    }

    fn reserved_sector_count(&self) -> u16 {
        self.common_fields.reserved_sector_count()
    }

    fn hidden_sector_count(&self) -> u32 {
        self.common_fields.hidden_sector_count()
    }

    fn should_mirror_fats(&self) -> bool {
        self.fat_count() > 1 && self.mirroring().all_fats_active_and_mirrored()
    }

    fn sectors_per_cluster(&self) -> u8 {
        self.common_fields.sectors_per_cluster()
    }

    fn total_sector_count(&self) -> u32 {
        self.common_fields.total_sector_count()
    }

    fn sectors_per_track(&self) -> u16 {
        self.common_fields.sectors_per_track()
    }

    fn bytes_per_sector(&self) -> u16 {
        self.common_fields.bytes_per_sector()
    }

    fn sectors_per_fat(&self) -> u32 {
        u32::from_le_bytes(self.sectors_per_fat)
    }

    fn number_of_heads(&self) -> u16 {
        self.common_fields.number_of_heads()
    }

    fn media_type(&self) -> u8 {
        self.common_fields.media_type()
    }

    fn fat_count(&self) -> u8 {
        self.common_fields.fat_count()
    }

    fn active_fat(&self) -> u8 {
        self.mirroring().active_fat().unwrap_or(0)
    }
}
