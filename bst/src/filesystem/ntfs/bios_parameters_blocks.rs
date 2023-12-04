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

use crate::filesystem::{fat::BiosParameterBlockFlags, BootSectorExtendedBootSignature};

// NOTE: Integers are stored in little-endian format on disk under NTFS. If we support big-endian processors
// (we don't currently), we will need to support endianness conversion.

pub struct NtfsBiosParametersBlock {
    // The number of bytes per logical sector. Must be > 0 and, realistically speaking, pow2 meeting criteria:
    // 32 <= sector_size <= 32768 for practically useful values
    bytes_per_sector: u16,
    // Must be pow2; a cluster is FAT's minimum allocation unit.
    sectors_per_cluster: u8,
    // Must be > 0 given the BSB containing this value.
    reserved_sector_count: u16,
    // >=1 technically valid, but 2 is STRONGLY recommended.
    // 1 is acceptable for non-disk memory, with a cost of reduced compatibility.
    fat_count: u8,
    // FAT12/16 root directory entry count; always 0 for NTFS.
    zero1: u16,
    // FAT12/16 sector size; always 0 for NTFS.
    zero2: u16,
    // Obsolete flag for identifying media type; don't need to support it. The first byte of the file access tables
    // should match this value.
    media_type: u8,
    // FAT12/16 FAT sector count; always 0 for NTFS.
    zero3: u16,
    // The number of sectors per track on media with tracks. We don't need to support this.
    sectors_per_track: u16,
    // The number of heads on media with tracks. We don't need to support this.
    number_of_heads: u16,
    // The number of hidden sectors preceding the FAT volume. For unpartitioned media, this should be 0.
    hidden_sector_count: u32,
    // The total number of sectors.
    total_sector_count: u32,

    physical_drive_number: u8,
    flags: BiosParameterBlockFlags,
}

struct NtfsBootSector {
    jump_boot: [u8; 3],
    oem_name: [u8; 8],
    bios_paramaters_block: NtfsBiosParametersBlock,
    // Must be V8_0
    extended_boot_signature: BootSectorExtendedBootSignature,
    reserved: u8,
    sectors_in_volume: u64,
    mft_first_cluster_number: u64,
    mft_mirror_first_cluster_number: u64,
    mft_record_size: u32,
    index_block_size: u32,
    volume_serial_number: u64,
    checksum: u32,
}
