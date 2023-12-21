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

// GPT partition labels consist of:
// MBR - A protective master boot record label in the first block which is used to prevent accidental overwrites by old software.
//       This MBR has a single partition entry with a starting CHS of 0x00, 0x02, 0x00, a type of 0xEE, and starting LBA of 0x00000001
//       which points at the partition table header located in block 1.
// Partition Table Header - This block defines the partition table.

#[repr(C)]
pub struct GptPartitionTableHeader {
    signature: [u8; 8],
    gpt_revision: [u8; 4],
    header_size: [u8; 4],
    // CRC32 checksum of the partition table header from block address 0x00 -> 0x5C
    self_crc_32: [u8; 4],
    reserved_1: [u8; 4],
    self_lba: [u8; 8],
    alternate_header_lba: [u8; 8],
    first_usable_block: [u8; 8],
    last_usable_block: [u8; 8],
    guid: [u8; 16],
    partition_array_start: [u8; 8],
    partition_entry_count: [u8; 4],
    partition_entry_size: [u8; 4],
    // CRC32 checksum of the partition array.
    partition_array_crc32: [u8; 4],
} // The remaining bytes in the block should be 0.

impl GptPartitionTableHeader {
    pub const VALID_SIGNATURE: &[u8; 8] = b"EFI PART";
}

#[repr(C)]
pub struct GptPartitionDescriptor {
    type_guid: [u8; 16],
    guid: [u8; 16],
    starting_lba: [u8; 8],
    ending_lba: [u8; 8],
    attributes: [u8; 8],
} // The remaining bytes (defined by partition table header's partition_entry_size) are a UTF16 string for the partition's name.
