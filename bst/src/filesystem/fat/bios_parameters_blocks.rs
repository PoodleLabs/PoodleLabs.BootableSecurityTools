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

pub struct BiosParameterBlockFlags(u8);

pub struct BiosParameterMirrorFlags(u16);

#[repr(u8)]
pub enum BiosParameterBlockExtendedBootSignature {
    V4_0 = 0x28,
    V4_1 = 0x29,
    V8_0 = 0x80,
}

#[repr(u8)]
pub enum BiosParameterBlockMediaDescriptor {
    PLACEHOLDER,
}

#[repr(packed)]
pub struct BiosParameterBlockD2_0 {
    // The number of bytes per logical sector. Must be  > 0,
    // but realistically a power of two which matches the criteria:
    // 32 <= sector_size <= 32768 for practically useful values
    // 128 <= sector_size <= 8192 for wide DOS compatibility
    sector_size: u16,
    sectors_per_cluster: u8,
    reserved_sector_count: u16,
    fat_count: u8,
    root_directory_entries: u16,
    logical_sector_count: u16,
    media_descriptor: BiosParameterBlockMediaDescriptor,
    sectors_per_fat: u16,
}

#[repr(packed)]
pub struct BiosParameterBlockD3_0 {
    parent: BiosParameterBlockD2_0,
    sectors_per_track: u16,
    head_count: u16,
    hidden_sector_count: u16,
}

#[repr(packed)]
pub struct BiosParameterBlockD3_2 {
    parent: BiosParameterBlockD3_0,
    sector_count: u16,
}

#[repr(packed)]
pub struct BiosParameterBlockD3_31 {
    parent: BiosParameterBlockD2_0,
    sectors_per_track: u16,
    head_count: u16,
    hidden_sector_count: u32,
    // The total number of logical sectors (superceding the u16 value in parent).
    total_sectors: u32,
}

#[repr(packed)]
pub struct BiosParametersBlockD3_4 {
    parent: BiosParameterBlockD3_31,
    physical_drive_number: u8,
    flags: BiosParameterBlockFlags,
    extended_boot_signature: BiosParameterBlockExtendedBootSignature,
    volume_serial_number: u32,
}

#[repr(packed)]
pub struct BiosParametersBlockD4_0 {
    parent: BiosParameterBlockD3_31,
    physical_drive_number: u8,
    flags: BiosParameterBlockFlags,
    extended_boot_signature: BiosParameterBlockExtendedBootSignature,
    volume_serial_number: u32,
    volume_label: [u8; 11],
    file_system_type: [u8; 8],
}

#[repr(packed)]
pub struct BiosParametersBlockD7_1 {
    parent: BiosParameterBlockD3_31,
    // The number of logical sectors per file acess table (superceding the u16 value in parent).
    logical_sectors_per_fat: u32,
    mirroring_flags: BiosParameterMirrorFlags,
    version: u16,
    root_directory_cluster: u32,
    fs_information_sector_location: u16,
    backup_sectors_location: u16,
    boot_file_name: [u8; 12],
    physical_drive_number: u8,
    flags: BiosParameterBlockFlags,
    extended_boot_signature: BiosParameterBlockExtendedBootSignature,
    volume_serial_number: u32,
}

#[repr(packed)]
pub struct BiosParametersBlockD7_1_EBS_4_1 {
    parent: BiosParametersBlockD7_1,
    volume_label: [u8; 11],
    file_system_type: [u8; 8],
}
