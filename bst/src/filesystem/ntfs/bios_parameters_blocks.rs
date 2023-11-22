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

use crate::filesystem::fat::{
    BiosParameterBlockD3_31, BiosParameterBlockExtendedBootSignature, BiosParameterBlockFlags,
};

#[repr(packed)]
pub struct BiosParametersBlockNtfs {
    parent: BiosParameterBlockD3_31,
    physical_drive_number: u8,
    flags: BiosParameterBlockFlags,
    // Must be V8_0
    extended_boot_signature: BiosParameterBlockExtendedBootSignature,
    reserved: u8,
    sectors_in_volume: u64,
    mft_first_cluster_number: u64,
    mft_mirror_first_cluster_number: u64,
    mft_record_size: u32,
    index_block_size: u32,
    volume_serial_number: u64,
    checksum: u32,
}
