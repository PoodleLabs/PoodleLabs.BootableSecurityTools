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

use crate::uefi::core_types::UefiStatusCode;

// TODO: Implement BlockDevice

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct UefiBlockIoMedia {
    media_id: u32,
    removable: bool,
    media_present: bool,
    logical_partition: bool,
    read_only: bool,
    write_caching: bool,
    block_size: u32,
    io_align: u32,
    last_block: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiBlockDeviceIoProtocol {
    revision: u64,
    media: &'static UefiBlockIoMedia,
    reset: extern "efiapi" fn(this: &Self, extended_verification: bool) -> UefiStatusCode,
    read_blocks: extern "efiapi" fn(
        this: &Self,
        media_id: u32,
        start_block: u64,
        buffer_size: usize,
        buffer: *mut u8,
    ) -> UefiStatusCode,
    write_blocks: extern "efiapi" fn(
        this: &Self,
        media_id: u32,
        start_block: u64,
        buffer_size: usize,
        buffer: *const u8,
    ) -> UefiStatusCode,
    flush_blocks: extern "efiapi" fn(this: &Self) -> UefiStatusCode,
}
