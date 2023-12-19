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

use crate::{
    file_systems::block_device::{BlockDevice, BlockDeviceType},
    uefi::core_types::UefiStatusCode,
};
use alloc::vec::Vec;

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub(in crate::uefi) struct BufferedUefiBlockDeviceIoProtocol<'a> {
    protocol: &'a UefiBlockDeviceIoProtocol,
    block_buffer: Vec<u8>,
}

impl<'a> BlockDevice for BufferedUefiBlockDeviceIoProtocol<'a> {
    fn device_type(&self) -> BlockDeviceType {
        if self.protocol.media.logical_partition {
            BlockDeviceType::Partition
        } else {
            BlockDeviceType::Hardware
        }
    }

    fn media_present(&self) -> bool {
        self.protocol.media.media_present
    }

    fn write_caching(&self) -> bool {
        self.protocol.media.write_caching
    }

    fn block_size(&self) -> usize {
        self.protocol.media.block_size as usize
    }

    fn block_count(&self) -> u64 {
        self.protocol.media.last_block + 1
    }

    fn read_only(&self) -> bool {
        self.protocol.media.read_only
    }

    fn media_id(&self) -> u32 {
        self.protocol.media.media_id
    }

    fn read_blocks(&self, media_id: u32, first_block: u64, buffer: &mut [u8]) -> bool {
        (self.protocol.read_blocks)(
            self.protocol,
            media_id,
            first_block,
            buffer.len(),
            buffer.as_mut_ptr(),
        )
        .is_success()
    }

    fn read_bytes(&mut self, media_id: u32, offset: u64, buffer: &mut [u8]) -> bool {
        todo!()
    }

    fn write_blocks(&mut self, media_id: u32, first_block: u64, buffer: &[u8]) -> bool {
        (self.protocol.write_blocks)(
            self.protocol,
            media_id,
            first_block,
            buffer.len(),
            buffer.as_ptr(),
        )
        .is_success()
    }

    fn flush_blocks(&mut self) -> bool {
        ((self.protocol.flush_blocks)(self.protocol)).is_success()
    }

    fn reset(&mut self) -> bool {
        ((self.protocol.reset)(self.protocol, true)).is_success()
    }
}
