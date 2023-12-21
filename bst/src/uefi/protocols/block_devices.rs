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

use super::{scoped_protocol::UefiScopedProtocol, UefiProtocol};
use crate::{
    file_systems::block_device::{BlockDevice, BlockDeviceDescription, BlockDeviceType},
    integers,
    uefi::core_types::{UefiGuid, UefiHandle, UefiStatusCode},
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
pub(in crate::uefi) struct UefiBlockDeviceIoProtocol<'a> {
    revision: u64,
    media: &'a UefiBlockIoMedia,
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

impl<'a> UefiBlockDeviceIoProtocol<'a> {
    pub const GUID: UefiGuid = UefiGuid::from(
        0x964e5b21,
        0x6459,
        0x11d2,
        0x8e,
        0x39,
        [0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );

    pub const fn description(&self, handle: UefiHandle) -> BlockDeviceDescription<UefiHandle> {
        BlockDeviceDescription::from(
            if self.media.logical_partition {
                BlockDeviceType::Partition
            } else {
                BlockDeviceType::Hardware
            },
            self.media.media_present,
            self.media.write_caching,
            self.media.block_size as usize,
            self.media.last_block + 1,
            self.media.read_only,
            handle,
            self.media.media_id,
        )
    }
}

impl<'a> UefiProtocol for UefiBlockDeviceIoProtocol<'a> {
    fn guid() -> &'static UefiGuid {
        &Self::GUID
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::uefi) struct BufferedUefiBlockDeviceIoProtocol<'a> {
    protocol: UefiScopedProtocol<'a, UefiBlockDeviceIoProtocol<'a>>,
    buffered_block: Option<(u64, u32)>,
    block_buffer: Vec<u8>,
    handle: UefiHandle,
}

impl<'a> BufferedUefiBlockDeviceIoProtocol<'a> {
    pub fn from(
        protocol: UefiScopedProtocol<'a, UefiBlockDeviceIoProtocol<'a>>,
        handle: UefiHandle,
    ) -> Self {
        Self {
            block_buffer: Vec::with_capacity(protocol.description(handle).block_size()),
            buffered_block: None,
            protocol,
            handle,
        }
    }

    fn read_blocks_internal(
        protocol: &UefiBlockDeviceIoProtocol,
        media_id: u32,
        first_block: u64,
        buffer: &mut [u8],
    ) -> bool {
        (protocol.read_blocks)(
            protocol,
            media_id,
            first_block,
            buffer.len(),
            buffer.as_mut_ptr(),
        )
        .is_success()
    }
}

impl<'a> BlockDevice for BufferedUefiBlockDeviceIoProtocol<'a> {
    type THandle = UefiHandle;

    fn description(&self) -> BlockDeviceDescription<UefiHandle> {
        self.protocol.description(self.handle)
    }

    fn read_blocks(&self, media_id: u32, first_block: u64, buffer: &mut [u8]) -> bool {
        Self::read_blocks_internal(&self.protocol, media_id, first_block, buffer)
    }

    fn write_blocks(&mut self, media_id: u32, first_block: u64, buffer: &[u8]) -> bool {
        if (self.protocol.write_blocks)(
            &self.protocol,
            media_id,
            first_block,
            buffer.len(),
            buffer.as_ptr(),
        )
        .is_success()
        {
            match self.buffered_block {
                Some((buffered_block, buffered_media_id)) => {
                    if media_id != buffered_media_id || first_block > buffered_block {
                        // If the media has changed since the last buffered read, or the first block we wrote to was after
                        // our currently buffered block, we don't need to do anything.
                        return true;
                    }

                    // Calculate the number of blocks we wrote to.
                    let block_size = self.protocol.media.block_size as usize;
                    let block_count = integers::ceil_div(buffer.len(), block_size) as u64;

                    // Calculate the offset of the buffered block from the first block we wrote to.
                    let buffered_offset = buffered_block - first_block;
                    if buffered_offset >= block_count {
                        // If our buffered block is outside the bounds of the mutated blocks,
                        // we don't need to do anything.
                        return true;
                    }

                    if block_count * block_size as u64 > buffer.len() as u64
                        && buffered_offset == block_count - 1
                    {
                        // The read should have failed in the case the buffer has a length which is not a multiple of
                        // the block size, but on the off chance of some bad UEFI implementation having some unknown
                        // behaviour, if a partial write was attempted, and reported successful, on our buffered block,
                        // we should just invalidate the buffer.
                        self.buffered_block = None;
                    } else {
                        // Our buffered block was overwritten. We can just copy the write buffer into our block buffer.
                        let write_buffer_start = buffered_offset as usize * block_size;
                        self.block_buffer.copy_from_slice(
                            &buffer[write_buffer_start..write_buffer_start + block_size],
                        )
                    }

                    true
                }
                None => true,
            }
        } else {
            false
        }
    }

    fn flush_blocks(&mut self) -> bool {
        ((self.protocol.flush_blocks)(&self.protocol)).is_success()
    }

    fn reset(&mut self) -> bool {
        self.buffered_block = None;
        ((self.protocol.reset)(&self.protocol, true)).is_success()
    }

    fn read_bytes(&mut self, media_id: u32, offset: u64, buffer: &mut [u8]) -> bool {
        // Calculate the start block and offset for the data to read.
        let block_size = self.protocol.media.block_size as u64;
        if self.block_buffer.len() != block_size as usize {
            // Ensure the block buffer has the correct length.
            self.block_buffer.resize(block_size as usize, 0);
            self.buffered_block = None;
        }

        let (mut block, first_block_offset) = (offset / block_size, (offset % block_size) as usize);
        if self.buffered_block.is_none() || self.buffered_block.unwrap() != (block, media_id) {
            // If the first block we need isn't buffered, read it.
            if !Self::read_blocks_internal(&self.protocol, media_id, block, buffer) {
                // If we can't read the first block we need, return false; we can't read the bytes.
                return false;
            }

            // Update the buffered block address.
            self.buffered_block = Some((block, media_id));
        }

        // Calculate the number of bytes to read from the first block.
        let bytes_from_first_block =
            ((block_size - (first_block_offset as u64)) as usize).min(buffer.len() as usize);

        // Read the bytes from the first block into the buffer.
        buffer[..bytes_from_first_block].copy_from_slice(
            &self.block_buffer[first_block_offset..first_block_offset + bytes_from_first_block],
        );

        // Calculate the number of bytes we still need to read.
        let (mut offset, mut remaining_bytes) = (
            bytes_from_first_block,
            buffer.len() - bytes_from_first_block,
        );

        while remaining_bytes > 0 {
            // Increment the block we're reading.
            block += 1;

            // Try to read the block.
            if !(self.protocol.read_blocks)(
                &self.protocol,
                media_id,
                block,
                1,
                self.block_buffer.as_mut_ptr(),
            )
            .is_success()
            {
                // If we can't read the block we need, return false.
                return false;
            }

            // Update the buffered block address.
            self.buffered_block = Some((block, media_id));

            // Calculate the number of bytes to read from the block.
            let bytes_from_block = self.block_buffer.len().min(remaining_bytes);

            // Copy the bytes from the block buffer into our output buffer.
            buffer[offset..offset + bytes_from_block]
                .copy_from_slice(&self.block_buffer[..bytes_from_block]);

            // Update our remaining byte count and output buffer offset.
            remaining_bytes -= bytes_from_block;
            offset += bytes_from_block;
        }

        true
    }
}
