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
    integers,
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
    buffered_block: Option<(u64, u32)>,
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

    fn write_blocks(&mut self, media_id: u32, first_block: u64, buffer: &[u8]) -> bool {
        if (self.protocol.write_blocks)(
            self.protocol,
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
                    let block_size = self.block_size();
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
        ((self.protocol.flush_blocks)(self.protocol)).is_success()
    }

    fn reset(&mut self) -> bool {
        self.buffered_block = None;
        ((self.protocol.reset)(self.protocol, true)).is_success()
    }

    fn read_bytes(&mut self, media_id: u32, offset: u64, buffer: &mut [u8]) -> bool {
        // Calculate the start block and offset for the data to read.
        let block_size = self.block_size() as u64;
        let (mut block, first_block_offset) = (offset / block_size, (offset % block_size) as usize);
        if self.buffered_block.is_none() || self.buffered_block.unwrap() != (block, media_id) {
            // If the first block we need isn't buffered, read it.
            if !(self.protocol.read_blocks)(
                self.protocol,
                media_id,
                block,
                1,
                self.block_buffer.as_mut_ptr(),
            )
            .is_success()
            {
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
                self.protocol,
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
