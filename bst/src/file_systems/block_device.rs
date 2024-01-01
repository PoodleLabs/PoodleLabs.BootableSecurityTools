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

use crate::integers;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlockDeviceType {
    FirmwarePartition,
    Hardware,
    SoftwarePartition,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockDeviceDescription<THandle: Copy> {
    device_type: BlockDeviceType,
    media_present: bool,
    write_caching: bool,
    block_size: usize,
    block_count: u64,
    read_only: bool,
    handle: THandle,
    media_id: u32,
}

impl<THandle: Copy> BlockDeviceDescription<THandle> {
    pub const fn from(
        device_type: BlockDeviceType,
        media_present: bool,
        write_caching: bool,
        block_size: usize,
        block_count: u64,
        read_only: bool,
        handle: THandle,
        media_id: u32,
    ) -> Self {
        Self {
            media_present,
            write_caching,
            device_type,
            block_count,
            block_size,
            read_only,
            media_id,
            handle,
        }
    }

    pub const fn device_type(&self) -> BlockDeviceType {
        self.device_type
    }

    pub const fn write_caching(&self) -> bool {
        self.write_caching
    }

    pub const fn media_present(&self) -> bool {
        self.media_present
    }

    pub const fn block_size(&self) -> usize {
        self.block_size
    }

    pub const fn block_count(&self) -> u64 {
        self.block_count
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn handle(&self) -> THandle {
        self.handle
    }

    pub const fn media_id(&self) -> u32 {
        self.media_id
    }
}

pub trait BlockDevice {
    type THandle: Copy;

    fn description(&self) -> BlockDeviceDescription<Self::THandle>;

    fn read_blocks(&self, media_id: u32, first_block: u64, buffer: &mut [u8]) -> bool;

    fn write_blocks(&mut self, media_id: u32, first_block: u64, buffer: &[u8]) -> bool;

    fn flush_blocks(&mut self) -> bool;

    fn reset(&mut self) -> bool;

    fn read_bytes(&mut self, media_id: u32, offset: u64, buffer: &mut [u8]) -> bool;
}

pub struct BlockDevicePartition<'a, TUnderlyingBlockDevice: BlockDevice> {
    underlying_block_device: &'a mut TUnderlyingBlockDevice,
    start_block: u64,
    block_count: u64,
}

impl<'a, TUnderlyingBlockDevice: BlockDevice> BlockDevicePartition<'a, TUnderlyingBlockDevice> {
    pub fn from(
        underlying_block_device: &'a mut TUnderlyingBlockDevice,
        start_block: u64,
        block_count: u64,
    ) -> Self {
        Self {
            underlying_block_device,
            start_block,
            block_count,
        }
    }
}

impl<'a, TUnderlyingBlockDevice: BlockDevice> BlockDevice
    for BlockDevicePartition<'a, TUnderlyingBlockDevice>
{
    type THandle = TUnderlyingBlockDevice::THandle;

    fn description(&self) -> BlockDeviceDescription<Self::THandle> {
        let underlying_description = self.underlying_block_device.description();
        BlockDeviceDescription::from(
            BlockDeviceType::SoftwarePartition,
            underlying_description.media_present,
            underlying_description.write_caching,
            underlying_description.block_size,
            self.block_count,
            underlying_description.read_only,
            underlying_description.handle,
            underlying_description.media_id,
        )
    }

    fn read_blocks(&self, media_id: u32, first_block: u64, buffer: &mut [u8]) -> bool {
        let block_size = self.underlying_block_device.description().block_size;
        let end_block = first_block + (integers::ceil_div(buffer.len(), block_size) as u64);
        end_block <= self.block_count
            && self.underlying_block_device.read_blocks(
                media_id,
                first_block + self.start_block,
                buffer,
            )
    }

    fn write_blocks(&mut self, media_id: u32, first_block: u64, buffer: &[u8]) -> bool {
        let block_size = self.underlying_block_device.description().block_size;
        let end_block = first_block + (integers::ceil_div(buffer.len(), block_size) as u64);
        end_block <= self.block_count
            && self.underlying_block_device.write_blocks(
                media_id,
                first_block + self.start_block,
                buffer,
            )
    }

    fn flush_blocks(&mut self) -> bool {
        self.underlying_block_device.flush_blocks()
    }

    fn reset(&mut self) -> bool {
        self.underlying_block_device.reset()
    }

    fn read_bytes(&mut self, media_id: u32, offset: u64, buffer: &mut [u8]) -> bool {
        let block_size = self.underlying_block_device.description().block_size as u64;
        let byte_count = block_size * self.block_count;
        let end_byte = offset + buffer.len() as u64;

        end_byte <= byte_count
            && self.read_bytes(
                media_id,
                offset + ((block_size as u64) * self.start_block),
                buffer,
            )
    }
}
