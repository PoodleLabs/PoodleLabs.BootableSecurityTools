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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlockDeviceType {
    Partition,
    Hardware,
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
