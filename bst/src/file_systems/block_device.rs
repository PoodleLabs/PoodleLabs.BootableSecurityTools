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

pub trait BlockDevice {
    fn device_type(&self) -> BlockDeviceType;

    fn media_present(&self) -> bool;

    fn write_caching(&self) -> bool;

    fn block_size(&self) -> usize;

    fn block_count(&self) -> u64;

    fn read_only(&self) -> bool;

    fn media_id(&self) -> u32;

    fn read_blocks(&self, media_id: u32, first_block: u64, buffer: &mut [u8]) -> bool;

    fn write_blocks(&mut self, media_id: u32, first_block: u64, buffer: &[u8]) -> bool;

    fn flush_blocks(&mut self) -> bool;

    fn reset(&mut self) -> bool;

    fn read_bytes(&mut self, media_id: u32, offset: u64, buffer: &mut [u8]) -> bool;
}
