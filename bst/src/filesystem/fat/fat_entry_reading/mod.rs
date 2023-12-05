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

mod fat_12;
mod fat_16;
mod fat_32;

pub use fat_12::Fat12Entry;
pub use fat_16::Fat16Entry;
pub use fat_32::Fat32Entry;

use super::{bios_parameters_blocks::FatBiosParameterBlock, FatErrors};
use core::mem::size_of;

#[derive(Debug, Copy, Clone)]
pub struct FatEntryOutOfRangeError {
    _value: u32,
    _max: u32,
}

impl FatEntryOutOfRangeError {
    pub const fn from(value: u32, max: u32) -> Self {
        Self {
            _value: value,
            _max: max,
        }
    }
}

pub trait FatEntry: Sized + Copy + TryFrom<u32> + Into<u32> + PartialEq + Eq {
    fn end_of_chain() -> Self;

    fn bad_cluster() -> Self;

    fn zero() -> Self;

    fn check_media_bits(&self, media_bits: u8) -> bool;

    fn check_error_bits(&self) -> FatErrors;

    fn is_end_of_chain(&self) -> bool;

    fn is_bad_cluster(&self) -> bool;

    fn is_free(&self) -> bool {
        self.eq(&Self::zero())
    }

    fn try_read_from<T: FatBiosParameterBlock>(
        index: usize,
        pointer: *const u8,
        parameters: &T,
    ) -> Option<Self>;

    fn try_write_to<T: FatBiosParameterBlock>(
        &self,
        index: usize,
        pointer: *mut u8,
        parameters: &T,
    ) -> bool;
}

fn get_byte_aligned_fat_entry_byte_offset_and_sector<TEntry: Sized>(
    sector_size: usize,
    entry_index: usize,
) -> (usize, usize) {
    let entries_per_sector = sector_size / size_of::<TEntry>();
    let sector = entry_index / entries_per_sector;
    let offset = entry_index % entries_per_sector;
    (
        (sector_size * sector) + (offset * size_of::<TEntry>()),
        sector,
    )
}

fn read_byte_aligned_fat_entry<T: FatBiosParameterBlock, TEntry: Sized + Copy>(
    index: usize,
    pointer: *const u8,
    parameters: &T,
) -> Option<TEntry> {
    let (byte_offset, sector) = get_byte_aligned_fat_entry_byte_offset_and_sector::<TEntry>(
        parameters.bytes_per_sector() as usize,
        index,
    );

    if sector >= parameters.sectors_per_fat() as usize {
        return None;
    }

    let byte_offset = byte_offset + parameters.fat_start_sector() as usize;
    Some(unsafe { *(pointer.add(byte_offset) as *const TEntry) })
}
