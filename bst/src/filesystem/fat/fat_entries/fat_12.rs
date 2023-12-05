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

use super::{get_status, FatEntry, FatEntryOutOfRangeError, FatEntryStatus};
use crate::{
    bits::{try_get_bit_at_index, try_set_bit_at_index},
    filesystem::fat::{bios_parameters_blocks::FatBiosParameterBlock, FatErrors},
};
use core::{
    ops::{BitAnd, BitOr, Not},
    slice,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Fat12Entry(u16);

impl Fat12Entry {
    const BIT_MASK: u32 = 0b111111111111;
    const END_OF_CHAIN: u16 = 0xFFF;
    const BAD_CLUSTER: u16 = 0xFF7;
    const RESERVED: u16 = 1;
    const FREE: u16 = 0;
}

impl TryFrom<u32> for Fat12Entry {
    type Error = FatEntryOutOfRangeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::BIT_MASK {
            Err(FatEntryOutOfRangeError::from(Self::BIT_MASK, value))
        } else {
            Ok(Self(value as u16))
        }
    }
}

impl Into<u32> for Fat12Entry {
    fn into(self) -> u32 {
        self.0 as u32
    }
}

fn unaligned_fat_entry_counts<T: FatBiosParameterBlock>(parameters: &T) -> (usize, usize) {
    let fat_byte_count =
        parameters.sectors_per_fat() as usize * parameters.bytes_per_sector() as usize;
    let fat_bit_count = fat_byte_count * 8;
    (fat_byte_count, fat_bit_count / 12)
}

impl Not for Fat12Entry {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self((!self.0) & (Self::BIT_MASK as u16))
    }
}

impl BitOr for Fat12Entry {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for Fat12Entry {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl FatEntry for Fat12Entry {
    fn volume_dirty_flag() -> Self {
        Self(1)
    }

    fn hard_error_flag() -> Self {
        Self(2)
    }

    fn end_of_chain() -> Self {
        Self(Self::END_OF_CHAIN)
    }

    fn bad_cluster() -> Self {
        Self(Self::BAD_CLUSTER)
    }

    fn reserved() -> Self {
        Self(Self::RESERVED)
    }

    fn free() -> Self {
        Self(Self::FREE)
    }

    fn check_media_bits(&self, media_bits: u8) -> bool {
        self.0 == (media_bits as u16 | 0x0F00)
    }

    fn check_error_bits(&self) -> FatErrors {
        if (self.0 & 0b111111111100) != 0b111111111100 {
            FatErrors::InvalidErrorFatEntry
        } else if (self.0 & 0b000000000010) != 0b000000000010 {
            FatErrors::HardError
        } else if (self.0 & 0b000000000001) != 0b000000000001 {
            FatErrors::VolumeDirty
        } else {
            FatErrors::None
        }
    }

    get_status!();

    fn try_read_from<T: FatBiosParameterBlock>(
        index: usize,
        pointer: *const u8,
        parameters: &T,
    ) -> Option<Self> {
        let (fat_bytes, fat_entries) = unaligned_fat_entry_counts(parameters);
        if index >= fat_entries {
            return None;
        }

        let mut aggregate = 0u16;
        let bit_index = index * 12;
        let shift_start = 1u16 << 11;
        let slice = unsafe { slice::from_raw_parts(pointer, fat_bytes) };
        for i in bit_index..bit_index + 12 {
            if try_get_bit_at_index(i, slice).unwrap() {
                aggregate |= shift_start >> (i - bit_index);
            }
        }

        Some(Self(aggregate))
    }

    fn try_write_to<T: FatBiosParameterBlock>(
        &self,
        index: usize,
        pointer: *mut u8,
        parameters: &T,
    ) -> bool {
        let (fat_bytes, fat_entries) = unaligned_fat_entry_counts(parameters);
        if index >= fat_entries {
            return false;
        }

        let bit_index = index * 12;
        let shift_start = 1u16 << 11;
        let slice = unsafe { slice::from_raw_parts_mut(pointer, fat_bytes) };
        for i in bit_index..bit_index + 12 {
            assert!(try_set_bit_at_index(
                i,
                (shift_start >> (i - bit_index) & self.0) != 0,
                slice
            ));
        }

        true
    }
}
