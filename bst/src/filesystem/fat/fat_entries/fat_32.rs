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

use super::{
    get_byte_aligned_fat_entry_byte_offset_and_sector, get_status, read_byte_aligned_fat_entry,
    FatEntry, FatEntryOutOfRangeError, FatEntryStatus,
};
use crate::filesystem::fat::{bios_parameters_blocks::FatBiosParameterBlock, FatErrors};
use core::ops::{BitAnd, BitOr, Not};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Fat32Entry(u32);

impl Fat32Entry {
    const BIT_MASK: u32 = 0b1111111111111111111111111111;
    const END_OF_CHAIN: u32 = 0xFFFFFFFF;
    const BAD_CLUSTER: u32 = 0xFFFFFFF7;
    const RESERVED: u32 = 1;
    const FREE: u32 = 0;
}

impl TryFrom<u32> for Fat32Entry {
    type Error = FatEntryOutOfRangeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::BIT_MASK {
            Err(FatEntryOutOfRangeError::from(Self::BIT_MASK, value))
        } else {
            Ok(Self(value))
        }
    }
}

impl Into<u32> for Fat32Entry {
    fn into(self) -> u32 {
        self.0 as u32
    }
}

impl Not for Fat32Entry {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self((!self.0) & Self::BIT_MASK)
    }
}

impl BitOr for Fat32Entry {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for Fat32Entry {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl FatEntry for Fat32Entry {
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
        self.0 == (media_bits as u32 | 0xFFFFFF00)
    }

    fn check_error_bits(&self) -> FatErrors {
        if (self.0 & 0b11111111111111111111111111111100) != 0b11111111111111111111111111111100 {
            FatErrors::InvalidErrorFatEntry
        } else if (self.0 & 0b00000000000000000000000000000010)
            != 0b00000000000000000000000000000010
        {
            FatErrors::HardError
        } else if (self.0 & 0b00000000000000000000000000000001)
            != 0b00000000000000000000000000000001
        {
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
        match read_byte_aligned_fat_entry::<_, u32>(index, pointer, parameters) {
            Some(e) => Some(Self(e & Self::BIT_MASK)),
            None => None,
        }
    }

    fn try_write_to<T: FatBiosParameterBlock>(
        &self,
        index: usize,
        pointer: *mut u8,
        parameters: &T,
    ) -> bool {
        let (byte_offset, sector) = get_byte_aligned_fat_entry_byte_offset_and_sector::<u32>(
            parameters.bytes_per_sector() as usize,
            index,
        );

        if sector >= parameters.sectors_per_fat() as usize {
            return false;
        }

        let byte_offset = byte_offset + parameters.fat_start_sector() as usize;
        let ptr = unsafe { (pointer.add(byte_offset) as *mut u32).as_mut() }.unwrap();
        *ptr = (*ptr & !Self::BIT_MASK) | (self.0 & Self::BIT_MASK);
        true
    }
}
