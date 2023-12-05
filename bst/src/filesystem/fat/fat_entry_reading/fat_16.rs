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
    get_byte_aligned_fat_entry_byte_offset_and_sector, read_byte_aligned_fat_entry, FatEntry,
    FatEntryOutOfRangeError,
};
use crate::filesystem::fat::{bios_parameters_blocks::FatBiosParameterBlock, FatErrors};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Fat16Entry(u16);

impl Fat16Entry {
    const BIT_MASK: u32 = 0b1111111111111111;
}

impl TryFrom<u32> for Fat16Entry {
    type Error = FatEntryOutOfRangeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::BIT_MASK {
            Err(FatEntryOutOfRangeError::from(Self::BIT_MASK, value))
        } else {
            Ok(Self(value as u16))
        }
    }
}

impl Into<u32> for Fat16Entry {
    fn into(self) -> u32 {
        self.0 as u32
    }
}

impl FatEntry for Fat16Entry {
    fn end_of_chain() -> Self {
        Self(0xFFFF)
    }

    fn bad_cluster() -> Self {
        Self(0xFFF7)
    }

    fn zero() -> Self {
        Self(0)
    }

    fn check_media_bits(&self, media_bits: u8) -> bool {
        self.0 == (media_bits as u16 | 0xFF00)
    }

    fn check_error_bits(&self) -> FatErrors {
        if (self.0 & 0b1111111111111100) != 0b1111111111111100 {
            FatErrors::InvalidErrorFatEntry
        } else if (self.0 & 0b0000000000000010) != 0b0000000000000010 {
            FatErrors::HardError
        } else if (self.0 & 0b0000000000000001) != 0b0000000000000001 {
            FatErrors::VolumeDirty
        } else {
            FatErrors::None
        }
    }

    fn is_end_of_chain(&self) -> bool {
        self.0 >= 0xFFF8
    }

    fn is_bad_cluster(&self) -> bool {
        self.0 == 0xFFF7
    }

    fn try_read_from<T: FatBiosParameterBlock>(
        index: usize,
        pointer: *const u8,
        parameters: &T,
    ) -> Option<Self> {
        match read_byte_aligned_fat_entry(index, pointer, parameters) {
            Some(e) => Some(e),
            None => None,
        }
    }

    fn try_write_to<T: FatBiosParameterBlock>(
        &self,
        index: usize,
        pointer: *mut u8,
        parameters: &T,
    ) -> bool {
        let (byte_offset, sector) = get_byte_aligned_fat_entry_byte_offset_and_sector::<u16>(
            parameters.bytes_per_sector() as usize,
            index,
        );

        if sector >= parameters.sectors_per_fat() as usize {
            return false;
        }

        let byte_offset = byte_offset + parameters.fat_start_sector() as usize;
        unsafe { *(pointer.add(byte_offset) as *mut u16) = self.0 }
        true
    }
}
