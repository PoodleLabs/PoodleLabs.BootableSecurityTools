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

use super::{FatEntry, FatEntryOutOfRangeError};
use crate::{
    bits::{try_get_bit_at_index, try_set_bit_at_index},
    filesystem::fat::{bios_parameters_blocks::FatBiosParameterBlock, boot_sectors::FatBootSector},
};
use core::slice;

#[derive(Debug, Copy, Clone)]
pub struct Fat12Entry(u16);

impl Fat12Entry {
    const BIT_MASK: u32 = 0b111111111111;
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

fn unaligned_fat_entry_counts<
    const N: usize,
    TBiosParametersBlock: FatBiosParameterBlock,
    TBootSector: FatBootSector<N, TBiosParametersBlock>,
>(
    boot_sector: &TBootSector,
) -> (usize, usize) {
    let bpb = boot_sector.boot_sector_body().bios_parameters_block();
    let fat_byte_count = bpb.sectors_per_fat() as usize * bpb.bytes_per_sector() as usize;
    let fat_bit_count = fat_byte_count * 8;
    (fat_byte_count, fat_bit_count / 12)
}

impl FatEntry for Fat12Entry {
    fn try_read_from<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        index: usize,
        pointer: *const u8,
        boot_sector: &TBootSector,
    ) -> Option<Self> {
        let (fat_bytes, fat_entries) = unaligned_fat_entry_counts(boot_sector);
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

    fn try_write_to<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        &self,
        index: usize,
        pointer: *mut u8,
        boot_sector: &TBootSector,
    ) -> bool {
        let (fat_bytes, fat_entries) = unaligned_fat_entry_counts(boot_sector);
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
