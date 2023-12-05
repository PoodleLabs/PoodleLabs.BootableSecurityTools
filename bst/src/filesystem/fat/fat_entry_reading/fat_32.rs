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
use crate::filesystem::fat::{
    bios_parameters_blocks::FatBiosParameterBlock, boot_sectors::FatBootSector,
};

#[derive(Debug, Copy, Clone)]
pub struct Fat32Entry(u32);

impl Fat32Entry {
    const BIT_MASK: u32 = 0b1111111111111111111111111111;
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

impl FatEntry for Fat32Entry {
    fn end_of_chain() -> Self {
        Self(0x0FFFFFFF)
    }

    fn is_end_of_chain(&self) -> bool {
        self.0 >= 0x0FFFFFF8
    }

    fn try_read_from<
        const N: usize,
        TBiosParametersBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParametersBlock>,
    >(
        index: usize,
        pointer: *const u8,
        boot_sector: &TBootSector,
    ) -> Option<Self> {
        match read_byte_aligned_fat_entry::<N, _, _, u32>(index, pointer, boot_sector) {
            Some(e) => Some(Self(e & Self::BIT_MASK)),
            None => None,
        }
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
        let bpb = boot_sector.body().bios_parameters_block();
        let (byte_offset, sector) = get_byte_aligned_fat_entry_byte_offset_and_sector::<u32>(
            bpb.bytes_per_sector() as usize,
            index,
        );

        if sector >= bpb.sectors_per_fat() as usize {
            return false;
        }

        let byte_offset = byte_offset + bpb.fat_start_sector() as usize;
        let ptr = unsafe { (pointer.add(byte_offset) as *mut u32).as_mut() }.unwrap();
        *ptr = (*ptr & !Self::BIT_MASK) | (self.0 & Self::BIT_MASK);
        true
    }
}
