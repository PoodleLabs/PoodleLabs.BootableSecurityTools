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

use super::{bios_parameters_blocks::FatBiosParameterBlock, boot_sectors::FatBootSector};

#[repr(C)]
pub struct DirectoryEntry {
    file_name: [u8; 20],
    file_size: u32,
    timestamp: u32,
    first_cluster: u32,
}

impl DirectoryEntry {
    pub const fn is_empty_file(&self) -> bool {
        self.file_size == 0 && self.first_cluster == 0
    }

    pub const fn is_invalid(&self) -> bool {
        ((self.file_size == 0) != (self.first_cluster == 0)) || (self.first_cluster == 1)
    }

    pub fn try_get_start_byte_offset<
        const N: usize,
        TBiosParameterBlock: FatBiosParameterBlock,
        TBootSector: FatBootSector<N, TBiosParameterBlock>,
    >(
        &self,
        boot_sector: &TBootSector,
    ) -> Option<usize> {
        if self.is_empty_file() || self.is_invalid() {
            None
        } else {
            boot_sector
                .body()
                .bios_parameters_block()
                .get_byte_offset_for_cluster(self.first_cluster as usize)
        }
    }
}
