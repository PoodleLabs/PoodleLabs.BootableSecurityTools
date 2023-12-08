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

#[repr(C)]
pub struct MbrPartitionTableEntry([u8; 16]);

#[repr(C)]
pub struct MasterBootRecord {
    boot_code: [u8; 446],
    partition_1: MbrPartitionTableEntry,
    partition_2: MbrPartitionTableEntry,
    partition_3: MbrPartitionTableEntry,
    partition_4: MbrPartitionTableEntry,
    signature: [u8; 2],
}

impl MasterBootRecord {
    const VALID_SIGNATURE: u16 = 0xAA55;

    pub const fn signature_is_valid(&self) -> bool {
        u16::from_le_bytes(self.signature) == Self::VALID_SIGNATURE
    }

    pub const fn partitions(&self) -> [&MbrPartitionTableEntry; 4] {
        [
            &self.partition_1,
            &self.partition_2,
            &self.partition_3,
            &self.partition_4,
        ]
    }

    pub const fn boot_code(&self) -> &[u8; 446] {
        &self.boot_code
    }
}
