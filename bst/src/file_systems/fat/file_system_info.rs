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

#[derive(Clone)]
pub struct FileSystemInfo {
    lead_signature: [u8; 4],
    reserved_1: [u8; 480],
    struct_signature: [u8; 4],
    free_cluster_count: [u8; 4],
    next_free_cluster: [u8; 4],
    reserved_2: [u8; 12],
    tail_signature: [u8; 4],
}

impl FileSystemInfo {
    const VALID_STRUCT_SIGNATURE: u32 = 0x61417272;
    const VALID_LEAD_SIGNATURE: u32 = 0x41615252;
    const VALID_TAIL_SIGNATURE: u32 = 0xAA550000;
    const UNKNOWN_VALUE: u32 = 0xFFFFFFFF;

    pub const fn signature_is_valid(&self) -> bool {
        self.struct_signature() == Self::VALID_STRUCT_SIGNATURE
            && self.lead_signature() == Self::VALID_LEAD_SIGNATURE
            && self.tail_signature() == Self::VALID_TAIL_SIGNATURE
    }

    pub const fn free_cluster_count(&self) -> Option<u32> {
        let fcc = u32::from_le_bytes(self.free_cluster_count);
        if fcc == Self::UNKNOWN_VALUE {
            None
        } else {
            Some(fcc)
        }
    }

    pub const fn next_free_cluster(&self) -> Option<u32> {
        let nfc = u32::from_le_bytes(self.next_free_cluster);
        if nfc == Self::UNKNOWN_VALUE {
            None
        } else {
            Some(nfc)
        }
    }

    pub const fn struct_signature(&self) -> u32 {
        u32::from_le_bytes(self.struct_signature)
    }

    pub const fn lead_signature(&self) -> u32 {
        u32::from_le_bytes(self.lead_signature)
    }

    pub const fn tail_signature(&self) -> u32 {
        u32::from_le_bytes(self.tail_signature)
    }

    pub fn set_free_cluster_count(&mut self, value: u32) {
        self.free_cluster_count = value.to_le_bytes();
    }

    pub fn set_next_free_cluster(&mut self, value: u32) {
        self.next_free_cluster = value.to_le_bytes();
    }
}
