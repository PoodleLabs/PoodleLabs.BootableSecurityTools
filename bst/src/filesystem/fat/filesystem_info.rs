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

pub struct FilesystemInfo {
    lead_signature: u32,
    reserved_1: [u8; 480],
    struct_signature: u32,
    free_cluster_count: u32,
    next_free_cluster: u32,
    reserved_2: [u8; 12],
    tail_signature: u32,
}

impl FilesystemInfo {
    const VALID_STRUCT_SIGNATURE: u32 = 0x61417272;
    const VALID_LEAD_SIGNATURE: u32 = 0x41615252;
    const VALID_TAIL_SIGNATURE: u32 = 0xAA550000;
    const UNKNOWN_VALUE: u32 = 0xFFFFFFFF;

    pub const fn signature_is_valid(&self) -> bool {
        self.struct_signature == Self::VALID_STRUCT_SIGNATURE
            && self.lead_signature == Self::VALID_LEAD_SIGNATURE
            && self.tail_signature == Self::VALID_TAIL_SIGNATURE
    }

    pub const fn free_cluster_count(&self) -> Option<u32> {
        if self.free_cluster_count == Self::UNKNOWN_VALUE {
            None
        } else {
            Some(self.free_cluster_count)
        }
    }

    pub const fn next_free_cluster(&self) -> Option<u32> {
        if self.next_free_cluster == Self::UNKNOWN_VALUE {
            None
        } else {
            Some(self.next_free_cluster)
        }
    }

    pub fn set_free_cluster_count(&mut self, value: u32) {
        self.free_cluster_count = value;
    }

    pub fn set_next_free_cluster(&mut self, value: u32) {
        self.next_free_cluster = value;
    }
}
