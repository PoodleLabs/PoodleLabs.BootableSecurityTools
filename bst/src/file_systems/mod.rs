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

mod exfat;
mod fat;
mod master_boot_record;

#[repr(u8)]
#[derive(Copy, Clone)]
enum BootSectorExtendedBootSignature {
    V4_0 = 0x28,
    V4_1 = 0x29,
    V8_0 = 0x80,
}

impl BootSectorExtendedBootSignature {
    pub const fn has_extended_fields(&self) -> bool {
        *self as u8 >= 0x29
    }
}
