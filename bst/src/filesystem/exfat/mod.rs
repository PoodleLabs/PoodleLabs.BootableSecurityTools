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

const JUMP_BOOT: [u8; 3] = [0xEB, 0x76, 0x90];
const FILE_SYSTEM_NAME: &[u8; 8] = b"EXFAT \0\0";
const BLANK: [u8; 53] = [0u8; 53];

#[repr(packed)]
struct ExfatBootSector {
    jump_boot: [u8; 3],
    file_system_name: [u8; 8],
    blank: [u8; 53],
}
