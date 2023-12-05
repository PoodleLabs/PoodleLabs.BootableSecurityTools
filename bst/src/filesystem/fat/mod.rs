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

mod bios_parameters_blocks;
mod boot_sectors;
mod directory_entries;
mod fat_entries;

// This FAT implementation was written based on the FatFs documentation,
// which can be found at: http://elm-chan.org/fsw/ff/00index_e.html.

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FatErrors {
    None,
    VolumeDirty,
    HardError,
    InvalidErrorFatEntry,
    InvalidMediaFatEntry,
    Unreadable,
}
