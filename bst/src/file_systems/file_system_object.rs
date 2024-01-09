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

use crate::bits::bit_field;
use alloc::vec::Vec;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileSystemObjectAttributes(u8);

impl FileSystemObjectAttributes {
    pub const READ_ONLY: Self = Self(0b00000001);
    pub const SYSTEM: Self = Self(0b00000010);
    pub const HIDDEN: Self = Self(0b00000100);
    pub const NONE: Self = Self(0b00000000);
}

bit_field!(FileSystemObjectAttributes);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileSystemObjectDateTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl FileSystemObjectDateTime {
    pub const fn from(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileSystemObjectType {
    Directory,
    File(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileSystemObject {
    last_modified: Option<FileSystemObjectDateTime>,
    attributes: FileSystemObjectAttributes,
    created: FileSystemObjectDateTime,
    object_type: FileSystemObjectType,
    name: Vec<u16>,
    start: u64,
}

impl FileSystemObject {
    pub const fn from(
        last_modified: Option<FileSystemObjectDateTime>,
        attributes: FileSystemObjectAttributes,
        created: FileSystemObjectDateTime,
        object_type: FileSystemObjectType,
        name: Vec<u16>,
        start: u64,
    ) -> Self {
        Self {
            last_modified,
            object_type,
            attributes,
            created,
            start,
            name,
        }
    }
}
