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

use alloc::{boxed::Box, vec::Vec};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FilePathPart {
    description_address: Option<u64>,
    content: Box<[u16]>,
}

impl FilePathPart {
    pub const fn from(description_address: Option<u64>, content: Box<[u16]>) -> Self {
        Self {
            description_address,
            content,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FilePath(Vec<FilePathPart>);

impl FilePath {
    pub const fn from(parts: Vec<FilePathPart>) -> Self {
        Self(parts)
    }
}

impl From<Vec<FilePathPart>> for FilePath {
    fn from(value: Vec<FilePathPart>) -> Self {
        Self::from(value)
    }
}

impl Into<Vec<FilePathPart>> for FilePath {
    fn into(self) -> Vec<FilePathPart> {
        self.0
    }
}
