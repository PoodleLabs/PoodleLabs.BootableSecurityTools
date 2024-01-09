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

use super::FileSystemObject;
use alloc::boxed::Box;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryReadResult {
    NotFound,
    NotADirectory,
    Success(Box<[FileSystemObject]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileReadResult {
    NotFound,
    NotAFile,
    Success(u64, bool),
}

pub trait FileSystemReader {
    fn volume_label(&self) -> Option<Box<[u16]>>;

    fn root_objects(&self) -> Box<[FileSystemObject]>;

    fn read_description_at(&self, address: u64) -> Option<FileSystemObject>;

    fn read_directory_objects(&self, directory: &FileSystemObject) -> DirectoryReadResult;

    fn read_file_content(&self, file: &FileSystemObject, buffer: &mut [u8]) -> FileReadResult;
}
