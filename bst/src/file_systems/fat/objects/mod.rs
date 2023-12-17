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

pub mod directories;

use crate::file_systems::fat;
use alloc::vec::Vec;
use macros::s16;

// FAT filesystems can contain three types of objects in their clustered area:
// 1. Files
// 2. Directories
// 3. Volume Labels
// Only one volume label can exist, inside the root directory of the volume.
// Files and directories point to a cluster chain, containing their content.
// The content for a file is arbitrary, while a directory's content is always
// a list of directories and files. All files and directories are defined as
// entries in a directory, except for the root directory, whose location is
// defined in the parameter block of the volume (and, in the case of FAT12
// and FAT16, a fixed maximum number of entries is defined, while the FAT32
// root directory is built from a cluster chain like any other directory).

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Object<'a> {
    VolumeLabel(&'a fat::naming::short::Name),
    ShortNamedObject(&'a directories::Entry),
    LongNamedObject(
        (
            &'a directories::Entry,
            usize,
            [Option<&'a fat::naming::long::NamePart>; 20],
        ),
    ),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ObjectWithDirectoryEntryPointer<'a> {
    directory_entry_pointer: directories::EntryPointer,
    object: Object<'a>,
}

impl<'a> ObjectWithDirectoryEntryPointer<'a> {
    pub const fn from(
        directory_entry_pointer: directories::EntryPointer,
        object: Object<'a>,
    ) -> Self {
        Self {
            directory_entry_pointer,
            object,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct LongNamedObject<'a> {
    lfn_parts: &'a [Option<&'a fat::naming::long::NamePart>],
    description: &'a directories::Entry,
}

impl<'a> LongNamedObject<'a> {
    pub const fn from(
        lfn_parts: &'a [Option<&'a fat::naming::long::NamePart>],
        description: &'a directories::Entry,
    ) -> Self {
        Self {
            description,
            lfn_parts,
        }
    }

    pub fn is_valid(&self) -> bool {
        // Calculate the sfn checksum each lfn entry must have.
        let expected_checksum = self.description.short_name().checksum();
        for i in 0..self.lfn_parts.len() {
            let part = match self.lfn_parts[i] {
                Some(e) => e,
                // There's a missing entry; the lfn is invalid.
                None => return false,
            };

            // Expect entries in reverse order, with 1-indexed 'order' value.
            let expected_order_value = (self.lfn_parts.len() - i) as u8;
            if !part.is_valid(expected_checksum, expected_order_value) {
                return false;
            }

            if i == 0 && !part.ordering().is_final_part() {
                // Check the first entry is marked correctly.
                return false;
            }
        }

        return true;
    }

    pub fn build_string(&self, null_terminate: bool) -> Vec<u16> {
        if !self.is_valid() {
            let mut invalid_name = Vec::from(s16!("INVALID LONG FILE NAME").content_slice());
            if null_terminate {
                invalid_name.push(0);
            }

            return invalid_name;
        }

        // Prepare a vector with adequate capacity to hold the entire name.
        let mut vec = Vec::with_capacity(
            self.lfn_parts
                .iter()
                .map(|p| {
                    fat::naming::long::NamePart::content_characters_from_raw_characters(
                        &p.unwrap().raw_characters(),
                    )
                    .len()
                })
                .sum::<usize>()
                + if null_terminate { 1 } else { 0 },
        );

        // Push all the content characters from the LFN entries in reverse order;
        // remember; they're stored on disk in reverse order.
        for i in (0..self.lfn_parts.len()).rev() {
            vec.extend(
                fat::naming::long::NamePart::content_characters_from_raw_characters(
                    &self.lfn_parts[i].unwrap().raw_characters(),
                ),
            );
        }

        if null_terminate {
            vec.push(0);
        }

        vec
    }
}

impl<'a>
    From<&'a (
        &'a directories::Entry,
        usize,
        [Option<&'a fat::naming::long::NamePart>; 20],
    )> for LongNamedObject<'a>
{
    fn from(
        (description, empty_lfn_part_count, lfn_parts): &'a (
            &'a directories::Entry,
            usize,
            [Option<&'a fat::naming::long::NamePart>; 20],
        ),
    ) -> Self {
        Self::from(&lfn_parts[*empty_lfn_part_count..], description)
    }
}
