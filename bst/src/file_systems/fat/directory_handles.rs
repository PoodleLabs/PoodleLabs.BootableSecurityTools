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

use super::{
    bios_parameters_blocks::FatBiosParameterBlock,
    directory_entries::{
        DirectoryEntry, LongFileName, LongFileNameDirectoryEntry, ShortFileNameFreeIndicator,
    },
    fat_entries::FatEntry,
};
use alloc::vec::Vec;
use core::{marker::PhantomData, mem::size_of};

pub struct DirectoryHandle<'a, TBpb: FatBiosParameterBlock, TFatEntry: FatEntry> {
    phantom_entry: PhantomData<TFatEntry>,
    long_file_name: Option<LongFileName>,
    directory_entry: &'a DirectoryEntry,
    bios_parameter_block: &'a TBpb,
    volume_root: *const u8,
}

impl<'a, TBpb: FatBiosParameterBlock, TFatEntry: FatEntry> DirectoryHandle<'a, TBpb, TFatEntry> {
    pub const fn from(
        long_file_name: Option<LongFileName>,
        directory_entry: &'a DirectoryEntry,
        bios_parameter_block: &'a TBpb,
        volume_root: *const u8,
    ) -> Self {
        Self {
            phantom_entry: PhantomData,
            bios_parameter_block,
            directory_entry,
            long_file_name,
            volume_root,
        }
    }

    pub fn list_children(&self) -> Vec<DirectoryHandle<'a, TBpb, TFatEntry>> {
        let entries_per_cluster = (self.bios_parameter_block.sectors_per_cluster() as usize
            * self.bios_parameter_block.bytes_per_sector() as usize)
            / size_of::<DirectoryEntry>();

        let mut v = Vec::new();
        let mut c = self.directory_entry.first_cluster();
        loop {
            match self
                .bios_parameter_block
                .get_byte_offset_for_cluster(c as usize)
            {
                Some(o) => {
                    let mut pointer = unsafe { self.volume_root.add(o) as *const DirectoryEntry };
                    let end = unsafe { pointer.add(entries_per_cluster) };
                    let mut lfn = None;
                    while pointer < end {
                        let entry = unsafe { pointer.as_ref() }.unwrap();
                        if entry.is_invalid() {
                            pointer = unsafe { pointer.add(1) };
                            continue;
                        }

                        let attributes = entry.attributes();
                        if attributes.is_long_file_name_entry() {
                            if lfn.is_none() {
                                let lfn_entry = unsafe {
                                    (pointer as *const LongFileNameDirectoryEntry).as_ref()
                                }
                                .unwrap();

                                lfn = Some(LongFileName::from(
                                    pointer,
                                    lfn_entry.ordering().value() as usize,
                                ));
                            }
                        } else if !attributes.is_hidden()
                            && !attributes.is_volume_label()
                            && entry.file_name().is_valid()
                        {
                            match entry.file_name().free_indicator() {
                                ShortFileNameFreeIndicator::NotFree => v.push(Self::from(
                                    lfn,
                                    entry,
                                    self.bios_parameter_block,
                                    self.volume_root,
                                )),
                                ShortFileNameFreeIndicator::IsolatedFree => {}
                                ShortFileNameFreeIndicator::FreeAndAllSubsequentEntriesFree => {
                                    break;
                                }
                            }
                        }

                        pointer = unsafe { pointer.add(1) };
                    }
                }
                None => {}
            };

            let next = match TFatEntry::try_read_from(
                c as usize,
                self.volume_root,
                self.bios_parameter_block,
            ) {
                Some(e) => e,
                None => break,
            };

            if next.is_free() || next.is_bad_cluster() {
                break;
            }

            if next.is_end_of_chain() {
                break;
            }

            c = next.into();
        }

        v
    }
}
