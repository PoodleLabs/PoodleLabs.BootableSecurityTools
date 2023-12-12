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
    fat_entries::{FatEntry, FatEntryStatus},
};
use alloc::vec::Vec;
use core::{marker::PhantomData, mem::size_of};

pub struct DirectoryHandleBounds {
    start_offset: usize,
    entry_count: usize,
}

impl DirectoryHandleBounds {
    pub const fn from(start_offset: usize, entry_count: usize) -> Self {
        Self {
            start_offset,
            entry_count,
        }
    }
}

pub struct DirectoryHandle<'a, TBpb: FatBiosParameterBlock, TFatEntry: FatEntry> {
    phantom_entry: PhantomData<TFatEntry>,
    bounds: Option<DirectoryHandleBounds>,
    long_file_name: Option<LongFileName>,
    directory_entry: DirectoryEntry,
    bios_parameter_block: &'a TBpb,
    volume_root: *const u8,
}

impl<'a, TBpb: FatBiosParameterBlock, TFatEntry: FatEntry> DirectoryHandle<'a, TBpb, TFatEntry> {
    pub const fn from(
        bounds: Option<DirectoryHandleBounds>,
        long_file_name: Option<LongFileName>,
        directory_entry: DirectoryEntry,
        bios_parameter_block: &'a TBpb,
        volume_root: *const u8,
    ) -> Self {
        Self {
            phantom_entry: PhantomData,
            bios_parameter_block,
            directory_entry,
            long_file_name,
            volume_root,
            bounds,
        }
    }

    pub fn list_children(&self) -> Option<Vec<DirectoryHandle<'a, TBpb, TFatEntry>>> {
        let (mut offset, mut cluster, count, multi_cluster) = match &self.bounds {
            // FAT12/16 root directory has fixed bounds and isn't cluster based.
            Some(b) => (b.start_offset, 0, b.entry_count, false),
            // FAT32 root directory is cluster based, like any other directory.
            None => match self
                .bios_parameter_block
                .get_byte_offset_for_cluster(self.directory_entry.first_cluster() as usize)
            {
                Some(o) => (
                    o,
                    self.directory_entry.first_cluster() as usize,
                    (self.bios_parameter_block.sectors_per_cluster() as usize
                        * self.bios_parameter_block.bytes_per_sector() as usize)
                        / size_of::<DirectoryEntry>(),
                    true,
                ),
                // Cluster doesn't exist on disk; just return None.
                None => return None,
            },
        };

        // Grab the active FAT bytes.
        let fat = self.bios_parameter_block.active_fat_bytes(self.volume_root);

        // Prepare a vector to return children in.
        let mut return_vec = Vec::new();
        loop {
            // Grab the start and end of the directory entries in this cluster.
            let mut pointer = unsafe { self.volume_root.add(offset) as *const DirectoryEntry };
            let end = unsafe { pointer.add(count) };

            // Prepare a buffer for tracking LFN entries.
            let mut lfn = None;

            // Iterate until we reach the end of the directory entires, unless we exit early.
            while pointer < end {
                // Grab the current entry and check it's valid.
                let entry = unsafe { pointer.as_ref() }.unwrap();
                if entry.is_invalid() {
                    // Skip and move to the next entry.
                    pointer = unsafe { pointer.add(1) };
                    continue;
                }

                let attributes = entry.attributes();
                if attributes.is_long_file_name_entry() {
                    // Temporarily store the first LFN entry in any encountered chain.
                    if lfn.is_none() {
                        let lfn_entry =
                            unsafe { (pointer as *const LongFileNameDirectoryEntry).as_ref() }
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
                    // Any visible file or directory should be added to the list.
                    match entry.file_name().free_indicator() {
                        ShortFileNameFreeIndicator::NotFree => return_vec.push(Self::from(
                            None,
                            // Any LFN precedes the SFN entry, so we can just use whatever out current tracked LFN is (including None).
                            lfn,
                            entry.clone(),
                            self.bios_parameter_block,
                            self.volume_root,
                        )),
                        ShortFileNameFreeIndicator::IsolatedFree => {}
                        ShortFileNameFreeIndicator::FreeAndAllSubsequentEntriesFree => {
                            // All subsequent entries are free; we can exit early.
                            break;
                        }
                    }

                    // Reset the tracked LFN.
                    lfn = None;
                }

                // Move to the next entry.
                pointer = unsafe { pointer.add(1) };
            }

            if !multi_cluster {
                // For FAT12/16 root directories, we don't want to check for another cluster.
                // TODO: Handle backwards traversal?
                break;
            }

            // Grab the next cluster indicator from the FAT.
            let next = match TFatEntry::try_read_from(fat, cluster) {
                Some(e) => e,
                None => break,
            };

            // If there's no next cluster, or it's invalid, break early.
            if next.status() != FatEntryStatus::Link {
                break;
            }

            // Move on to the next cluster in the chain.
            cluster = next.into();
            offset = match self
                .bios_parameter_block
                .get_byte_offset_for_cluster(cluster)
            {
                Some(o) => o,
                None => break,
            }
        }

        Some(return_vec)
    }
}
