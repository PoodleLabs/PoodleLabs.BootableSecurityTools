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
    clustering::{map::Entry, ReadResult, VolumeParameters},
    naming::{
        long::LongFileNameDirectoryEntry,
        short::{DirectoryEntryNameCaseFlags, ShortFileName, ShortFileNameFreeIndicator},
    },
    timekeeping::{FatDate, FatTime, FatTime2sResolution},
};
use crate::bits::bit_field;
use alloc::vec::Vec;
use core::{marker::PhantomData, slice};
use macros::s16;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DirectoryEntryClusterPointer {
    UnclusteredRoot,
    Cluster(usize),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DirectoryEntryPointer {
    cluster: DirectoryEntryClusterPointer,
    index: usize,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DirectoryEntryContent<'a> {
    ShortFileNameEntry(&'a DirectoryEntry),
    VolumeLabel(&'a ShortFileName),
    LongFileName(
        (
            &'a DirectoryEntry,
            usize,
            [Option<&'a LongFileNameDirectoryEntry>; 20],
        ),
    ),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DirectoryEntryDescriptor<'a> {
    content: DirectoryEntryContent<'a>,
    pointer: DirectoryEntryPointer,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DirectoryEntryAttributes(u8);

impl DirectoryEntryAttributes {
    pub const LONG_FILE_NAME_ENTRY: Self = Self(0x0F);
    pub const READ_ONLY: Self = Self(0x01);
    pub const HIDDEN: Self = Self(0x02);
    pub const SYSTEM: Self = Self(0x04);
    /// An entry with this attribute is the volume label. Only one entry can have this flag, in the root directory. Cluster and filesize values must all be set to zero.
    pub const VOLUME_LABEL: Self = Self(0x08);
    pub const DIRECTORY: Self = Self(0x10);
    /// A flag for backup utilities to detect changes. Should be set to 1 on any change, 0 by the backup utility on backup.
    pub const ARCHIVE: Self = Self(0x20);

    pub const fn is_long_file_name_entry(&self) -> bool {
        self.0 == Self::LONG_FILE_NAME_ENTRY.0
    }

    pub const fn is_read_only(&self) -> bool {
        self.encompasses(Self::READ_ONLY)
    }

    pub const fn is_hidden(&self) -> bool {
        self.overlaps(Self::HIDDEN)
    }

    pub const fn is_system_entry(&self) -> bool {
        self.overlaps(Self::SYSTEM)
    }

    pub const fn is_volume_label(&self) -> bool {
        self.overlaps(Self::VOLUME_LABEL)
    }

    pub const fn is_directory(&self) -> bool {
        self.overlaps(Self::DIRECTORY)
    }

    pub const fn updated_since_last_archive(&self) -> bool {
        self.overlaps(Self::ARCHIVE)
    }
}

bit_field!(DirectoryEntryAttributes);

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    name: ShortFileName,
    attributes: DirectoryEntryAttributes,
    name_case_flags: DirectoryEntryNameCaseFlags,
    creation_time: FatTime,
    creation_date: FatDate,
    last_access_date: FatDate,
    cluster_high: [u8; 2], // Upper bytes of the cluster number, always 0x00, 0x00 on FAT12/16
    last_write_time: FatTime2sResolution,
    last_write_date: FatDate,
    cluster_low: [u8; 2], // Lower bytes of the cluster number.
    file_size: [u8; 4],
}

impl DirectoryEntry {
    pub const fn attributes(&self) -> &DirectoryEntryAttributes {
        &self.attributes
    }

    pub const fn file_name(&self) -> &ShortFileName {
        &self.name
    }

    pub const fn file_size(&self) -> u32 {
        u32::from_le_bytes(self.file_size)
    }

    pub fn is_empty_file(&self) -> bool {
        self.file_size() == 0 && self.first_cluster() == 0
    }

    pub fn first_cluster(&self) -> u32 {
        let mut bytes = [0u8; 4];
        bytes[..2].copy_from_slice(&self.cluster_high);
        bytes[2..].copy_from_slice(&self.cluster_low);
        u32::from_le_bytes(bytes)
    }

    pub fn is_invalid(&self) -> bool {
        ((self.file_size() == 0) != (self.first_cluster() == 0)) || (self.first_cluster() == 1)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DirectoryEntryWithLfn<'a> {
    lfn_entries: &'a [Option<&'a LongFileNameDirectoryEntry>],
    sfn_entry: &'a DirectoryEntry,
}

impl<'a> DirectoryEntryWithLfn<'a> {
    pub const fn from(
        lfn_entries: &'a [Option<&'a LongFileNameDirectoryEntry>],
        sfn_entry: &'a DirectoryEntry,
    ) -> Self {
        Self {
            lfn_entries,
            sfn_entry,
        }
    }

    pub fn is_valid(&self) -> bool {
        // Calculate the sfn checksum each lfn entry must have.
        let expected_checksum = self.sfn_entry.file_name().checksum();
        for i in 0..self.lfn_entries.len() {
            let entry = match self.lfn_entries[i] {
                Some(e) => e,
                // There's a missing entry; the lfn is invalid.
                None => return false,
            };

            // Expect entries in reverse order, with 1-indexed 'order' value.
            let expected_order_value = (self.lfn_entries.len() - i) as u8;
            if !entry.is_valid(expected_checksum, expected_order_value) {
                return false;
            }

            if i == 0 && !entry.ordering().is_end() {
                // Check the first entry is marked correctly.
                return false;
            }
        }

        return true;
    }

    pub fn build_name(&self, null_terminate: bool) -> Vec<u16> {
        if !self.is_valid() {
            let mut invalid_name = Vec::from(s16!("INVALID LONG FILE NAME").content_slice());
            if null_terminate {
                invalid_name.push(0);
            }

            return invalid_name;
        }

        // Prepare a vector with adequate capacity to hold the entire name.
        let mut vec = Vec::with_capacity(
            self.lfn_entries
                .iter()
                .map(|e| {
                    LongFileNameDirectoryEntry::content_characters_from_raw_characters(
                        &e.unwrap().raw_characters(),
                    )
                    .len()
                })
                .sum::<usize>()
                + if null_terminate { 1 } else { 0 },
        );

        // Push all the content characters from the LFN entries in reverse order;
        // remember; they're stored on disk in reverse order.
        for i in (0..self.lfn_entries.len()).rev() {
            vec.extend(
                LongFileNameDirectoryEntry::content_characters_from_raw_characters(
                    &self.lfn_entries[i].unwrap().raw_characters(),
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
        &'a DirectoryEntry,
        usize,
        [Option<&'a LongFileNameDirectoryEntry>; 20],
    )> for DirectoryEntryWithLfn<'a>
{
    fn from(
        (sfn_entry, lfn_start_index, lfn_entries): &'a (
            &'a DirectoryEntry,
            usize,
            [Option<&'a LongFileNameDirectoryEntry>; 20],
        ),
    ) -> Self {
        Self::from(&lfn_entries[*lfn_start_index..], sfn_entry)
    }
}

fn next_directory_entry_in_cluster<'a>(
    lfn_buffer: &mut [Option<&'a LongFileNameDirectoryEntry>; 20],
    cluster_pointer: DirectoryEntryClusterPointer,
    directory_entries: &'a [DirectoryEntry],
    next_index: &mut usize,
    skip_hidden: bool,
) -> Option<DirectoryEntryDescriptor<'a>> {
    loop {
        // Iterate over entries in the provided cluster.
        if *next_index >= directory_entries.len() {
            // We've reached the end of the cluster without encountering an entry.
            return None;
        }

        let entry = &directory_entries[*next_index];
        if entry.is_invalid() {
            // Skip invalid entries.
            *next_index += 1;
            continue;
        }

        match entry.file_name().free_indicator() {
            ShortFileNameFreeIndicator::NotFree => {
                // We've encountered a non-free entry. Interrogate it.
                let attributes = entry.attributes();
                if attributes.is_volume_label() {
                    // Clear any entries in the LFN buffer; any followed by a volume label are invalid.
                    lfn_buffer.fill(None);

                    // Return the volume label.
                    return Some(DirectoryEntryDescriptor {
                        content: DirectoryEntryContent::VolumeLabel(entry.file_name()),
                        pointer: DirectoryEntryPointer {
                            cluster: cluster_pointer,
                            index: *next_index,
                        },
                    });
                }

                if attributes.is_long_file_name_entry() {
                    // Interpret the directory entry as a LFN entry.
                    let lfn_entry = unsafe {
                        (directory_entries.as_ptr().add(*next_index)
                            as *const LongFileNameDirectoryEntry)
                            .as_ref()
                    }
                    .unwrap();

                    // LFNs can have inclusively between 1 and 20 entries, and are in reverse order, with a 1 indexed ordering value.
                    // Calculate the index this LFN entry should be stored at in the LFN entry buffer.
                    let index = 20 - lfn_entry.ordering().value() as usize;
                    lfn_buffer[index] = Some(lfn_entry);

                    // Any trailing LFN entries currently in the buffer are invalid, so clear them.
                    // An example where this fill would matter is:
                    // lfna2,lfna1,lfnb4,lfnb3,lfnb2,sfn
                    // Both LFNs are invalid, as the first is not followed by a sfn, and the second does not have all the lfn entries,
                    // but without the below fill, we'd end up with lfnb4,lfnb3,lfnb2,lfna1,sfn.
                    lfn_buffer[index + 1..].fill(None);
                }

                if attributes.is_hidden() && skip_hidden {
                    // Discard any entries in the LFN buffer.
                    lfn_buffer.fill(None);

                    // Skip hidden entries.
                    *next_index += 1;
                    continue;
                }

                // Calculate the length of any LFN in the buffer by iterating backwards until we find an empty slot.
                let mut lfn_length = 0;
                for i in (0..20).rev() {
                    if lfn_buffer[i].is_none() {
                        break;
                    }

                    lfn_length += 1;
                }

                if lfn_length == 0 {
                    // No LFN buffer entries are set. We can just return a SFN entry.
                    return Some(DirectoryEntryDescriptor {
                        content: DirectoryEntryContent::ShortFileNameEntry(entry),
                        pointer: DirectoryEntryPointer {
                            cluster: cluster_pointer,
                            index: *next_index,
                        },
                    });
                }

                // There are entries in the LFN buffer. Calculate the start index.
                let lfn_start_index = 20 - lfn_length;

                // Extract the trailing LFN entries.
                let lfn_entries = &lfn_buffer[lfn_start_index..];
                let full_entry = DirectoryEntryWithLfn::from(lfn_entries, entry);
                if full_entry.is_valid() {
                    // The LFN is valid. Create an owned output buffer.
                    let mut lfn_out = [None; 20];

                    // Copy the LFN entries into the output buffer.
                    lfn_out[lfn_start_index..].copy_from_slice(lfn_entries);

                    // Clear the values in our working buffer.
                    lfn_buffer.fill(None);

                    // Return an LFN directory entry.
                    return Some(DirectoryEntryDescriptor {
                        content: DirectoryEntryContent::LongFileName((
                            entry,
                            lfn_start_index,
                            lfn_out,
                        )),
                        pointer: DirectoryEntryPointer {
                            cluster: cluster_pointer,
                            index: *next_index,
                        },
                    });
                } else {
                    // The LFN is invalid; clear the buffer and just return a SFN entry.
                    lfn_buffer.fill(None);
                    return Some(DirectoryEntryDescriptor {
                        content: DirectoryEntryContent::ShortFileNameEntry(entry),
                        pointer: DirectoryEntryPointer {
                            cluster: cluster_pointer,
                            index: *next_index,
                        },
                    });
                }
            }
            ShortFileNameFreeIndicator::IsolatedFree => {
                // Skip isolated free entries.
                *next_index += 1;
                continue;
            }
            ShortFileNameFreeIndicator::FreeAndAllSubsequentEntriesFree => {
                // There's no entry remaining in this cluster.
                return None;
            }
        }
    }
}

pub trait FatDirectoryEntryIterator<'a>: Iterator<Item = DirectoryEntryDescriptor<'a>> {
    fn reset(&mut self);
}

pub struct FatFixedSizeDirectoryEntryIterator<'a, TFatEntry: Entry> {
    lfn_buffer: [Option<&'a LongFileNameDirectoryEntry>; 20],
    volume_parameters: &'a VolumeParameters,
    phantom_data: PhantomData<TFatEntry>,
    directory_entry_count: usize,
    next_index: usize,
    skip_hidden: bool,
}

impl<'a, TFatEntry: Entry> Iterator for FatFixedSizeDirectoryEntryIterator<'a, TFatEntry> {
    type Item = DirectoryEntryDescriptor<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let directory_entries = unsafe {
            slice::from_raw_parts(
                self.volume_parameters
                    .volume_root()
                    .add(self.volume_parameters.clustered_area_start())
                    as *const DirectoryEntry,
                self.directory_entry_count,
            )
        };

        self.lfn_buffer.fill(None);
        // We can handle fixed sized root directories by treating them as having a single, special cluster.
        match next_directory_entry_in_cluster(
            &mut self.lfn_buffer,
            DirectoryEntryClusterPointer::UnclusteredRoot,
            directory_entries,
            &mut self.next_index,
            self.skip_hidden,
        ) {
            Some(e) => {
                // We don't want to return this entry in the next call; bump the next index.
                self.next_index += 1;
                Some(e)
            }
            None => None,
        }
    }
}

impl<'a, TFatEntry: Entry> FatDirectoryEntryIterator<'a>
    for FatFixedSizeDirectoryEntryIterator<'a, TFatEntry>
{
    fn reset(&mut self) {
        self.next_index = 0;
    }
}

pub struct FatClusterBasedDirectoryEntryIterator<'a, TFatEntry: Entry> {
    current_cluster_data: Option<(usize, &'a [u8], Option<usize>)>,
    lfn_buffer: [Option<&'a LongFileNameDirectoryEntry>; 20],
    volume_parameters: &'a VolumeParameters,
    phantom_data: PhantomData<TFatEntry>,
    entries_per_cluster: usize,
    start_cluster: usize,
    next_index: usize,
    skip_hidden: bool,
}

impl<'a, TFatEntry: Entry> FatClusterBasedDirectoryEntryIterator<'a, TFatEntry> {
    fn set_current_cluster(&mut self, cluster_index: usize) {
        self.next_index = 0;
        self.current_cluster_data = match self
            .volume_parameters
            .read_cluster::<TFatEntry>(cluster_index)
        {
            ReadResult::Link(d, n) => Some((cluster_index, d, Some(n))),
            ReadResult::EndOfChain(d) => Some((cluster_index, d, None)),
            _ => None,
        };
    }
}

impl<'a, TFatEntry: Entry> Iterator for FatClusterBasedDirectoryEntryIterator<'a, TFatEntry> {
    type Item = DirectoryEntryDescriptor<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.lfn_buffer.fill(None);
        match loop {
            // Iterate over the clusters composing the directory.
            let (current_cluster, cluster_content, next_cluster) = match self.current_cluster_data {
                Some(d) => d,
                None => return None,
            };

            let directory_entries = unsafe {
                slice::from_raw_parts(
                    cluster_content.as_ptr() as *const DirectoryEntry,
                    self.entries_per_cluster,
                )
            };

            match next_directory_entry_in_cluster(
                &mut self.lfn_buffer,
                DirectoryEntryClusterPointer::Cluster(current_cluster),
                directory_entries,
                &mut self.next_index,
                self.skip_hidden,
            ) {
                Some(v) => break Some(v),
                None => {
                    // No returnable entry was found in the remaining entries in the cluster.
                    match next_cluster {
                        // Move to the next cluster if there is one.
                        Some(n) => self.set_current_cluster(n),
                        // If there's no next cluster, there's no next value.
                        None => break None,
                    }
                }
            };
        } {
            Some(v) => {
                // We don't want to return this entry in the next call; bump the next index.
                self.next_index += 1;
                Some(v)
            }
            None => None,
        }
    }
}

impl<'a, TFatEntry: Entry> FatDirectoryEntryIterator<'a>
    for FatClusterBasedDirectoryEntryIterator<'a, TFatEntry>
{
    fn reset(&mut self) {
        self.set_current_cluster(self.start_cluster)
    }
}
