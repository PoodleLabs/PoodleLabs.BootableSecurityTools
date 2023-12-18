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

use crate::{
    bits::bit_field,
    file_systems::{block_device::BlockDevice, fat},
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::{marker::PhantomData, mem::size_of, slice};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EntryAttributes(u8);

impl EntryAttributes {
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

bit_field!(EntryAttributes);

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    name: fat::naming::short::Name,
    attributes: EntryAttributes,
    name_case_flags: fat::naming::short::CaseFlags,
    creation_time: fat::timekeeping::Time,
    creation_date: fat::timekeeping::Date,
    last_access_date: fat::timekeeping::Date,
    cluster_high: [u8; 2], // Upper bytes of the cluster number, always 0x00, 0x00 on FAT12/16
    last_write_time: fat::timekeeping::Time2sResolution,
    last_write_date: fat::timekeeping::Date,
    cluster_low: [u8; 2], // Lower bytes of the cluster number.
    file_size: [u8; 4],
}

impl Entry {
    pub const fn attributes(&self) -> &EntryAttributes {
        &self.attributes
    }

    pub const fn short_name(&self) -> &fat::naming::short::Name {
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
pub enum EntryClusterPointer {
    UnclusteredRoot,
    Cluster(usize),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EntryPointer {
    cluster: EntryClusterPointer,
    index: usize,
}

impl EntryPointer {
    pub const fn from(cluster: EntryClusterPointer, index: usize) -> Self {
        Self { cluster, index }
    }
}

//////////////////////////////////
// DIRECTORY OBJECT ENUMERATION //
//////////////////////////////////

fn next_object_in_cluster<'a>(
    lfn_part_buffer: &mut [Option<&'a fat::naming::long::NamePart>; 20],
    cluster_pointer: EntryClusterPointer,
    next_index: &mut usize,
    entries: &'a [Entry],
    skip_hidden: bool,
) -> Option<super::ObjectWithDirectoryEntryPointer<'a>> {
    loop {
        // Iterate over entries in the provided cluster.
        if *next_index >= entries.len() {
            // We've reached the end of the cluster without encountering a valid entry.
            return None;
        }

        let entry = &entries[*next_index];
        if entry.is_invalid() {
            // Skip invalid entries.
            *next_index += 1;
            continue;
        }

        match entry.short_name().free_indicator() {
            fat::naming::short::FreeIndicator::NotFree => {
                // We've encountered a non-free entry. Interrogate it.
                let attributes = entry.attributes();
                if attributes.is_volume_label() {
                    // Clear any entries in the LFN part buffer; any LFN followed by a volume label is invalid.
                    lfn_part_buffer.fill(None);

                    // Return a volume label object.
                    return Some(super::ObjectWithDirectoryEntryPointer::from(
                        EntryPointer::from(cluster_pointer, *next_index),
                        super::Object::VolumeLabel(entry.short_name()),
                    ));
                }

                if attributes.is_long_file_name_entry() {
                    // Interpret the entry as an LFN part.
                    let lfn_part = unsafe {
                        (entries.as_ptr().add(*next_index) as *const fat::naming::long::NamePart)
                            .as_ref()
                    }
                    .unwrap();

                    // LFNs can have inclusively between 1 and 20 parts, written in reverse order, with a 1-indexed 'order' value.
                    // Calculate the index this LFN part should be stored at in the LFN part buffer.
                    let index = 20 - lfn_part.ordering().number() as usize;
                    lfn_part_buffer[index] = Some(lfn_part);

                    // Any trailing LFN parts currently in the buffer are invalid, so clear them.
                    // An example where this fill would matter is:
                    // lfna2,lfna1,lfnb4,lfnb3,lfnb2,sfn
                    // Both LFNs are invalid, as the first is not followed by a sfn, and the second does not have all the lfn parts
                    // it should, as indicated by its 'order' values, but without the below fill, we'd end up with:
                    //lfnb4,lfnb3,lfnb2,lfna1,sfn
                    lfn_part_buffer[index + 1..].fill(None);

                    // Move to the next entry.
                    *next_index += 1;
                    continue;
                }

                if attributes.is_hidden() && skip_hidden {
                    // Discard any parts in the LFN part buffer; they point to a hidden file
                    // which we don't want to return according to the iterator params.
                    lfn_part_buffer.fill(None);

                    // Skip the entry.
                    *next_index += 1;
                    continue;
                }

                // Calculate the length of any LFN in the buffer by iterating backwards until we find an empty slot.
                let mut lfn_length = 0;
                for i in (0..20).rev() {
                    if lfn_part_buffer[i].is_none() {
                        break;
                    }

                    lfn_length += 1;
                }

                if lfn_length == 0 {
                    // No LFN parts are present. We can just return a short-named object.
                    return Some(super::ObjectWithDirectoryEntryPointer::from(
                        EntryPointer::from(cluster_pointer, *next_index),
                        super::Object::ShortNamedObject(entry),
                    ));
                }

                // There are parts in the LFN buffer. Calculate the number of empty LFN parts, given the fixed
                // part buffer length of 20 parts.
                let lfn_empty_part_count = 20 - lfn_length;

                // Extract the trailing LFN parts.
                let lfn_parts = &lfn_part_buffer[lfn_empty_part_count..];
                let long_named_object = super::LongNamedObject::from(lfn_parts, entry);
                if long_named_object.is_valid() {
                    // The LFN is valid. Create an owned output buffer.
                    let mut lfn_out = [None; 20];

                    // Copy the LFN parts into the output buffer.
                    lfn_out[lfn_empty_part_count..].copy_from_slice(lfn_parts);

                    // Clear the values in our working buffer.
                    lfn_part_buffer.fill(None);

                    // Return an long-named object.
                    return Some(super::ObjectWithDirectoryEntryPointer::from(
                        EntryPointer::from(cluster_pointer, *next_index),
                        super::Object::LongNamedObject((entry, lfn_empty_part_count, lfn_out)),
                    ));
                } else {
                    // The LFN is invalid; clear the buffer and just return a short-named object.
                    lfn_part_buffer.fill(None);

                    return Some(super::ObjectWithDirectoryEntryPointer::from(
                        EntryPointer::from(cluster_pointer, *next_index),
                        super::Object::ShortNamedObject(entry),
                    ));
                }
            }
            fat::naming::short::FreeIndicator::IsolatedFree => {
                // Skip isolated free entries.
                *next_index += 1;
                continue;
            }
            fat::naming::short::FreeIndicator::FreeAndAllSubsequentEntriesFree => {
                // There's no entry remaining in this cluster.
                return None;
            }
        }
    }
}

pub trait ChildIterator<'a>: Iterator<Item = super::ObjectWithDirectoryEntryPointer<'a>> {
    fn reset(&mut self);
}

pub struct FixedSizedDirectoryChildIterator<
    'a,
    TBlockDevice: BlockDevice,
    TMapEntry: fat::clustering::map::Entry,
> {
    volume_parameters: &'a fat::clustering::VolumeParameters<'a, TBlockDevice>,
    lfn_part_buffer: [Option<&'a fat::naming::long::NamePart>; 20],
    phantom_data: PhantomData<TMapEntry>,
    entry_count: usize,
    next_index: usize,
    skip_hidden: bool,
    buffer: Vec<u8>,
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: fat::clustering::map::Entry>
    FixedSizedDirectoryChildIterator<'a, TBlockDevice, TMapEntry>
{
    pub fn from(
        volume_parameters: &'a fat::clustering::VolumeParameters<'a, TBlockDevice>,
        entry_count: usize,
        start_index: usize,
        skip_hidden: bool,
    ) -> Self {
        Self {
            buffer: vec![0; entry_count * size_of::<fat::objects::directories::Entry>()],
            lfn_part_buffer: [None; 20],
            phantom_data: PhantomData,
            next_index: start_index,
            volume_parameters,
            entry_count,
            skip_hidden,
        }
    }
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: fat::clustering::map::Entry> Iterator
    for FixedSizedDirectoryChildIterator<'a, TBlockDevice, TMapEntry>
{
    type Item = super::ObjectWithDirectoryEntryPointer<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Read the directory's bytes from the block device.
        // Note: We do this on each iteration to reflect any changes to the disk,
        // though this is a performance trade-off we may want to reconsider eventually.
        if !self.volume_parameters.volume_root().read_bytes(
            self.volume_parameters.media_id(),
            self.volume_parameters.clustered_area_start() as u64,
            &mut self.buffer,
        ) {
            // Reading the directory bytes failed; end iteration.
            return None;
        }

        // Interpret the data in the directory buffer as directory entries.
        let entries = unsafe {
            slice::from_raw_parts(self.buffer.as_ptr() as *const Entry, self.entry_count)
        };

        self.lfn_part_buffer.fill(None);
        // We can handle fixed sized root directories by treating them as having a single, special cluster.
        match next_object_in_cluster(
            &mut self.lfn_part_buffer,
            EntryClusterPointer::UnclusteredRoot, // A fixed-sized directory is always the root directory.
            &mut self.next_index,
            entries,
            self.skip_hidden,
        ) {
            Some(e) => {
                // Increment the index so we don't return the same object repeatedly.
                self.next_index += 1;
                Some(e)
            }
            None => None,
        }
    }
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: fat::clustering::map::Entry> ChildIterator<'a>
    for FixedSizedDirectoryChildIterator<'a, TBlockDevice, TMapEntry>
{
    fn reset(&mut self) {
        self.next_index = 0;
    }
}

pub struct ClusteredDirectoryChildIterator<
    'a,
    TBlockDevice: BlockDevice,
    TMapEntry: fat::clustering::map::Entry,
> {
    volume_parameters: &'a fat::clustering::VolumeParameters<'a, TBlockDevice>,
    operating_cluster_info: Option<(usize, Box<[u8]>, Option<usize>)>,
    lfn_part_buffer: [Option<&'a fat::naming::long::NamePart>; 20],
    phantom_data: PhantomData<TMapEntry>,
    start_cluster: usize,
    next_index: usize,
    skip_hidden: bool,
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: fat::clustering::map::Entry>
    ClusteredDirectoryChildIterator<'a, TBlockDevice, TMapEntry>
{
    pub const fn from(
        volume_parameters: &'a fat::clustering::VolumeParameters<'a, TBlockDevice>,
        start_cluster: usize,
        start_index: usize,
        skip_hidden: bool,
    ) -> Self {
        Self {
            operating_cluster_info: None,
            lfn_part_buffer: [None; 20],
            phantom_data: PhantomData,
            next_index: start_index,
            volume_parameters,
            start_cluster,
            skip_hidden,
        }
    }
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: fat::clustering::map::Entry>
    ClusteredDirectoryChildIterator<'a, TBlockDevice, TMapEntry>
{
    fn change_operating_cluster(&mut self, cluster_index: usize) {
        self.next_index = 0;
        self.operating_cluster_info = match self
            .volume_parameters
            .read_cluster::<TMapEntry>(cluster_index)
        {
            fat::clustering::ReadResult::Link(d, n) => Some((cluster_index, d, Some(n))),
            fat::clustering::ReadResult::EndOfChain(d) => Some((cluster_index, d, None)),
            _ => None,
        };
    }
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: fat::clustering::map::Entry> Iterator
    for ClusteredDirectoryChildIterator<'a, TBlockDevice, TMapEntry>
{
    type Item = super::ObjectWithDirectoryEntryPointer<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.lfn_part_buffer.fill(None);
        match loop {
            // Iterate over the clusters composing the directory.
            let (current_cluster, cluster_content, next_cluster) =
                match &self.operating_cluster_info {
                    Some(d) => d,
                    None => return None,
                };

            let entries = unsafe {
                slice::from_raw_parts(
                    cluster_content.as_ptr() as *const Entry,
                    self.volume_parameters.directory_entries_per_cluster(),
                )
            };

            match next_object_in_cluster(
                &mut self.lfn_part_buffer,
                EntryClusterPointer::Cluster(*current_cluster),
                &mut self.next_index,
                entries,
                self.skip_hidden,
            ) {
                Some(v) => break Some(v),
                None => {
                    // No object was found in the remaining directory entries in the cluster.
                    match next_cluster {
                        // Move to the next cluster if there is one.
                        Some(n) => self.change_operating_cluster(*n),
                        // If there's no next cluster, there are no remaining objects.
                        None => break None,
                    }
                }
            };
        } {
            Some(v) => {
                // Increment the index so we don't return the same object repeatedly.
                self.next_index += 1;
                Some(v)
            }
            None => None,
        }
    }
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: fat::clustering::map::Entry> ChildIterator<'a>
    for ClusteredDirectoryChildIterator<'a, TBlockDevice, TMapEntry>
{
    fn reset(&mut self) {
        self.change_operating_cluster(self.start_cluster)
    }
}
