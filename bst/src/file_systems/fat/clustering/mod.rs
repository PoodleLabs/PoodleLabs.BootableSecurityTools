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

pub mod map;

use core::{marker::PhantomData, slice};

// FAT filesystems operate on a cluster-based system. Files and directories are made up of
// cluster chains, with a map at the beginning of the volume to the next cluster in the chain
// you're currently following. A simplified demonstration is:
// MAP:
// 0: 1
// 1: 3
// 2: 4
// 3: END
// 4: END
// CLUSTERS:
// 0: "Hello"
// 1: " Worl"
// 2: "Foo, "
// 3: "d!"
// 4: "Bar!"
//
// The above 'filesystem' has two distinct 'files': "Hello World!", and "Foo Bar!".
// FAT12 has 12 bit cluster addresses, FAT16 has 16 bit cluster addresses, and FAT32 has 32 bit cluster addresses,
// though in the case of FAT32, the first 4 bits are reserved. A cluster can be an arbitrary size; FAT volumes are
// divided into clusters, which are sub-divided into sectors, the size of each determined by the 'parameter block'
// at the beginning of the volume. A common configuration is 512 byte sectors, with 4 sectors per cluster.

pub struct VolumeParameters {
    sectors_per_cluster: usize,
    active_map: Option<usize>,
    bytes_per_sector: usize,
    reserved_sectors: usize,
    volume_root: *const u8,
    sectors_per_map: usize,
    sector_count: usize,
    map_count: usize,
}

impl VolumeParameters {
    pub const fn sectors_per_cluster(&self) -> usize {
        self.sectors_per_cluster
    }

    pub const fn bytes_per_sector(&self) -> usize {
        self.bytes_per_sector
    }

    pub const fn volume_root(&self) -> *const u8 {
        self.volume_root
    }

    pub const fn map_area_start(&self) -> usize {
        self.reserved_sectors * self.bytes_per_sector
    }

    pub const fn map_size(&self) -> usize {
        self.bytes_per_sector * self.sectors_per_map
    }

    pub const fn active_map_bytes(&self) -> &[u8] {
        let map_size = self.map_size();
        let map_offset = self.map_area_start()
            + (match self.active_map {
                Some(i) => i,
                None => 0,
            } * map_size);

        unsafe { slice::from_raw_parts(self.volume_root.add(map_offset), map_size) }
    }

    pub const fn clustered_area_start(&self) -> usize {
        self.map_area_start() + (self.map_size() * self.map_count)
    }

    pub const fn cluster_count(&self) -> usize {
        let clustered_sector_count =
            self.sector_count - self.reserved_sectors - (self.map_count * self.sectors_per_map);
        clustered_sector_count / self.sectors_per_cluster
    }

    pub fn read_cluster<TMapEntry: map::Entry>(&self, index: usize) -> ReadResult {
        match TMapEntry::try_read_from(self.active_map_bytes(), index) {
            Some(e) => ReadResult::from(self, e, index),
            None => ReadResult::OutOfBounds,
        }
    }
}

pub struct LinearIterator<'a, TMapEntry: map::Entry> {
    volume_parameters: &'a VolumeParameters,
    phantom_data: PhantomData<TMapEntry>,
    next_index: usize,
}

impl<'a, TMapEntry: map::Entry> LinearIterator<'a, TMapEntry> {
    pub const fn from(volume_parameters: &'a VolumeParameters, next_index: usize) -> Self {
        Self {
            phantom_data: PhantomData,
            volume_parameters,
            next_index,
        }
    }
}

impl<'a, TMapEntry: map::Entry> Iterator for LinearIterator<'a, TMapEntry> {
    type Item = ReadResult<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self
            .volume_parameters
            .read_cluster::<TMapEntry>(self.next_index);
        if result == ReadResult::OutOfBounds {
            return None;
        }

        self.next_index += 1;
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.volume_parameters.cluster_count();
        (count, Some(count))
    }
}

pub struct ChainIterator<'a, TMapEntry: map::Entry> {
    volume_parameters: &'a VolumeParameters,
    phantom_data: PhantomData<TMapEntry>,
    next_index: usize,
}

impl<'a, TMapEntry: map::Entry> ChainIterator<'a, TMapEntry> {
    pub const fn from(volume_parameters: &'a VolumeParameters, next_index: usize) -> Self {
        Self {
            phantom_data: PhantomData,
            volume_parameters,
            next_index,
        }
    }
}

impl<'a, TMapEntry: map::Entry> Iterator for ChainIterator<'a, TMapEntry> {
    type Item = ReadResult<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self
            .volume_parameters
            .read_cluster::<TMapEntry>(self.next_index);
        if result == ReadResult::OutOfBounds {
            return None;
        }

        self.next_index = match result {
            ReadResult::Link(_, n) => n,
            _ => usize::MAX,
        };

        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let cluster_count = self.volume_parameters.cluster_count();
        (cluster_count, Some(cluster_count))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadResult<'a> {
    OutOfBounds,
    Free,
    Reserved(&'a [u8]),
    EndOfChain(&'a [u8]),
    BadCluster(&'a [u8]),
    Link(&'a [u8], usize),
}

impl<'a> ReadResult<'a> {
    pub fn from<TMapEntry: map::Entry>(
        parameters: &'a VolumeParameters,
        map_entry: TMapEntry,
        index: usize,
    ) -> Self {
        let map_entry_type = map_entry.entry_type();
        if map_entry_type == map::EntryType::Free {
            return Self::Free;
        }

        let data = if index >= parameters.cluster_count() {
            return Self::OutOfBounds;
        } else {
            let size = parameters.bytes_per_sector() * parameters.sectors_per_cluster();
            let offset = parameters.clustered_area_start() + (size * index);

            unsafe { slice::from_raw_parts(parameters.volume_root().add(offset), size) }
        };

        match map_entry_type {
            map::EntryType::Free => Self::Free,
            map::EntryType::Reserved => Self::Reserved(data),
            map::EntryType::Link => Self::Link(data, map_entry.into()),
            map::EntryType::BadCluster => Self::BadCluster(data),
            map::EntryType::EndOfChain => Self::EndOfChain(data),
        }
    }
}
