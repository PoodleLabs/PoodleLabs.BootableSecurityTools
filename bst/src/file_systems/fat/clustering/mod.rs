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

use crate::file_systems::{block_device::BlockDevice, fat};
use alloc::{boxed::Box, vec::Vec};
use core::{marker::PhantomData, mem::size_of};

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

pub struct VolumeParameters<'a, TBlockDevice: BlockDevice> {
    block_device: &'a TBlockDevice,
    root_directory_value: usize,
    sectors_per_cluster: usize,
    fat_entry_buffer: Vec<u8>,
    active_map: Option<usize>,
    bytes_per_sector: usize,
    reserved_sectors: usize,
    sectors_per_map: usize,
    sector_count: usize,
    map_count: usize,
    media_type: u8,
    media_id: u32,
}

impl<'a, TBlockDevice: BlockDevice> VolumeParameters<'a, TBlockDevice> {
    pub fn from(
        block_device: &'a TBlockDevice,
        root_directory_value: usize,
        sectors_per_cluster: usize,
        active_map: Option<usize>,
        bytes_per_sector: usize,
        reserved_sectors: usize,
        sectors_per_map: usize,
        sector_count: usize,
        map_count: usize,
        media_type: u8,
        media_id: u32,
    ) -> Self {
        Self {
            fat_entry_buffer: Vec::with_capacity(3),
            root_directory_value,
            sectors_per_cluster,
            bytes_per_sector,
            reserved_sectors,
            sectors_per_map,
            sector_count,
            block_device,
            active_map,
            map_count,
            media_type,
            media_id,
        }
    }

    pub const fn directory_entries_per_cluster(&self) -> usize {
        (self.sectors_per_cluster * self.bytes_per_sector)
            / size_of::<fat::objects::directories::Entry>()
    }

    pub const fn root_directory_value(&self) -> usize {
        self.root_directory_value
    }

    pub const fn block_device(&self) -> &TBlockDevice {
        self.block_device
    }

    pub const fn sectors_per_cluster(&self) -> usize {
        self.sectors_per_cluster
    }

    pub const fn bytes_per_sector(&self) -> usize {
        self.bytes_per_sector
    }

    pub const fn map_area_start(&self) -> usize {
        self.reserved_sectors * self.bytes_per_sector
    }

    pub const fn map_size(&self) -> usize {
        self.bytes_per_sector * self.sectors_per_map
    }

    pub const fn media_type(&self) -> u8 {
        self.media_type
    }

    pub const fn media_id(&self) -> u32 {
        self.media_id
    }

    pub const fn clustered_area_start(&self) -> usize {
        self.map_area_start() + (self.map_size() * self.map_count)
    }

    pub const fn cluster_count(&self) -> usize {
        let clustered_sector_count =
            self.sector_count - self.reserved_sectors - (self.map_count * self.sectors_per_map);
        clustered_sector_count / self.sectors_per_cluster
    }

    pub fn read_map_entry<TMapEntry: map::Entry>(&mut self, index: usize) -> Option<TMapEntry> {
        let address = TMapEntry::get_address_for(index);

        self.fat_entry_buffer.fill(0);
        self.fat_entry_buffer.resize(address.byte_count(), 0);
        if !self.block_device.read_bytes(
            self.media_id,
            (self.map_area_start() + address.map_byte()) as u64,
            &mut self.fat_entry_buffer,
        ) {
            return None;
        }

        TMapEntry::try_read_from(address, &self.fat_entry_buffer)
    }

    pub fn read_cluster<TMapEntry: map::Entry>(&mut self, index: usize) -> ReadResult {
        match self.read_map_entry::<TMapEntry>(index) {
            Some(e) => ReadResult::from(self, e, index),
            None => ReadResult::OutOfBounds,
        }
    }
}

pub struct LinearIterator<'a, TBlockDevice: BlockDevice, TMapEntry: map::Entry> {
    volume_parameters: &'a mut VolumeParameters<'a, TBlockDevice>,
    phantom_data: PhantomData<TMapEntry>,
    next_index: usize,
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: map::Entry>
    LinearIterator<'a, TBlockDevice, TMapEntry>
{
    pub fn from(
        volume_parameters: &'a mut VolumeParameters<'a, TBlockDevice>,
        next_index: usize,
    ) -> Self {
        Self {
            phantom_data: PhantomData,
            volume_parameters,
            next_index,
        }
    }
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: map::Entry> Iterator
    for LinearIterator<'a, TBlockDevice, TMapEntry>
{
    type Item = ReadResult;

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

pub struct ChainIterator<'a, TBlockDevice: BlockDevice, TMapEntry: map::Entry> {
    volume_parameters: &'a mut VolumeParameters<'a, TBlockDevice>,
    phantom_data: PhantomData<TMapEntry>,
    next_index: usize,
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: map::Entry>
    ChainIterator<'a, TBlockDevice, TMapEntry>
{
    pub fn from(
        volume_parameters: &'a mut VolumeParameters<'a, TBlockDevice>,
        next_index: usize,
    ) -> Self {
        Self {
            phantom_data: PhantomData,
            volume_parameters,
            next_index,
        }
    }
}

impl<'a, TBlockDevice: BlockDevice, TMapEntry: map::Entry> Iterator
    for ChainIterator<'a, TBlockDevice, TMapEntry>
{
    type Item = ReadResult;

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
pub enum ReadResult {
    OutOfBounds,
    ReadError,
    Free,
    Reserved(Box<[u8]>),
    EndOfChain(Box<[u8]>),
    BadCluster(Box<[u8]>),
    Link(Box<[u8]>, usize),
}

impl ReadResult {
    pub fn from<'a, TBlockDevice: BlockDevice, TMapEntry: map::Entry>(
        parameters: &'a VolumeParameters<'a, TBlockDevice>,
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
            let mut buffer = Box::from_iter((0..size).map(|_| 0u8));
            if parameters
                .block_device()
                .read_bytes(parameters.media_id, offset as u64, &mut buffer)
            {
                buffer
            } else {
                return Self::ReadError;
            }
        };

        match map_entry_type {
            map::EntryType::Free => Self::Free,
            map::EntryType::Reserved => Self::Reserved(data.into()),
            map::EntryType::Link => Self::Link(data.into(), map_entry.into()),
            map::EntryType::BadCluster => Self::BadCluster(data.into()),
            map::EntryType::EndOfChain => Self::EndOfChain(data.into()),
        }
    }
}
