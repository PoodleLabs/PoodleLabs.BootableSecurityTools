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

use super::fat_entries::FatEntry;
use crate::file_systems::fat::fat_entries::FatEntryStatus;
use core::{marker::PhantomData, slice};

pub struct FatVolumeParameters {
    sectors_per_cluster: usize,
    active_fat: Option<usize>,
    bytes_per_sector: usize,
    reserved_sectors: usize,
    volume_root: *const u8,
    sectors_per_fat: usize,
    sector_count: usize,
    fat_count: usize,
}

pub struct LinearFatEntryIterator<'a, TFatEntry: FatEntry> {
    volume_parameters: &'a FatVolumeParameters,
    phantom_data: PhantomData<TFatEntry>,
    next_index: usize,
}

impl<'a, TFatEntry: FatEntry> Iterator for LinearFatEntryIterator<'a, TFatEntry> {
    type Item = TFatEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = match TFatEntry::try_read_from(
            active_fat_bytes(self.volume_parameters),
            self.next_index,
        ) {
            Some(e) => e,
            None => return None,
        };

        self.next_index += 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let fat_entries = (fat_size(self.volume_parameters) * 8) / TFatEntry::bits_per_digit();
        (fat_entries, Some(fat_entries))
    }
}

pub struct FatEntryChainIterator<'a, TFatEntry: FatEntry> {
    volume_parameters: &'a FatVolumeParameters,
    phantom_data: PhantomData<TFatEntry>,
    next_index: usize,
}

impl<'a, TFatEntry: FatEntry> Iterator for FatEntryChainIterator<'a, TFatEntry> {
    type Item = TFatEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = match TFatEntry::try_read_from(
            active_fat_bytes(self.volume_parameters),
            self.next_index,
        ) {
            Some(e) => e,
            None => return None,
        };

        self.next_index = entry.into();
        Some(entry)
    }
}

pub struct LinearFatClusterIterator<'a, TFatEntry: FatEntry> {
    volume_parameters: &'a FatVolumeParameters,
    phantom_data: PhantomData<TFatEntry>,
    next_index: usize,
}

impl<'a, TFatEntry: FatEntry> Iterator for LinearFatClusterIterator<'a, TFatEntry> {
    type Item = ClusterReadResult<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = read_cluster::<TFatEntry>(self.volume_parameters, self.next_index);
        if result == ClusterReadResult::OutOfBounds {
            return None;
        }

        self.next_index += 1;
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let cluster_count = cluster_count(self.volume_parameters);
        (cluster_count, Some(cluster_count))
    }
}

pub struct FatClusterChainIterator<'a, TFatEntry: FatEntry> {
    volume_parameters: &'a FatVolumeParameters,
    phantom_data: PhantomData<TFatEntry>,
    next_index: usize,
}

impl<'a, TFatEntry: FatEntry> Iterator for FatClusterChainIterator<'a, TFatEntry> {
    type Item = ClusterReadResult<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = read_cluster::<TFatEntry>(self.volume_parameters, self.next_index);
        if result == ClusterReadResult::OutOfBounds {
            return None;
        }

        self.next_index = match result {
            ClusterReadResult::Link(_, n) => n,
            _ => usize::MAX,
        };

        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let cluster_count = cluster_count(self.volume_parameters);
        (cluster_count, Some(cluster_count))
    }
}

pub trait FatFileSystemReader {
    type FatEntry: FatEntry;

    fn volume_parameters(&self) -> &FatVolumeParameters;

    fn iter_fat_entries_linear(&self) -> LinearFatEntryIterator<'_, Self::FatEntry> {
        self.iter_fat_entries_linear_from(0)
    }

    fn iter_fat_entries_linear_from(
        &self,
        start_index: usize,
    ) -> LinearFatEntryIterator<'_, Self::FatEntry> {
        LinearFatEntryIterator {
            phantom_data: PhantomData::<Self::FatEntry>,
            volume_parameters: self.volume_parameters(),
            next_index: start_index,
        }
    }

    fn iter_fat_entry_chain(
        &self,
        start_index: usize,
    ) -> FatEntryChainIterator<'_, Self::FatEntry> {
        FatEntryChainIterator {
            phantom_data: PhantomData::<Self::FatEntry>,
            volume_parameters: self.volume_parameters(),
            next_index: start_index,
        }
    }

    fn iter_fat_clusters_linear(&self) -> LinearFatClusterIterator<'_, Self::FatEntry> {
        self.iter_fat_clusters_linear_from(0)
    }

    fn iter_fat_clusters_linear_from(
        &self,
        start_index: usize,
    ) -> LinearFatClusterIterator<'_, Self::FatEntry> {
        LinearFatClusterIterator {
            phantom_data: PhantomData::<Self::FatEntry>,
            volume_parameters: self.volume_parameters(),
            next_index: start_index,
        }
    }

    fn iter_fat_cluster_chain(
        &self,
        start_index: usize,
    ) -> FatClusterChainIterator<'_, Self::FatEntry> {
        FatClusterChainIterator {
            phantom_data: PhantomData::<Self::FatEntry>,
            volume_parameters: self.volume_parameters(),
            next_index: start_index,
        }
    }
}

// Layout calculations.

const fn clustered_sector_count(parameters: &FatVolumeParameters) -> usize {
    parameters.sector_count
        - parameters.reserved_sectors
        - (parameters.fat_count * parameters.sectors_per_fat)
}

const fn clustered_area_start(parameters: &FatVolumeParameters) -> usize {
    fat_area_start(parameters) + (fat_size(parameters) * parameters.fat_count)
}

const fn fat_area_start(parameters: &FatVolumeParameters) -> usize {
    parameters.reserved_sectors * parameters.bytes_per_sector
}

const fn cluster_count(parameters: &FatVolumeParameters) -> usize {
    clustered_sector_count(parameters) / parameters.sectors_per_cluster
}

const fn cluster_size(parameters: &FatVolumeParameters) -> usize {
    parameters.bytes_per_sector * parameters.sectors_per_cluster
}

const fn fat_size(parameters: &FatVolumeParameters) -> usize {
    parameters.bytes_per_sector * parameters.sectors_per_fat
}

// FAT reads.

const fn active_fat_bytes(parameters: &FatVolumeParameters) -> &[u8] {
    let fat_size = fat_size(parameters);
    let fat_offset = fat_area_start(parameters) + (active_fat_index(parameters) * fat_size);
    unsafe { slice::from_raw_parts(parameters.volume_root.add(fat_offset), fat_size) }
}

const fn active_fat_index(parameters: &FatVolumeParameters) -> usize {
    match parameters.active_fat {
        Some(i) => i,
        None => 0,
    }
}

// Cluster reads.

const fn try_get_cluster_content(parameters: &FatVolumeParameters, index: usize) -> Option<&[u8]> {
    if index >= cluster_count(parameters) {
        None
    } else {
        let cluster_size = cluster_size(parameters);
        let cluster_offset = clustered_area_start(parameters) + (cluster_size * index);
        Some(unsafe {
            slice::from_raw_parts(parameters.volume_root.add(cluster_offset), cluster_size)
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClusterReadResult<'a> {
    OutOfBounds,
    Free,
    Reserved(&'a [u8]),
    EndOfChain(&'a [u8]),
    BadCluster(&'a [u8]),
    Link(&'a [u8], usize),
}

impl<'a> ClusterReadResult<'a> {
    fn from<TFatEntry: FatEntry>(
        fat_entry: TFatEntry,
        parameters: &'a FatVolumeParameters,
        index: usize,
    ) -> Self {
        let status = fat_entry.status();
        if status == FatEntryStatus::Free {
            return Self::Free;
        }

        let data = try_get_cluster_content(parameters, index).unwrap();
        match status {
            FatEntryStatus::Free => Self::Free,
            FatEntryStatus::Reserved => Self::Reserved(data),
            FatEntryStatus::Link => Self::Link(data, fat_entry.into()),
            FatEntryStatus::BadCluster => Self::BadCluster(data),
            FatEntryStatus::EndOfChain => Self::EndOfChain(data),
        }
    }
}

fn read_cluster<TFatEntry: FatEntry>(
    parameters: &FatVolumeParameters,
    index: usize,
) -> ClusterReadResult {
    match TFatEntry::try_read_from(active_fat_bytes(parameters), index) {
        Some(e) => ClusterReadResult::from(e, parameters, index),
        None => ClusterReadResult::OutOfBounds,
    }
}
