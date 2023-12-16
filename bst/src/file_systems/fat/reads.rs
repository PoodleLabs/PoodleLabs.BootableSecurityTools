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
    directory_entries::{self, DirectoryEntry, ShortFileName, ShortFileNameFreeIndicator},
    fat_entries::FatEntry,
};
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FatDirectoryEntry<'a> {
    VolumeLabel(&'a ShortFileName),
}

fn next_directory_entry_in_cluster<'a>(
    directory_entries: &'a [DirectoryEntry],
    next_index: &mut usize,
    skip_hidden: bool,
) -> Option<FatDirectoryEntry<'a>> {
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
                    return Some(FatDirectoryEntry::VolumeLabel(entry.file_name()));
                }

                if attributes.is_long_file_name_entry() {
                    // Remember to check hidden flag on SFN entry.
                    todo!("LFN Directory or File")
                }

                if attributes.is_hidden() && skip_hidden {
                    // Skip hidden entries.
                    *next_index += 1;
                    continue;
                }

                if attributes.is_directory() {
                    todo!("SFN Directory")
                }

                todo!("SFN File")
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

pub trait FatDirectoryEntryIterator<'a>: Iterator<Item = FatDirectoryEntry<'a>> {
    fn reset(&mut self);
}

pub struct FatFixedSizeDirectoryEntryIterator<'a, TFatEntry: FatEntry> {
    volume_parameters: &'a FatVolumeParameters,
    phantom_data: PhantomData<TFatEntry>,
    directory_entry_count: usize,
    next_index: usize,
    skip_hidden: bool,
}

impl<'a, TFatEntry: FatEntry> Iterator for FatFixedSizeDirectoryEntryIterator<'a, TFatEntry> {
    type Item = FatDirectoryEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let directory_entries = unsafe {
            slice::from_raw_parts(
                self.volume_parameters
                    .volume_root
                    .add(clustered_area_start(self.volume_parameters))
                    as *const DirectoryEntry,
                self.directory_entry_count,
            )
        };

        // We can handle fixed sized root directories by treating them as having a single, special cluster.
        match next_directory_entry_in_cluster(
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

impl<'a, TFatEntry: FatEntry> FatDirectoryEntryIterator<'a>
    for FatFixedSizeDirectoryEntryIterator<'a, TFatEntry>
{
    fn reset(&mut self) {
        self.next_index = 0;
    }
}

pub struct FatClusterBasedDirectoryEntryIterator<'a, TFatEntry: FatEntry> {
    current_cluster_data: Option<(&'a [u8], Option<usize>)>,
    volume_parameters: &'a FatVolumeParameters,
    phantom_data: PhantomData<TFatEntry>,
    entries_per_cluster: usize,
    start_cluster: usize,
    next_index: usize,
    skip_hidden: bool,
}

impl<'a, TFatEntry: FatEntry> FatClusterBasedDirectoryEntryIterator<'a, TFatEntry> {
    fn set_current_cluster(&mut self, cluster_index: usize) {
        self.next_index = 0;
        self.current_cluster_data =
            match read_cluster::<TFatEntry>(self.volume_parameters, cluster_index) {
                ClusterReadResult::Link(d, n) => Some((d, Some(n))),
                ClusterReadResult::EndOfChain(d) => Some((d, None)),
                _ => None,
            };
    }
}

impl<'a, TFatEntry: FatEntry> Iterator for FatClusterBasedDirectoryEntryIterator<'a, TFatEntry> {
    type Item = FatDirectoryEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match loop {
            // Iterate over the clusters composing the directory.
            let (cluster, next_cluster) = match self.current_cluster_data {
                Some(d) => d,
                None => return None,
            };

            let directory_entries = unsafe {
                slice::from_raw_parts(
                    cluster.as_ptr() as *const DirectoryEntry,
                    self.entries_per_cluster,
                )
            };

            match next_directory_entry_in_cluster(
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

impl<'a, TFatEntry: FatEntry> FatDirectoryEntryIterator<'a>
    for FatClusterBasedDirectoryEntryIterator<'a, TFatEntry>
{
    fn reset(&mut self) {
        self.set_current_cluster(self.start_cluster)
    }
}

pub trait FatFileSystemReader<'a> {
    type RootDirectoryEntryIterator: FatDirectoryEntryIterator<'a>;
    type FatEntry: FatEntry;

    fn iter_root_directory_entries(&self) -> Self::RootDirectoryEntryIterator;

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
const fn fat_area_start(parameters: &FatVolumeParameters) -> usize {
    parameters.reserved_sectors * parameters.bytes_per_sector
}

const fn cluster_count(parameters: &FatVolumeParameters) -> usize {
    let clustered_sector_count = parameters.sector_count
        - parameters.reserved_sectors
        - (parameters.fat_count * parameters.sectors_per_fat);
    clustered_sector_count / parameters.sectors_per_cluster
}

const fn fat_size(parameters: &FatVolumeParameters) -> usize {
    parameters.bytes_per_sector * parameters.sectors_per_fat
}

// FAT reads.
const fn active_fat_bytes(parameters: &FatVolumeParameters) -> &[u8] {
    let fat_size = fat_size(parameters);
    let fat_offset = fat_area_start(parameters)
        + (match parameters.active_fat {
            Some(i) => i,
            None => 0,
        } * fat_size);

    unsafe { slice::from_raw_parts(parameters.volume_root.add(fat_offset), fat_size) }
}

// Cluster reads.
const fn clustered_area_start(parameters: &FatVolumeParameters) -> usize {
    fat_area_start(parameters) + (fat_size(parameters) * parameters.fat_count)
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

        let data = if index >= cluster_count(parameters) {
            return Self::OutOfBounds;
        } else {
            let cluster_size = parameters.bytes_per_sector * parameters.sectors_per_cluster;
            let cluster_offset = clustered_area_start(parameters) + (cluster_size * index);
            unsafe {
                slice::from_raw_parts(parameters.volume_root.add(cluster_offset), cluster_size)
            }
        };

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
