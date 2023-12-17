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

mod bios_parameters_blocks;
mod boot_sectors;
mod clustering;
mod file_system_info;
mod naming;
mod objects;
mod timekeeping;

// This FAT implementation was written based on the FatFs documentation,
// which can be found at: http://elm-chan.org/fsw/ff/00index_e.html.

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Variant {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Errors {
    None,
    VolumeDirty,
    HardError,
    InvalidErrorFatEntry,
    InvalidMediaFatEntry,
    Unreadable,
}

pub trait FileSystemReader<'a> {
    type RootDirectoryEntryIterator: objects::directories::ChildIterator<'a>;
    type FatEntry: clustering::map::Entry;

    fn iter_root_directory_entries(&self) -> Self::RootDirectoryEntryIterator;

    fn volume_parameters(&self) -> &clustering::VolumeParameters;

    fn iter_map_linear(&self) -> clustering::map::LinearIterator<'_, Self::FatEntry> {
        self.iter_map_linear_from(0)
    }

    fn iter_map_linear_from(
        &self,
        start_index: usize,
    ) -> clustering::map::LinearIterator<'_, Self::FatEntry> {
        clustering::map::LinearIterator::from(self.volume_parameters(), start_index)
    }

    fn iter_map_chain(
        &self,
        start_index: usize,
    ) -> clustering::map::ChainIterator<'_, Self::FatEntry> {
        clustering::map::ChainIterator::from(self.volume_parameters(), start_index)
    }

    fn iter_clusters_linear(&self) -> clustering::LinearIterator<'_, Self::FatEntry> {
        self.iter_clusters_linear_from(0)
    }

    fn iter_clusters_linear_from(
        &self,
        start_index: usize,
    ) -> clustering::LinearIterator<'_, Self::FatEntry> {
        clustering::LinearIterator::from(self.volume_parameters(), start_index)
    }

    fn iter_cluster_chain(
        &self,
        start_index: usize,
    ) -> clustering::ChainIterator<'_, Self::FatEntry> {
        clustering::ChainIterator::from(self.volume_parameters(), start_index)
    }
}
