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

mod clustering;
mod naming;
mod objects;
mod raw_layout;
mod timekeeping;

use super::block_device::BlockDevice;

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

trait FileSystemReader<'a, TBlockDevice: BlockDevice> {
    type RootDirectoryEntryIterator: objects::directories::ChildIterator<'a>;
    type FatEntry: clustering::map::Entry;

    fn iter_root_directory_entries(&self) -> Self::RootDirectoryEntryIterator;

    fn volume_parameters(&self) -> &clustering::VolumeParameters<'a, TBlockDevice>;

    fn iter_map_linear(
        &'a self,
    ) -> clustering::map::LinearIterator<'a, TBlockDevice, Self::FatEntry> {
        self.iter_map_linear_from(0)
    }

    fn iter_map_linear_from(
        &'a self,
        start_index: usize,
    ) -> clustering::map::LinearIterator<'a, TBlockDevice, Self::FatEntry> {
        clustering::map::LinearIterator::from(self.volume_parameters(), start_index)
    }

    fn iter_map_chain(
        &'a self,
        start_index: usize,
    ) -> clustering::map::ChainIterator<'a, TBlockDevice, Self::FatEntry> {
        clustering::map::ChainIterator::from(self.volume_parameters(), start_index)
    }

    fn iter_clusters_linear(
        &'a self,
    ) -> clustering::LinearIterator<'a, TBlockDevice, Self::FatEntry> {
        self.iter_clusters_linear_from(0)
    }

    fn iter_clusters_linear_from(
        &'a self,
        start_index: usize,
    ) -> clustering::LinearIterator<'a, TBlockDevice, Self::FatEntry> {
        clustering::LinearIterator::from(self.volume_parameters(), start_index)
    }

    fn iter_cluster_chain(
        &'a self,
        start_index: usize,
    ) -> clustering::ChainIterator<'a, TBlockDevice, Self::FatEntry> {
        clustering::ChainIterator::from(self.volume_parameters(), start_index)
    }
}

macro_rules! filesystem_reader {
    ($($name:ident($map_entry_type:ident, $iterator_type:ident),)*) => {
        $(
            struct $name<'a, TBlockDevice: BlockDevice> {
                volume_parameters: clustering::VolumeParameters<'a, TBlockDevice>,
                skip_hidden: bool,
            }

            impl<'a, TBlockDevice: BlockDevice> FileSystemReader<'a, TBlockDevice> for &'a $name<'a, TBlockDevice> {
                type FatEntry = clustering::map::$map_entry_type;
                type RootDirectoryEntryIterator = objects::directories::$iterator_type<'a, TBlockDevice, Self::FatEntry>;

                fn iter_root_directory_entries(&self) -> Self::RootDirectoryEntryIterator {
                    Self::RootDirectoryEntryIterator::from(
                        &self.volume_parameters,
                        self.volume_parameters.root_directory_value(),
                        0,
                        self.skip_hidden,
                    )
                }

                fn volume_parameters(&self) -> &clustering::VolumeParameters<'a, TBlockDevice> {
                    &self.volume_parameters
                }
            }

        )*
    }
}

filesystem_reader!(
    Fat32FileSystemReader(Entry32, ClusteredDirectoryChildIterator),
    Fat16FileSystemReader(Entry16, FixedSizedDirectoryChildIterator),
    Fat12FileSystemReader(Entry12, FixedSizedDirectoryChildIterator),
);
