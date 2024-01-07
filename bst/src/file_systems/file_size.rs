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

use crate::String16;
use macros::s16;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileSizeUnit {
    Bytes,
    Kilobytes,
    Megabytes,
    Gigabytes,
    Terabytes,
    Petabytes,
    Exabytes,
}

impl FileSizeUnit {
    pub const fn suffix(&self) -> String16<'static> {
        match self {
            FileSizeUnit::Bytes => s16!("B"),
            FileSizeUnit::Kilobytes => s16!("KB"),
            FileSizeUnit::Megabytes => s16!("MB"),
            FileSizeUnit::Gigabytes => s16!("GB"),
            FileSizeUnit::Terabytes => s16!("TB"),
            FileSizeUnit::Petabytes => s16!("PB"),
            FileSizeUnit::Exabytes => s16!("EB"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileSize(u64);

impl FileSize {
    pub const fn from(value: u64, unit: FileSizeUnit) -> Self {
        match unit {
            FileSizeUnit::Bytes => Self(value),
            FileSizeUnit::Kilobytes => Self(value * 1000),
            FileSizeUnit::Megabytes => Self(value * 1000000),
            FileSizeUnit::Gigabytes => Self(value * 1000000000),
            FileSizeUnit::Terabytes => Self(value * 1000000000000),
            FileSizeUnit::Petabytes => Self(value * 1000000000000000),
            FileSizeUnit::Exabytes => Self(value * 1000000000000000000),
        }
    }

    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    pub const fn preferred_unit(&self) -> FileSizeUnit {
        if self.0 < 1000 {
            FileSizeUnit::Bytes
        } else if self.0 < 1000000 {
            FileSizeUnit::Kilobytes
        } else if self.0 < 1000000000 {
            FileSizeUnit::Megabytes
        } else if self.0 < 1000000000000 {
            FileSizeUnit::Gigabytes
        } else if self.0 < 1000000000000000 {
            FileSizeUnit::Terabytes
        } else if self.0 < 1000000000000000000 {
            FileSizeUnit::Petabytes
        } else {
            FileSizeUnit::Exabytes
        }
    }

    pub fn in_units(&self, unit: FileSizeUnit) -> f64 {
        self.0 as f64
            / (match unit {
                FileSizeUnit::Bytes => 1f64,
                FileSizeUnit::Kilobytes => 1000f64,
                FileSizeUnit::Megabytes => 1000000f64,
                FileSizeUnit::Gigabytes => 1000000000f64,
                FileSizeUnit::Terabytes => 1000000000000f64,
                FileSizeUnit::Petabytes => 1000000000000000f64,
                FileSizeUnit::Exabytes => 1000000000000000000f64,
            })
    }

    pub const fn bytes(&self) -> u64 {
        self.0
    }
}
