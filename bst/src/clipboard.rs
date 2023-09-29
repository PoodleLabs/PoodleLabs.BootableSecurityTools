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
use alloc::sync::Arc;
use core::mem;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClipboardEntry {
    Empty,
    Bytes(String16<'static>, Arc<[u8]>),
    String16(String16<'static>, Arc<[u16]>),
}

pub struct Clipboard {
    entries: [ClipboardEntry; 10],
}

impl Clipboard {
    pub const fn new() -> Self {
        Self {
            entries: [
                ClipboardEntry::Empty,
                ClipboardEntry::Empty,
                ClipboardEntry::Empty,
                ClipboardEntry::Empty,
                ClipboardEntry::Empty,
                ClipboardEntry::Empty,
                ClipboardEntry::Empty,
                ClipboardEntry::Empty,
                ClipboardEntry::Empty,
                ClipboardEntry::Empty,
            ],
        }
    }

    pub const fn get_entries(&self) -> &[ClipboardEntry] {
        &self.entries
    }

    pub fn get_entry(&self, index: usize) -> ClipboardEntry {
        self.entries[index].clone()
    }

    pub fn set_entry(&mut self, index: usize, new_value: ClipboardEntry) -> ClipboardEntry {
        mem::replace(&mut self.entries[index], new_value)
    }
}
