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

use alloc::string::String;
use core::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
    slice::Iter,
};

#[derive(Clone, Copy)]
pub struct String16<'a>(&'a [u16]);

impl Debug for String16<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("String16")
            .field(&String::from_utf16(&self.content_slice()))
            .finish()
    }
}

impl PartialEq for String16<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.content_slice().eq(other.content_slice())
    }
}

impl Eq for String16<'_> {}

impl PartialOrd for String16<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.content_slice().partial_cmp(other.content_slice())
    }
}

impl Ord for String16<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.content_slice().cmp(other.content_slice())
    }
}

impl String16<'static> {
    pub const fn from_static(slice: &'static [u16]) -> Self {
        Self(slice)
    }
}

impl<'a> String16<'a> {
    pub const fn from(slice: &'a [u16]) -> Self {
        Self(slice)
    }

    pub unsafe fn get_underlying_slice(&self) -> &[u16] {
        self.0
    }

    pub fn copy_content_to(&self, buffer: &mut [u16]) {
        buffer.copy_from_slice(&self.0[..self.content_length()])
    }

    pub fn content_iterator(&self) -> Iter<u16> {
        self.content_slice().into_iter()
    }

    pub fn content_slice(&self) -> &[u16] {
        &self.0[..self.content_length()]
    }

    pub fn content_length(&self) -> usize {
        if self.is_null_terminated() {
            self.0.len() - 1
        } else {
            self.0.len()
        }
    }

    pub fn is_null_terminated(&self) -> bool {
        self.0.len() > 0 && self.0[self.0.len() - 1] == 0
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0 || self.0[0] == 0
    }
}
