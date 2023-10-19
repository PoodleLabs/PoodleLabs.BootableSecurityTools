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

#[cfg(test)]
use alloc::string::String;
use alloc::{boxed::Box, vec::Vec};
#[cfg(test)]
use core::fmt::{self, Debug, Formatter};
use core::{char::decode_utf16, cmp::Ordering, slice::Iter};

#[derive(Clone, Copy)]
pub struct String16<'a>(&'a [u16]);

#[cfg(test)]
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

    pub fn write_content_to_utf16_vec(&self, vec: &mut Vec<u16>) {
        vec.extend_from_slice(self.content_slice())
    }

    pub fn write_content_to_utf8_vec(&self, vec: &mut Vec<u8>) {
        let mut char_buffer = [0u8; 2];
        for char in decode_utf16(self.content_slice().iter().cloned())
            .filter(|c| c.is_ok())
            .map(|c| c.unwrap())
        {
            vec.extend(char.encode_utf8(&mut char_buffer).as_bytes());
        }
    }

    pub fn copy_content_to(&self, buffer: &mut [u16]) {
        buffer.copy_from_slice(&self.0[..self.content_length()])
    }

    pub fn content_iterator(&self) -> Iter<u16> {
        self.content_slice().into_iter()
    }

    pub fn utf8_content_length(&self) -> usize {
        decode_utf16(self.content_slice().iter().cloned())
            .filter(|c| c.is_ok())
            .map(|c| c.unwrap().len_utf8())
            .sum()
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

    pub fn to_program_error(&self) -> Box<[u16]> {
        self.0.into()
    }
}
