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

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Date([u8; 2]);

impl Date {
    pub const fn year(&self) -> u16 {
        (((self.0[0] & 0b11111110) >> 1) as u16) + 1980
    }

    pub const fn month(&self) -> u8 {
        ((self.0[0] & 0b00000001) << 3) | ((self.0[1] & 0b11100000) >> 5)
    }

    pub const fn day(&self) -> u8 {
        self.0[1] & 0b00011111
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Time2sResolution([u8; 2]);

impl Time2sResolution {
    pub const fn hour(&self) -> u8 {
        (self.0[0] & 0b11111000) >> 3
    }

    pub const fn minute(&self) -> u8 {
        ((self.0[0] & 0b00000111) << 3) | ((self.0[1] & 0b11100000) >> 5)
    }

    pub const fn second(&self) -> u8 {
        (self.0[1] & 0b00011111) * 2
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Time {
    sub_2s: u8, // Resolution of 10 milliseconds, 0-199 where 0 = 0, and 199 = 1.99s.
    main: Time2sResolution,
}

impl Time {
    pub const fn hour(&self) -> u8 {
        self.main.hour()
    }

    pub const fn minute(&self) -> u8 {
        self.main.minute()
    }

    pub const fn second(&self) -> u8 {
        self.main.second() + (self.sub_2s / 100)
    }

    pub const fn millisecond(&self) -> u16 {
        (self.sub_2s as u16 % 100) * 10
    }
}
