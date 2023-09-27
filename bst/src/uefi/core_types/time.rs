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
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::uefi) struct UefiTime {
    year: u16,  /* 1900 - 9999 */
    month: u8,  /* 1 - 12 */
    day: u8,    /* 1 - 31 */
    hour: u8,   /* 0 - 23 */
    minute: u8, /* 0 - 59 */
    second: u8, /* 0 - 59 */
    pad_1: u8,
    nanosecond: u32, /* 0 - 999,999,999 */
    time_zone: i16,  /* -1440 - 1440 */
    daylight: u8,
    pad_2: u8,
}

impl UefiTime {
    const UNSPECIFIED_TIME_ZONE: i16 = 2047;
    const ADJUST_DAYLIGHT_FLAG: u8 = 0x01;
    const IN_DAYLIGHT_FLAG: u8 = 0x02;

    pub const fn timezone_utc_offset_minutes(self) -> Option<i16> {
        if self.time_zone == Self::UNSPECIFIED_TIME_ZONE {
            None
        } else {
            Some(self.time_zone)
        }
    }

    pub const fn tracks_dst(self) -> bool {
        (self.daylight & Self::ADJUST_DAYLIGHT_FLAG) != 0
    }

    pub const fn is_dst(self) -> bool {
        (self.daylight & Self::IN_DAYLIGHT_FLAG) != 0
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiTimeCapabilities {
    resolution: u32,    /* Ticks Per Second */
    accuracy: u32, /* Error rate of 1E-6 parts per million (50 parts per million = 50,000,000) */
    sets_to_zero: bool, /* Whether time set operations sets times beyond the resolution to 0 */
}
