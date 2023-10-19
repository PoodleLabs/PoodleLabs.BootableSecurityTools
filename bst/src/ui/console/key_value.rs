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

use macros::s16;

use super::ConsoleWriteable;
use crate::{console_out::ConsoleOut, constants, String16};

pub struct ConsoleUiKeyValue<'a> {
    key: String16<'a>,
    value: String16<'a>,
}

impl<'a> ConsoleUiKeyValue<'a> {
    pub const fn from(key: String16<'a>, value: String16<'a>) -> Self {
        Self { key, value }
    }
}

impl ConsoleWriteable for ConsoleUiKeyValue<'_> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console
            .line_start()
            .in_colours(constants::LABEL_COLOURS, |c| {
                c.output_utf16(self.key).output_utf16(s16!(": "))
            })
            .output_utf16_line(self.value);
    }
}
