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

use super::ConsoleWriteable;
use crate::{console_out::ConsoleOut, constants, String16};
use macros::s16;

pub struct ConsoleUiLabel<'a> {
    label: String16<'a>,
}

impl<'a> ConsoleUiLabel<'a> {
    pub const fn from(label: String16<'a>) -> Self {
        Self { label }
    }
}

impl ConsoleWriteable for ConsoleUiLabel<'_> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console
            .line_start()
            .new_line()
            .in_colours(constants::LABEL_COLOURS, |c| {
                c.output_utf16(self.label).output_utf16_line(s16!(":"))
            });
    }
}
