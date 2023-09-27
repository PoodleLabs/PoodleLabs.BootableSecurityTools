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

use super::protocols::{text::UefiSimpleTextOutput, UefiProtocolHandle};
use crate::{
    console_out::{ConsoleColours, ConsoleCursorState, ConsoleModeInformation, ConsoleOut},
    ui::Point,
    String16,
};
use alloc::{boxed::Box, vec, vec::Vec};
use macros::{c16, s16};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(in crate::uefi) struct UefiConsoleOut {
    protocol_handle: UefiProtocolHandle<&'static UefiSimpleTextOutput>,
    empty_line_buffer: Vec<u16>,
}

impl UefiConsoleOut {
    pub fn from(protocol_handle: UefiProtocolHandle<&'static UefiSimpleTextOutput>) -> Self {
        let len = protocol_handle.protocol().size().width() + 1;
        let mut vec = vec![c16!(" "); len];
        vec[len - 1] = 0;
        Self {
            empty_line_buffer: vec,
            protocol_handle,
        }
    }

    fn update_line_buffer(&mut self) -> &mut Self {
        let width = self.protocol_handle.protocol().size().width();
        let empty_line_buffer_length = self.empty_line_buffer.len();
        if empty_line_buffer_length < width + 1 {
            self.empty_line_buffer.reserve(width + 1);
            self.empty_line_buffer[empty_line_buffer_length - 1] = c16!(" ");
            for _ in 0..width - empty_line_buffer_length {
                self.empty_line_buffer.push(c16!(" "));
            }

            self.empty_line_buffer.push(0);
        } else {
            self.empty_line_buffer.truncate(width + 1);
            self.empty_line_buffer[width] = 0;
        }

        self
    }
}

const NEW_LINE: String16<'static> = s16!("\r\n");

impl ConsoleOut for UefiConsoleOut {
    type TModeIdentifer = usize;

    fn set_colours(&self, colours: ConsoleColours) -> Result<(), ConsoleColours> {
        if self.colours() == colours {
            return Ok(());
        }

        self.protocol_handle.protocol().set_colours(colours)
    }

    fn get_modes(&self) -> Box<[ConsoleModeInformation<Self::TModeIdentifer>]> {
        self.protocol_handle.protocol().get_modes()
    }

    fn set_mode(&mut self, mode_identifier: Self::TModeIdentifer) -> bool {
        let result = self
            .protocol_handle
            .protocol()
            .set_mode(mode_identifier)
            .is_success();
        self.update_line_buffer();
        result
    }

    fn blank_up_to_line_end(&self, max_within_line: usize) -> &Self {
        let width = self.size().width();
        let max_within_line = if max_within_line > width {
            width
        } else {
            max_within_line
        };

        self.output_utf16(String16::from(
            &self.empty_line_buffer[self.cursor().position().x().max(width - max_within_line)..],
        ))
    }

    fn current_mode_identifier(&self) -> Self::TModeIdentifer {
        self.protocol_handle.protocol().mode()
    }

    fn output_utf16<'a>(&self, string: String16<'a>) -> &Self {
        if string.is_empty() {
            return self;
        }

        assert!(self
            .protocol_handle
            .protocol()
            .output_string(unsafe { string.get_underlying_slice() })
            .is_warning_or_success());
        self
    }

    fn set_cursor_position(&self, position: Point) -> &Self {
        if self.cursor().position() == position {
            return self;
        }

        assert!(self
            .protocol_handle
            .protocol()
            .set_cursor_position(position.clamp_exclusive(self.size()))
            .is_warning_or_success());
        self
    }

    fn set_cursor_visibility(&self, visible: bool) -> &Self {
        _ = self // Don't assert here; QEMU always incorrectly returns UNSUPPORTED for false.
            .protocol_handle
            .protocol()
            .set_cursor_visibility(visible);

        self
    }

    fn output_utf32(&self, string: &str) -> &Self {
        if string.len() == 0 {
            return self;
        }

        assert!(self
            .protocol_handle
            .protocol()
            .output_string(&string.encode_utf16().collect::<Box<[u16]>>())
            .is_warning_or_success());
        self
    }

    fn blank_remaining_line(&self) -> &Self {
        self.output_utf16(String16::from(
            &self.empty_line_buffer[self.cursor().position().x()..],
        ))
    }

    fn cursor(&self) -> ConsoleCursorState {
        self.protocol_handle.protocol().cursor_state()
    }

    fn colours(&self) -> ConsoleColours {
        self.protocol_handle.protocol().colours()
    }

    fn new_line(&self) -> &Self {
        self.output_utf16(NEW_LINE)
    }

    fn reset(&mut self) -> &mut Self {
        assert!(self
            .protocol_handle
            .protocol()
            .reset(true)
            .is_warning_or_success());
        self.update_line_buffer()
    }

    fn clear(&self) -> &Self {
        assert!(self
            .protocol_handle
            .protocol()
            .clear()
            .is_warning_or_success());
        self
    }

    fn size(&self) -> Point {
        self.protocol_handle.protocol().size()
    }
}
