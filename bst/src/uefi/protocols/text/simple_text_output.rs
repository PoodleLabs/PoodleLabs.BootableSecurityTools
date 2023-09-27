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

use crate::{
    console_out::{ConsoleColour, ConsoleColours, ConsoleCursorState, ConsoleModeInformation},
    uefi::{
        core_types::{UefiGuid, UefiStatusCode, UefiString},
        protocols::UefiProtocol,
    },
    ui::Point,
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::ffi::c_void;
use macros::c16;

const FOREGROUND_BLACK: u8 = 0x00;
const FOREGROUND_BLUE: u8 = 0x01;
const FOREGROUND_GREEN: u8 = 0x02;
const FOREGROUND_CYAN: u8 = 0x03;
const FOREGROUND_RED: u8 = 0x04;
const FOREGROUND_MAGENTA: u8 = 0x05;
const FOREGROUND_BROWN: u8 = 0x06;
const FOREGROUND_LIGHTGRAY: u8 = 0x07;
const FOREGROUND_DARKGRAY: u8 = 0x08;
const FOREGROUND_LIGHTBLUE: u8 = 0x09;
const FOREGROUND_LIGHTGREEN: u8 = 0x0A;
const FOREGROUND_LIGHTCYAN: u8 = 0x0B;
const FOREGROUND_LIGHTRED: u8 = 0x0C;
const FOREGROUND_LIGHTMAGENTA: u8 = 0x0D;
const FOREGROUND_YELLOW: u8 = 0x0E;
const FOREGROUND_WHITE: u8 = 0x0F;

const BACKGROUND_BLACK: u8 = 0x00;
const BACKGROUND_BLUE: u8 = 0x10;
const BACKGROUND_GREEN: u8 = 0x20;
const BACKGROUND_CYAN: u8 = 0x30;
const BACKGROUND_RED: u8 = 0x40;
const BACKGROUND_MAGENTA: u8 = 0x50;
const BACKGROUND_LIGHTGRAY: u8 = 0x70;
const BACKGROUND_BROWN: u8 = 0x60;

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct UefiSimpleTextOutputDetails {
    max_mode: i32,
    current_mode: i32,
    colours: i32,
    cursor_x: i32,
    cursor_y: i32,
    cursor_visible: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::uefi) struct UefiSimpleTextOutput {
    reset: extern "efiapi" fn(this: &Self, extended_verification: bool) -> UefiStatusCode,
    output_string: extern "efiapi" fn(
        this: &Self,
        content: UefiString, /* Null Terminated String */
    ) -> UefiStatusCode,
    test_string: *const c_void,
    query_mode: extern "efiapi" fn(
        this: &Self,
        mode: usize,
        columns: &mut usize, /* OUT */
        rows: &mut usize,    /* OUT */
    ) -> UefiStatusCode,
    set_mode: extern "efiapi" fn(this: &Self, mode: usize) -> UefiStatusCode,
    set_colours: extern "efiapi" fn(this: &Self, colours: usize) -> UefiStatusCode,
    clear: extern "efiapi" fn(this: &Self) -> UefiStatusCode,
    set_cursor_position:
        extern "efiapi" fn(this: &Self, column: usize, row: usize) -> UefiStatusCode,
    set_cursor_visibility: extern "efiapi" fn(this: &Self, visible: bool) -> UefiStatusCode,
    details: &'static UefiSimpleTextOutputDetails,
}

impl UefiSimpleTextOutput {
    pub const GUID: UefiGuid = UefiGuid::from(
        0x387477c2,
        0x69c7,
        0x11d2,
        0x8e,
        0x39,
        [0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );

    pub fn set_colours(&self, colours: ConsoleColours) -> Result<(), ConsoleColours> {
        let current = self.colours();
        let foreground = if colours.foreground() == ConsoleColour::Inherit {
            current.foreground()
        } else {
            colours.foreground()
        };

        let foreground = match foreground {
            ConsoleColour::Black => FOREGROUND_BLACK,
            ConsoleColour::Blue => FOREGROUND_BLUE,
            ConsoleColour::Green => FOREGROUND_GREEN,
            ConsoleColour::Cyan => FOREGROUND_CYAN,
            ConsoleColour::Red => FOREGROUND_RED,
            ConsoleColour::Magenta => FOREGROUND_MAGENTA,
            ConsoleColour::Brown => FOREGROUND_BROWN,
            ConsoleColour::LightGray => FOREGROUND_LIGHTGRAY,
            ConsoleColour::DarkGray => FOREGROUND_DARKGRAY,
            ConsoleColour::LightBlue => FOREGROUND_LIGHTBLUE,
            ConsoleColour::LightGreen => FOREGROUND_LIGHTGREEN,
            ConsoleColour::LightCyan => FOREGROUND_LIGHTCYAN,
            ConsoleColour::LightRed => FOREGROUND_LIGHTRED,
            ConsoleColour::LightMagenta => FOREGROUND_LIGHTMAGENTA,
            ConsoleColour::Yellow => FOREGROUND_YELLOW,
            _ => FOREGROUND_WHITE,
        };

        let background = if colours.background() == ConsoleColour::Inherit {
            current.background()
        } else {
            colours.background()
        };

        let (background, background_replaced_with) = match background {
            ConsoleColour::Black => (BACKGROUND_BLACK, None),
            ConsoleColour::Blue => (BACKGROUND_BLUE, None),
            ConsoleColour::Green => (BACKGROUND_GREEN, None),
            ConsoleColour::Cyan => (BACKGROUND_CYAN, None),
            ConsoleColour::Red => (BACKGROUND_RED, None),
            ConsoleColour::Magenta => (BACKGROUND_MAGENTA, None),
            ConsoleColour::Brown => (BACKGROUND_BROWN, None),
            ConsoleColour::LightGray => (BACKGROUND_LIGHTGRAY, None),
            ConsoleColour::DarkGray => (BACKGROUND_BLACK, Some(ConsoleColour::Black)),
            ConsoleColour::LightBlue => (BACKGROUND_BLUE, Some(ConsoleColour::Blue)),
            ConsoleColour::LightGreen => (BACKGROUND_GREEN, Some(ConsoleColour::Green)),
            ConsoleColour::LightCyan => (BACKGROUND_CYAN, Some(ConsoleColour::Cyan)),
            ConsoleColour::LightRed => (BACKGROUND_RED, Some(ConsoleColour::Red)),
            ConsoleColour::LightMagenta => (BACKGROUND_MAGENTA, Some(ConsoleColour::Magenta)),
            ConsoleColour::Yellow => (BACKGROUND_BROWN, Some(ConsoleColour::Brown)),
            _ => (BACKGROUND_LIGHTGRAY, Some(ConsoleColour::LightGray)),
        };

        if (self.set_colours)(self, (foreground | background) as usize).is_success() {
            match background_replaced_with {
                Some(c) => Err(ConsoleColours::from(colours.foreground(), c)),
                None => Ok(()),
            }
        } else {
            Err(self.colours())
        }
    }

    pub fn reset(&self, allow_extended_verification: bool) -> UefiStatusCode {
        (self.reset)(self, allow_extended_verification)
    }

    pub fn set_cursor_visibility(&self, visible: bool) -> UefiStatusCode {
        (self.set_cursor_visibility)(self, visible)
    }

    pub fn set_cursor_position(&self, position: Point) -> UefiStatusCode {
        (self.set_cursor_position)(self, position.x(), position.y())
    }

    pub fn output_string(&self, string: &[u16]) -> UefiStatusCode {
        if string.len() == 0 {
            UefiStatusCode::SUCCESS
        } else if string[string.len() - 1] == c16!("\0") {
            (self.output_string)(self, string.as_ptr().into())
        } else {
            let mut nt_string = vec![0u16; string.len() + 1];
            nt_string[..string.len()].copy_from_slice(string);
            nt_string[string.len()] = c16!("\0");

            (self.output_string)(self, nt_string.as_ptr().into())
        }
    }

    pub fn query_mode(&self, mode_id: usize) -> Option<Point> {
        let mut cols = 0usize;
        let mut rows = 0usize;
        match (self.query_mode)(self, mode_id, &mut cols, &mut rows).into() {
            Ok(_) => Some(Point::from(cols, rows)),
            Err(_) => None,
        }
    }

    pub fn cursor_state(&self) -> ConsoleCursorState {
        ConsoleCursorState::from(
            Point::from(
                self.details.cursor_x as usize,
                self.details.cursor_y as usize,
            ),
            self.details.cursor_visible,
        )
    }

    pub fn colours(&self) -> ConsoleColours {
        ConsoleColours::from(
            match (self.details.colours & 0x0F) as u8 {
                FOREGROUND_BLACK => ConsoleColour::Black,
                FOREGROUND_BLUE => ConsoleColour::Blue,
                FOREGROUND_GREEN => ConsoleColour::Green,
                FOREGROUND_CYAN => ConsoleColour::Cyan,
                FOREGROUND_RED => ConsoleColour::Red,
                FOREGROUND_MAGENTA => ConsoleColour::Magenta,
                FOREGROUND_BROWN => ConsoleColour::Brown,
                FOREGROUND_LIGHTGRAY => ConsoleColour::LightGray,
                FOREGROUND_DARKGRAY => ConsoleColour::DarkGray,
                FOREGROUND_LIGHTBLUE => ConsoleColour::LightBlue,
                FOREGROUND_LIGHTGREEN => ConsoleColour::LightGreen,
                FOREGROUND_LIGHTCYAN => ConsoleColour::LightCyan,
                FOREGROUND_LIGHTRED => ConsoleColour::LightRed,
                FOREGROUND_LIGHTMAGENTA => ConsoleColour::LightMagenta,
                FOREGROUND_YELLOW => ConsoleColour::Yellow,
                FOREGROUND_WHITE => ConsoleColour::White,
                _ => ConsoleColour::White,
            },
            match (self.details.colours & 0xF0) as u8 {
                BACKGROUND_BLACK => ConsoleColour::Black,
                BACKGROUND_BLUE => ConsoleColour::Blue,
                BACKGROUND_GREEN => ConsoleColour::Green,
                BACKGROUND_CYAN => ConsoleColour::Cyan,
                BACKGROUND_RED => ConsoleColour::Red,
                BACKGROUND_MAGENTA => ConsoleColour::Magenta,
                BACKGROUND_LIGHTGRAY => ConsoleColour::LightGray,
                BACKGROUND_BROWN => ConsoleColour::Brown,
                _ => ConsoleColour::Black,
            },
        )
    }

    pub fn set_mode(&self, mode: usize) -> UefiStatusCode {
        (self.set_mode)(&self, mode)
    }

    pub fn get_modes(&self) -> Box<[ConsoleModeInformation<usize>]> {
        let mut vec = Vec::with_capacity(self.details.max_mode as usize);
        for i in 0..self.details.max_mode as usize {
            match self.query_mode(i) {
                Some(p) => {
                    if p.area() > 0 {
                        vec.push(ConsoleModeInformation::from(i, p))
                    }
                }
                None => {}
            }
        }

        vec.into()
    }

    pub fn clear(&self) -> UefiStatusCode {
        (self.clear)(self)
    }

    pub fn size(&self) -> Point {
        self.query_mode(self.details.current_mode as usize).unwrap()
    }

    pub fn mode(&self) -> usize {
        self.details.current_mode as usize
    }
}

impl UefiProtocol for UefiSimpleTextOutput {
    fn guid() -> &'static UefiGuid {
        &Self::GUID
    }
}
