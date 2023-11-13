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

use crate::{ui::Point, String16};
use alloc::boxed::Box;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleModeInformation<TIdentifier: Clone> {
    identifier: TIdentifier,
    size: Point,
}

impl<TIdentifier: Clone> ConsoleModeInformation<TIdentifier> {
    pub const fn from(identifier: TIdentifier, size: Point) -> Self {
        Self { identifier, size }
    }

    pub const fn identifier(&self) -> &TIdentifier {
        &self.identifier
    }

    pub const fn size(&self) -> Point {
        self.size
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleCursorState {
    position: Point,
    visible: bool,
}

impl ConsoleCursorState {
    pub const fn from(position: Point, visible: bool) -> Self {
        Self { position, visible }
    }

    pub const fn position(&self) -> Point {
        self.position
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConsoleColour {
    Inherit,
    Black,
    Blue,
    Green,
    Cyan,
    Red,
    Magenta,
    Brown,
    LightGray,
    DarkGray,
    LightBlue,
    LightGreen,
    LightCyan,
    LightRed,
    LightMagenta,
    Yellow,
    White,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleColours {
    foreground: ConsoleColour,
    background: ConsoleColour,
}

impl ConsoleColours {
    pub const INHERIT: Self = Self::from(ConsoleColour::Inherit, ConsoleColour::Inherit);

    pub const fn from(foreground: ConsoleColour, background: ConsoleColour) -> Self {
        Self {
            foreground,
            background,
        }
    }

    pub const fn foreground_only(colour: ConsoleColour) -> Self {
        Self {
            background: ConsoleColour::Inherit,
            foreground: colour,
        }
    }

    #[allow(dead_code)]
    pub const fn background_only(colour: ConsoleColour) -> Self {
        Self {
            foreground: ConsoleColour::Inherit,
            background: colour,
        }
    }

    pub const fn foreground(&self) -> ConsoleColour {
        self.foreground
    }

    pub const fn background(&self) -> ConsoleColour {
        self.background
    }
}

pub trait ConsoleOut: Clone {
    type TModeIdentifer: Clone;

    fn in_colours<F: Fn(&Self) -> &Self>(&self, colours: ConsoleColours, closure: F) -> &Self {
        let original_colours = self.colours();
        _ = self.set_colours(colours);
        _ = closure(self).set_colours(original_colours);
        self
    }

    fn in_colours_with_context<T, F: Fn(&Self, T) -> &Self>(
        &self,
        colours: ConsoleColours,
        context: T,
        closure: F,
    ) -> &Self {
        let original_colours = self.colours();
        _ = self.set_colours(colours);
        _ = closure(self, context).set_colours(original_colours);
        self
    }

    fn output_utf16_line<'a>(&self, string: String16<'a>) -> &Self {
        self.output_utf16(string).line_start()
    }

    fn output_utf32_line(&self, string: &str) -> &Self {
        self.output_utf32(string).line_start()
    }

    fn line_start(&self) -> &Self {
        if self.cursor().position().x() == 0 {
            self
        } else {
            self.new_line()
        }
    }

    fn set_colours(&self, colours: ConsoleColours) -> Result<(), ConsoleColours>;

    fn get_modes(&self) -> Box<[ConsoleModeInformation<Self::TModeIdentifer>]>;

    fn set_mode(&mut self, mode_identifier: Self::TModeIdentifer) -> bool;

    fn blank_up_to_line_end(&self, max_within_line: usize) -> &Self;

    fn current_mode_identifier(&self) -> Self::TModeIdentifer;

    fn output_utf16<'a>(&self, string: String16<'a>) -> &Self;

    fn set_cursor_position(&self, position: Point) -> &Self;

    fn set_cursor_visibility(&self, visible: bool) -> &Self;

    fn output_utf32(&self, string: &str) -> &Self;

    fn blank_remaining_line(&self) -> &Self;

    fn cursor(&self) -> ConsoleCursorState;

    fn colours(&self) -> ConsoleColours;

    fn reset(&mut self) -> &mut Self;

    fn new_line(&self) -> &Self;

    fn clear(&self) -> &Self;

    fn size(&self) -> Point;
}
