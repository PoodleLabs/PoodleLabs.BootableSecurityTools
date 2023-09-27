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
use crate::{
    console_out::{ConsoleColours, ConsoleOut},
    constants,
    ui::{
        scroll_text::{UiScrollText, UiScrollTextChunkType, UiScrollTextLineStartType},
        Point,
    },
    String16,
};
use alloc::{vec, vec::Vec};
use macros::{c16, s16};

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleUiScrollTextStyles {
    scroll_indicator_colours: ConsoleColours,
    wrap_indicator_colours: ConsoleColours,
    wrap_indicator: String16<'static>,
    content_colours: ConsoleColours,
    height: usize,
}

#[allow(dead_code)]
impl ConsoleUiScrollTextStyles {
    pub const fn from(
        scroll_indicator_colours: ConsoleColours,
        wrap_indicator_colours: ConsoleColours,
        wrap_indicator: String16<'static>,
        content_colours: ConsoleColours,
        height: usize,
    ) -> Self {
        Self {
            scroll_indicator_colours,
            wrap_indicator_colours,
            wrap_indicator,
            content_colours,
            height,
        }
    }

    pub const fn with_scroll_indicator(self, colours: ConsoleColours) -> Self {
        Self {
            wrap_indicator_colours: self.wrap_indicator_colours,
            content_colours: self.content_colours,
            wrap_indicator: self.wrap_indicator,
            scroll_indicator_colours: colours,
            height: self.height,
        }
    }

    pub const fn with_wrap_indicator(
        self,
        colour: ConsoleColours,
        character: String16<'static>,
    ) -> Self {
        Self {
            scroll_indicator_colours: self.scroll_indicator_colours,
            content_colours: self.content_colours,
            wrap_indicator_colours: colour,
            wrap_indicator: character,
            height: self.height,
        }
    }

    pub const fn with_content(self, colour: ConsoleColours) -> Self {
        Self {
            scroll_indicator_colours: self.scroll_indicator_colours,
            wrap_indicator_colours: self.wrap_indicator_colours,
            wrap_indicator: self.wrap_indicator,
            content_colours: colour,
            height: self.height,
        }
    }

    pub const fn with_height(self, height: usize) -> Self {
        Self {
            scroll_indicator_colours: self.scroll_indicator_colours,
            wrap_indicator_colours: self.wrap_indicator_colours,
            content_colours: self.content_colours,
            wrap_indicator: self.wrap_indicator,
            height: height,
        }
    }

    pub const fn height(&self) -> usize {
        self.height
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleUiScrollText {
    character_predicate: Option<fn(character: u16) -> bool>,
    styles: ConsoleUiScrollTextStyles,
    scroll_text: UiScrollText,
    position: Point,
}

impl ConsoleUiScrollText {
    pub fn from(
        character_predicate: Option<fn(character: u16) -> bool>,
        styles: ConsoleUiScrollTextStyles,
        characters: &[u16],
        position: Point,
        width: usize,
    ) -> Self {
        if width < 4 {
            panic!("Scroll text cannot have a width less than 4.");
        }

        let scroll_bounds = Point::from(width - 3, styles.height);
        Self {
            scroll_text: UiScrollText::with_bounds(scroll_bounds, characters),
            character_predicate,
            position,
            styles,
        }
    }

    pub fn take_ownership_of_content(self) -> Vec<u16> {
        self.scroll_text.take_ownership_of_content()
    }

    pub fn change_position(&mut self, position: Point) -> &mut Self {
        self.position = position;
        self
    }

    pub fn move_cursor_right(&mut self) -> &mut Self {
        self.scroll_text.move_cursor_right();
        self
    }

    pub fn move_cursor_left(&mut self) -> &mut Self {
        self.scroll_text.move_cursor_left();
        self
    }

    pub fn move_cursor_down(&mut self) -> &mut Self {
        self.scroll_text.move_cursor_down();
        self
    }

    pub fn move_cursor_up(&mut self) -> &mut Self {
        self.scroll_text.move_cursor_up();
        self
    }

    pub fn move_cursor_to_start_of_line(&mut self) -> &mut Self {
        self.scroll_text.move_cursor_to_start_of_line();
        self
    }

    pub fn move_cursor_to_end_of_line(&mut self) -> &mut Self {
        self.scroll_text.move_cursor_to_end_of_line();
        self
    }

    pub fn go_to_start(&mut self) -> &mut Self {
        self.scroll_text.go_to_start();
        self
    }

    pub fn go_to_end(&mut self) -> &mut Self {
        self.scroll_text.go_to_end();
        self
    }

    pub fn viewport_up(&mut self) -> &mut Self {
        self.scroll_text.viewport_up();
        self
    }

    pub fn viewport_down(&mut self) -> &mut Self {
        self.scroll_text.viewport_down();
        self
    }

    pub fn page_up(&mut self, cursor_agnostic: bool) -> &mut Self {
        self.scroll_text.page_up(cursor_agnostic);
        self
    }

    pub fn page_down(&mut self, cursor_agnostic: bool) -> &mut Self {
        self.scroll_text.page_down(cursor_agnostic);
        self
    }

    // Character Mutation
    pub fn insert_character(&mut self, character: u16) -> &mut Self {
        match self.character_predicate {
            Some(p) => {
                // There's a character predicate; check the character passes before inserting.
                if (p)(character) {
                    self.scroll_text.insert_character(character);
                }
            }
            None => {
                // There's no character predicate; just insert the character.
                self.scroll_text.insert_character(character);
            }
        }
        self
    }

    pub fn insert_characters<TIterator: Iterator<Item = u16>>(
        &mut self,
        characters: TIterator,
    ) -> &mut Self {
        match self.character_predicate {
            Some(p) => {
                // There's a character predicate; check the characters pass before inserting.
                self.scroll_text
                    .insert_characters(characters.filter(|c| p(*c)));
            }
            None => {
                // There's no character predicate; just insert the characters.
                self.scroll_text.insert_characters(characters);
            }
        }
        self
    }

    pub fn backspace(&mut self) -> &mut Self {
        self.scroll_text.backspace();
        self
    }

    pub fn delete(&mut self) -> &mut Self {
        self.scroll_text.delete();
        self
    }

    pub fn set_input_cursor_position<TConsoleOut: ConsoleOut>(
        &mut self,
        console_out: &TConsoleOut,
    ) -> &mut Self {
        // Offset the internal cursor position by the position of this scroll text and the scroll indicator character & space columns.
        console_out.set_cursor_position(
            Point::from(self.position.x() + 2, self.position.y()) + self.scroll_text.cursor(),
        );

        self
    }
}

impl ConsoleWriteable for ConsoleUiScrollText {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        // Prepare a line buffer for the viewport.
        let viewport_bounds = self.scroll_text.viewport_bounds();
        let mut line_buffer = vec![0u16; viewport_bounds.width() + 1];
        let viewport_end = self.position.x() + 3 + viewport_bounds.width();

        console.in_colours_with_context(
            self.styles.content_colours,
            &mut line_buffer,
            |c, line_buffer| {
                // Write the scroll indicator and its spacing column.
                c.set_cursor_position(self.position).in_colours(
                    self.styles.scroll_indicator_colours,
                    |c| {
                        // Write the scroll indicator character and the space beside it.
                        c.output_utf16(if self.scroll_text.has_hidden_leading_content() {
                            if self.scroll_text.has_hidden_trailing_content() {
                                constants::SCROLL_TEXT_SCROLL_INDICATOR_CHARACTER_SCROLL_UP_OR_DOWN
                            } else {
                                constants::SCROLL_TEXT_SCROLL_INDICATOR_CHARACTER_SCROLL_UP
                            }
                        } else if self.scroll_text.has_hidden_trailing_content() {
                            constants::SCROLL_TEXT_SCROLL_INDICATOR_CHARACTER_SCROLL_DOWN
                        } else {
                            constants::SCROLL_TEXT_SCROLL_INDICATOR_CHARACTER_NO_SCROLL
                        });

                        // Fill the empty space below it.
                        for _ in 0..self.scroll_text.viewport_bounds().height() - 1 {
                            c.output_utf16(s16!("\r\n  "));
                        }

                        c
                    },
                );

                // Iterate over the lines in the viewport.
                let viewport_start = self.scroll_text.viewport_start_line_index();
                for i in viewport_start..viewport_start + viewport_bounds.height() {
                    // Get the content for the lines.
                    let (content, next_line_start_type) = self
                        .scroll_text
                        .line_characters(i, UiScrollTextChunkType::TrimmedContent);

                    // Get a slice for the line buffer to write to.
                    let buffer = &mut line_buffer
                        [viewport_bounds.width() - content.len()..viewport_bounds.width()];

                    // Copy the content of the line to the line buffer.
                    buffer.copy_from_slice(content);
                    for i in 0..buffer.len() {
                        // Replace any tabs in the line buffer with spaces; tabs are not printed in the UEFI console out.
                        // They instead shift the cursor in a confusing way. We just want to render them as spaces.
                        if buffer[i] == c16!("\t") {
                            buffer[i] = c16!(" ");
                        }
                    }

                    // Move the cursor to the start of the line inside the viewport.
                    c.set_cursor_position(Point::from(
                        self.position.x() + 2,
                        self.position.y() + i - viewport_start,
                    )) // Write the buffer.
                    .output_utf16(String16::from(buffer));
                    match next_line_start_type {
                        Some(t) => match t {
                            // If the line ends because it wrapped, write a wrap indicator.
                            UiScrollTextLineStartType::Wrap => {
                                c.in_colours(self.styles.wrap_indicator_colours, |c| {
                                    c.output_utf16(self.styles.wrap_indicator)
                                });
                            }
                            _ => {}
                        },
                        None => {}
                    }

                    // Write spaces for the remaining viewport width.
                    let cursor_x = c.cursor().position().x();
                    if cursor_x < viewport_end && cursor_x != 0 {
                        c.blank_up_to_line_end(viewport_end - cursor_x);
                    }
                }

                c
            },
        );
    }
}
