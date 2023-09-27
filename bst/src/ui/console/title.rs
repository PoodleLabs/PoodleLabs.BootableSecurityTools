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
    ui::UiElementAlignment,
    String16,
};
use alloc::vec;
use macros::c16;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleUiTitleStyles {
    content_colours: ConsoleColours,
    padding_colours: ConsoleColours,
    border_colours: ConsoleColours,
    alignment: UiElementAlignment,
    border_character: u16,
    padding_character: u16,
    border_thickness: u8,
}

#[allow(dead_code)]
impl ConsoleUiTitleStyles {
    pub const fn from(
        content_colours: ConsoleColours,
        padding_colours: ConsoleColours,
        border_colours: ConsoleColours,
        alignment: UiElementAlignment,
        border_character: u16,
        pading_character: u16,
        border_thickness: u8,
    ) -> Self {
        Self {
            content_colours,
            padding_colours,
            border_colours,
            alignment,
            border_character,
            padding_character: pading_character,
            border_thickness,
        }
    }

    pub const fn with_padding(&self, colours: ConsoleColours, character: u16) -> Self {
        Self::from(
            self.content_colours,
            colours,
            self.border_colours,
            self.alignment,
            self.border_character,
            character,
            self.border_thickness,
        )
    }

    pub const fn with_content(
        &self,
        colours: ConsoleColours,
        alignment: UiElementAlignment,
    ) -> Self {
        Self::from(
            colours,
            self.padding_colours,
            self.border_colours,
            alignment,
            self.border_character,
            self.padding_character,
            self.border_thickness,
        )
    }

    pub const fn with_border(
        &self,
        thickness: u8,
        character: u16,
        colours: ConsoleColours,
    ) -> Self {
        Self::from(
            self.content_colours,
            self.padding_colours,
            colours,
            self.alignment,
            character,
            self.padding_character,
            thickness,
        )
    }

    pub const fn height(&self) -> usize {
        (self.border_thickness as usize * 2) + 1
    }
}

pub struct ConsoleUiTitle<'a> {
    styles: ConsoleUiTitleStyles,
    content: String16<'a>,
}

impl<'a> ConsoleUiTitle<'a> {
    pub const fn from(content: String16<'a>, style: ConsoleUiTitleStyles) -> Self {
        Self {
            content,
            styles: style,
        }
    }

    pub const fn height(&self) -> usize {
        self.styles.height()
    }
}

impl<'a> ConsoleWriteable for ConsoleUiTitle<'a> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console.line_start();
        let console_width = console.size().width();
        // Create a line buffer because we're going to be drawing a bunch of individual characters.
        let mut line_buffer = vec![0u16; console_width + 1];

        // Closure to write the border; we'll need to to it once before the content, and once after.
        let write_border = |line_buffer: &mut [u16]| {
            // Fill the buffer with the border character.
            line_buffer[..console_width].fill(self.styles.border_character);
            console.in_colours(self.styles.border_colours, |c| {
                // Write the full border lines.
                for _ in 0..self.styles.border_thickness {
                    c.output_utf16(String16::from(&line_buffer));
                }

                // Write the border characters for the line with the content.
                c.output_utf16(String16::from(
                    &line_buffer[console_width - (self.styles.border_thickness as usize)..],
                ))
            });
        };

        // Closure to write padding; we'll need to do it once before the content, and once after.
        let write_padding = |line_buffer: &mut [u16], padding_length: usize| {
            // Fill the buffer with the padding we'll need.
            line_buffer[console_width - padding_length..console_width]
                .fill(self.styles.padding_character);

            // Write the padding from the buffer.
            console.in_colours(self.styles.padding_colours, |c| {
                c.output_utf16(String16::from(
                    &line_buffer[console_width - padding_length..],
                ))
            });
        };

        // Write the leading border.
        write_border(&mut line_buffer);

        // Get the content length and the maximum length we can write.
        let content_length = self.content.content_length();
        let max_content_length = console_width - 2 - (self.styles.border_thickness as usize * 2);
        if content_length > max_content_length {
            // The content is too large to fit on a single line. We'll truncate it.
            // Write the leading padding; we want minimum padding to truncate as little as possible.
            write_padding(&mut line_buffer, 1);
            let start = console_width - max_content_length;
            let mut index = start;

            // Write as much content to the line buffer as we can, leaving space to an ellipsis.
            for character in self.content.content_iterator().take(max_content_length - 3) {
                line_buffer[index] = *character;
                index += 1;
            }

            // Write the ellipsis to the line buffer.
            line_buffer[index..console_width].fill(c16!("."));

            // Write the truncated content.
            console.in_colours(self.styles.content_colours, |c| {
                c.output_utf16(String16::from(&line_buffer[start..]))
            });

            // Write the trailing padding.
            write_padding(&mut line_buffer, 1);
        } else {
            // Calculate the total number of padding characters we'll write.
            let total_padding =
                console_width - (self.styles.border_thickness as usize * 2) - content_length;

            // Work out the left/right padding.
            let (left_padding, right_padding) = match self.styles.alignment {
                UiElementAlignment::Left => (1, total_padding - 1),
                UiElementAlignment::Centre => {
                    (total_padding / 2, total_padding - (total_padding / 2))
                }
                UiElementAlignment::Right => (total_padding - 1, 1),
            };

            // Write the leading padding.
            write_padding(&mut line_buffer, left_padding);

            // Write the content to the line buffer.
            let start = console_width - content_length;
            self.content
                .copy_content_to(&mut line_buffer[start..start + content_length]);

            // Write the content from the buffer to the console.
            console.in_colours(self.styles.content_colours, |c| {
                c.output_utf16(String16::from(&line_buffer[start..]))
            });

            // Write the trailing padding.
            write_padding(&mut line_buffer, right_padding);
        }

        // Write the trailing border.
        write_border(&mut line_buffer);
    }
}
