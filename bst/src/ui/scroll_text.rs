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

use super::Point;
use crate::characters::Character;
use alloc::{vec, vec::Vec};
use macros::c16;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::ui) enum UiScrollTextChunkType {
    TrimmedContent,
    RawContent,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::ui) enum UiScrollTextLineStartType {
    SingleCharacterNewLine,
    TextStart,
    CrLf,
    Wrap,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::ui) struct UiScrollTextLineStartInformation {
    start_type: UiScrollTextLineStartType,
    index: usize,
}

impl UiScrollTextLineStartInformation {
    pub const TEXT_START: Self = Self::from(UiScrollTextLineStartType::TextStart, 0);

    const fn from(end_type: UiScrollTextLineStartType, index: usize) -> Self {
        Self {
            start_type: end_type,
            index,
        }
    }

    const fn cr_or_lf(index: usize) -> Self {
        Self::from(UiScrollTextLineStartType::SingleCharacterNewLine, index)
    }

    const fn cr_lf(index: usize) -> Self {
        Self::from(UiScrollTextLineStartType::CrLf, index)
    }

    const fn wrap(index: usize) -> Self {
        Self::from(UiScrollTextLineStartType::Wrap, index)
    }

    const fn start_index(&self) -> usize {
        self.index
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::ui) struct UiScrollText {
    line_starts: Vec<UiScrollTextLineStartInformation>,
    viewport_start_line_index: usize,
    viewport_bounds: Point,
    characters: Vec<u16>,
    cursor: Point,
}

impl UiScrollText {
    pub fn with_bounds(bounds: Point, characters: &[u16]) -> Self {
        let mut scroll_text = Self {
            line_starts: vec![UiScrollTextLineStartInformation::TEXT_START],
            viewport_start_line_index: 0,
            viewport_bounds: bounds,
            cursor: Point::ZERO,
            characters: characters
                .iter()
                .filter(|c| c.is_printable())
                .cloned()
                .collect::<Vec<u16>>(),
        };

        let character_count = scroll_text.character_count();
        scroll_text
            .update_line_starts()
            .move_cursor_to_character_index(character_count);

        scroll_text
    }

    pub fn take_ownership_of_content(self) -> Vec<u16> {
        self.characters
    }

    pub fn character_count(&self) -> usize {
        self.characters.len()
    }

    // Line Information
    pub fn line_starts(&self) -> &[UiScrollTextLineStartInformation] {
        &self.line_starts
    }

    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    pub fn line_start_index(&self, line_index: usize) -> usize {
        if line_index >= self.line_starts.len() {
            // Imaginary lines start at the end of the content.
            self.character_count()
        } else {
            // Line starts indexes are tracked.
            self.line_starts[line_index].index
        }
    }

    pub fn line_end_index(
        &self,
        line_index: usize,
        chunk_type: UiScrollTextChunkType,
    ) -> (usize, Option<UiScrollTextLineStartType>) {
        let next_line_index = line_index + 1;
        if next_line_index >= self.line_count() {
            // The line is the last line, or an imaginary line after it; it ends where the characters end.
            (self.character_count(), None)
        } else {
            // There's a next line; our line ends where that line starts.
            let next_line_start = self.line_starts[next_line_index];
            (
                match chunk_type {
                    UiScrollTextChunkType::TrimmedContent => match next_line_start.start_type {
                        // Trimmed content excludes the line endings, if there were any.
                        UiScrollTextLineStartType::SingleCharacterNewLine => {
                            next_line_start.index - 1
                        }
                        UiScrollTextLineStartType::CrLf => next_line_start.index - 2,
                        UiScrollTextLineStartType::Wrap => next_line_start.index,
                        UiScrollTextLineStartType::TextStart => 0,
                    },
                    // If we want the raw content (included line-endings),
                    // the end index is just the start index of the next line.
                    UiScrollTextChunkType::RawContent => next_line_start.index,
                },
                // Also return the next line's start type; a line start type is the end type of the previous line.
                Some(next_line_start.start_type),
            )
        }
    }

    pub fn line_length(&self, line_index: usize, chunk_type: UiScrollTextChunkType) -> usize {
        self.line_end_index(line_index, chunk_type).0 - self.line_start_index(line_index)
    }

    pub fn line_characters(
        &self,
        line_index: usize,
        chunk_type: UiScrollTextChunkType,
    ) -> (&[u16], Option<UiScrollTextLineStartType>) {
        let (end_index, end_type) = self.line_end_index(line_index, chunk_type);
        (
            &self.characters[self.line_start_index(line_index)..end_index],
            end_type,
        )
    }

    pub fn line_index_for_character_index(&self, index: usize) -> usize {
        // The first possible line which could contain this character index is, of course, the first line.
        let mut last_line_start_below = 0usize;
        for i in last_line_start_below + 1..self.line_starts.len() {
            // Iterate over the lines after the first.
            let line_start_index = self.line_starts[i].index;
            if index == line_start_index {
                // If this line starts at the requested index, we can just return this line's index right away.
                return i;
            }

            // If the requested index is before this line's start type, the index was contained in the previous line.
            if index < line_start_index {
                return last_line_start_below;
            }

            // We still haven't hit the requested index yet; this line might contain it, or it might be a subsequent line.
            last_line_start_below = i;
        }

        // The character index was on the last line (or doesn't exist).
        return last_line_start_below;
    }

    // Viewport Information
    pub const fn viewport_start_line_index(&self) -> usize {
        self.viewport_start_line_index
    }

    pub const fn viewport_bounds(&self) -> Point {
        self.viewport_bounds
    }

    pub fn viewport_end_line_index(&self) -> usize {
        (self.viewport_start_line_index() + self.viewport_bounds.height()).min(self.line_count())
    }

    pub fn has_hidden_leading_content(&self) -> bool {
        self.viewport_start_line_index > 0
    }

    pub fn has_hidden_trailing_content(&self) -> bool {
        self.viewport_end_line_index() < self.line_count()
    }

    // Cursor Information
    pub const fn cursor(&self) -> Point {
        self.cursor
    }

    pub const fn cursor_line_index(&self) -> usize {
        self.viewport_start_line_index + self.cursor.y()
    }

    pub fn cursor_line_start_index(&self) -> usize {
        self.line_start_index(self.cursor_line_index())
    }

    pub fn cursor_index(&self) -> usize {
        self.cursor_line_start_index() + self.cursor.x()
    }

    pub fn cursor_line_end_index(&self, chunk_type: UiScrollTextChunkType) -> usize {
        self.line_end_index(self.cursor_line_index(), chunk_type).0
    }

    // Cursor Movement
    pub fn move_cursor_to_character_index(&mut self, character_index: usize) -> &mut Self {
        let mut new_index = character_index;
        if self.is_cr_lf_at_index(new_index - 1) {
            // Don't drop the cursor into the middle of a cr lf.
            new_index += 1;
        }

        let character_line_index = self.line_index_for_character_index(new_index);
        if self.viewport_start_line_index > character_line_index {
            // If our new cursor line is above the viewport start, move the viewport up to include it.
            self.viewport_start_line_index = character_line_index
        } else if self.viewport_end_line_index() <= character_line_index {
            // If our new cursor line is below the viewport end, move the viewport down to include it.
            self.viewport_start_line_index =
                character_line_index - self.viewport_bounds.height() + 1
        }

        // Work out the cursor position based on the viewport position and character index.
        self.cursor = Point::from(
            (new_index - self.line_start_index(character_line_index)).min(
                self.line_end_index(character_line_index, UiScrollTextChunkType::RawContent)
                    .0,
            ),
            character_line_index - self.viewport_start_line_index,
        );

        self
    }

    pub fn move_cursor_right(&mut self) -> &mut Self {
        let cursor_index = self.cursor_index();
        if cursor_index == self.character_count() {
            // We're already at the end of the text; don't do anything.
            self
        } else {
            // Move the cursor to the next character.
            self.move_cursor_to_character_index(cursor_index + 1)
        }
    }

    pub fn move_cursor_left(&mut self) -> &mut Self {
        let cursor_index = self.cursor_index();
        if cursor_index == 0 {
            // We're already at the start of the text; don't do anything.
            self
        } else {
            // Move the cursor to the left; two character if we've got a CR LF to the left, otherwise one character.
            let offset = if self.is_cr_lf_at_index(cursor_index - 2) {
                2
            } else {
                1
            };

            self.move_cursor_to_character_index(cursor_index - offset)
        }
    }

    pub fn move_cursor_down(&mut self) -> &mut Self {
        let cursor_line_index = self.cursor_line_index();
        if cursor_line_index + 1 == self.line_count() {
            // If already at the bottom, move to the very end of the text.
            self.move_cursor_to_character_index(self.character_count())
        } else {
            // If we're not at the bottom yet, just move down one line.
            self.move_cursor_to_line(cursor_line_index + 1)
        }
    }

    pub fn move_cursor_up(&mut self) -> &mut Self {
        let cursor_line_index = self.cursor_line_index();
        if cursor_line_index == 0 {
            // If already at the top, move to the very start of the text.
            self.move_cursor_to_character_index(0)
        } else {
            // If we're not at the top yet, just move up one line.
            self.move_cursor_to_line(cursor_line_index - 1)
        }
    }

    pub fn move_cursor_to_start_of_line(&mut self) -> &mut Self {
        self.move_cursor_to_character_index(self.cursor_line_start_index())
    }

    pub fn move_cursor_to_end_of_line(&mut self) -> &mut Self {
        self.move_cursor_to_character_index(
            self.cursor_line_end_index(UiScrollTextChunkType::TrimmedContent),
        )
    }

    pub fn go_to_start(&mut self) -> &mut Self {
        self.move_cursor_to_character_index(0)
    }

    pub fn go_to_end(&mut self) -> &mut Self {
        self.move_cursor_to_character_index(self.character_count())
    }

    pub fn viewport_up(&mut self) -> &mut Self {
        if self.viewport_start_line_index() > 0 {
            self.move_cursor_to_line(self.viewport_start_line_index() - 1);
        }

        self
    }

    pub fn viewport_down(&mut self) -> &mut Self {
        self.move_cursor_to_line(self.viewport_end_line_index())
    }

    pub fn page_up(&mut self, cursor_agnostic: bool) -> &mut Self {
        let current_line_index = if cursor_agnostic {
            self.viewport_start_line_index()
        } else {
            self.cursor_line_index()
        };

        if current_line_index < self.viewport_bounds.height() - 1 {
            // If within a page of the top, move to the very start.
            self.move_cursor_to_character_index(0)
        } else {
            // Otherwise just move the cursor up a page's worth of lines.
            self.move_cursor_to_line(current_line_index - (self.viewport_bounds.height() - 1))
        }
    }

    pub fn page_down(&mut self, cursor_agnostic: bool) -> &mut Self {
        let current_line_index = if cursor_agnostic {
            self.viewport_end_line_index() - 1
        } else {
            self.cursor_line_index()
        };

        self.move_cursor_to_line(current_line_index + (self.viewport_bounds.height() - 1))
    }

    // Character Mutation
    pub fn insert_character(&mut self, character: u16) -> &mut Self {
        if !character.is_printable() {
            // Don't include non-printable characters.
            return self;
        }

        let cursor_index = self.cursor_index();
        // Insert the character wherever the cursor currently is.
        self.characters.insert(cursor_index, character);
        // Update the line starts, then move the cursor to the right.
        self.update_line_starts()
            .move_cursor_to_character_index(cursor_index + 1)
    }

    pub fn insert_characters<TIterator: Iterator<Item = u16>>(
        &mut self,
        characters: TIterator,
    ) -> &mut Self {
        let cursor_index = self.cursor_index();
        let mut printable_count = 0;

        for character in characters {
            if !character.is_printable() {
                // Don't include non-printable characters.
                continue;
            }

            // Insert the character.
            self.characters
                .insert(cursor_index + printable_count, character);

            // Count how many characters we've actually inserted.
            printable_count += 1;
        }

        // Update the line starts, then move the cursor to the right.
        self.update_line_starts()
            .move_cursor_to_character_index(cursor_index + printable_count)
    }

    pub fn backspace(&mut self) -> &mut Self {
        let cursor_index = self.cursor_index();
        if cursor_index == 0 {
            // We're at the start of the text; there's nothing to delete.
            return self;
        }

        let offset = if self.is_cr_lf_at_index(cursor_index - 2) {
            // There's a CR LF to the left of cursor; remove both at once.
            self.characters.remove(cursor_index - 1);
            self.characters.remove(cursor_index - 2);
            2
        } else {
            // Otherwise just remove the last character.
            self.characters.remove(cursor_index - 1);
            1
        };

        // Move the cursor to the new index, then update the line starts from there.
        self.move_cursor_to_character_index(cursor_index - offset)
            .update_line_starts()
    }

    pub fn delete(&mut self) -> &mut Self {
        let cursor_index = self.cursor_index();
        if cursor_index == self.character_count() {
            // We're at the end of the text; there's nothing to delete.
            return self;
        }

        // If there's a CR LF to our right, delete an extra character.
        if self.is_cr_lf_at_index(cursor_index) {
            self.characters.remove(cursor_index);
        }

        // Always delete at least one character.
        self.characters.remove(cursor_index);

        // Update the line starts from where we are.
        self.update_line_starts()
    }

    // Internal Helper Methods
    fn is_cr_lf_at_index(&self, index: usize) -> bool {
        self.character_count() > index // Check both index and index + 1 for a shortcut to underflow handling.
            && self.character_count() > index + 1 // Check there's at least 2 characters left at the index..
            && self.characters[index] == c16!("\r") // Check those two character are a CR
            && self.characters[index + 1] == c16!("\n") // And an LF.
    }

    fn move_cursor_to_line(&mut self, new_line_index: usize) -> &mut Self {
        let new_line_start_index = self.line_start_index(new_line_index);
        let new_line_length =
            self.line_length(new_line_index, UiScrollTextChunkType::TrimmedContent);

        // Don't leave the cursor floating in non-existent text.
        let new_index = new_line_start_index + (new_line_length.min(self.cursor.x()));
        self.move_cursor_to_character_index(new_index)
    }

    fn update_line_starts(&mut self) -> &mut Self {
        let cursor_line_index = self.cursor_line_index();
        let start_line_index = if cursor_line_index == 0 {
            0
        } else {
            // We need to go back a line for some awkward edge cases like multiple newlines in a row.
            cursor_line_index - 1
        };

        // Drop all the line endings after our working line.
        self.line_starts.truncate(start_line_index + 1);

        let mut skip_next = false;
        let mut working_line_length = 0;
        for i in self.line_starts().last().unwrap().start_index()..self.character_count() {
            if skip_next {
                // If we've previously determined that this character can be skipped, skip it.
                skip_next = false;
                continue;
            }

            let character = self.characters[i];
            if character == c16!("\n") {
                // We've hit a newline. Insert a line start.
                working_line_length = 0;
                self.line_starts
                    .push(UiScrollTextLineStartInformation::cr_or_lf(i + 1));
            } else if character == c16!("\r") {
                // We've hit a newline. It could be a CR LF. Work out which one it is.
                if self.is_cr_lf_at_index(i) {
                    self.line_starts
                        .push(UiScrollTextLineStartInformation::cr_lf(i + 2));
                    // There's an LF we've already handled after the current character; skip it.
                    skip_next = true;
                } else {
                    self.line_starts
                        .push(UiScrollTextLineStartInformation::cr_or_lf(i + 1));
                }

                working_line_length = 0;
            } else {
                // Not a newline character... Maybe it wraps?
                working_line_length += 1;
                if working_line_length >= self.viewport_bounds.width() {
                    self.line_starts
                        .push(UiScrollTextLineStartInformation::wrap(i + 1));
                    working_line_length = 0;
                }
            }
        }

        self
    }
}
