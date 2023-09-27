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
    bitcoin::mnemonics::bip_39::{LONGEST_WORD_LENGTH, WORD_LIST},
    clipboard::ClipboardEntry,
    console_out::ConsoleOut,
    constants,
    keyboard_in::{BehaviourKey, Key, KeyboardIn},
    programs::{console::write_bytes, Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{prompt_for_clipboard_write, ConsoleUiLabel, ConsoleUiTitle, ConsoleWriteable},
        Point,
    },
    String16,
};
use alloc::{boxed::Box, vec::Vec};
use macros::{c16, s16};

pub trait Bip39BasedMnemonicParseResult: ConsoleWriteable {
    fn get_bytes(self) -> Option<Box<[u8]>>;
}

pub struct ConsoleBip39WordListMnemonicDecoder<
    TSystemServices: SystemServices,
    TMnemonicParseResult: Bip39BasedMnemonicParseResult,
    FMnemonicParser: Fn(&Vec<String16<'static>>) -> TMnemonicParseResult,
> {
    clipboard_entry_name: String16<'static>,
    mnemonic_format_name: String16<'static>,
    system_services: TSystemServices,
    mnemonic_parser: FMnemonicParser,
    name: String16<'static>,
}

impl<
        TSystemServices: SystemServices,
        TMnemonicParseResult: Bip39BasedMnemonicParseResult,
        FMnemonicParser: Fn(&Vec<String16<'static>>) -> TMnemonicParseResult,
    > ConsoleBip39WordListMnemonicDecoder<TSystemServices, TMnemonicParseResult, FMnemonicParser>
{
    pub const fn from(
        name: String16<'static>,
        mnemonic_parser: FMnemonicParser,
        system_services: TSystemServices,
        mnemonic_format_name: String16<'static>,
        clipboard_entry_name: String16<'static>,
    ) -> Self {
        Self {
            clipboard_entry_name,
            mnemonic_format_name,
            system_services,
            mnemonic_parser,
            name,
        }
    }
}

impl<
        TSystemServices: SystemServices,
        TMnemonicParseResult: Bip39BasedMnemonicParseResult,
        FMnemonicParser: Fn(&Vec<String16<'static>>) -> TMnemonicParseResult,
    > Program
    for ConsoleBip39WordListMnemonicDecoder<TSystemServices, TMnemonicParseResult, FMnemonicParser>
{
    fn name(&self) -> String16<'static> {
        self.name
    }

    fn run(&self) -> ProgramExitResult {
        // Readers beware... This program has a fairly complicated UI. I'd recommend checking out some of the other programs first
        // if you haven't already, to get familiar with how BST UIs are written so the weirder stuff here isn't as hard to 'get'.
        // Definitely at least try USING this UI before trying to read the code.

        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16(s16!("This program decodes entropy from the "))
            .output_utf16(self.mnemonic_format_name)
            .output_utf16_line(s16!(
                " Mnemonic Format utilizing the BIP 39 word list, validates it, and extracts the underlying bytes."
            ));

        let console_width = console.size().width();
        const MAX_WORDS: usize = 24;

        // A buffer for input truncation.
        let mut input_buffer = [0u16; MAX_WORDS * (LONGEST_WORD_LENGTH as usize + 1)];

        // A buffer for the individual mnemonic words.
        let mut words: Vec<String16> = Vec::with_capacity(MAX_WORDS);

        // A buffer for inputting mnemonic words one at a time.
        let mut current_word_buffer = [0u16; LONGEST_WORD_LENGTH as usize];
        let mut current_word_buffer_count = 0;

        // 'Possible word list' dimensions.
        let words_per_row = console_width / (LONGEST_WORD_LENGTH as usize + 1);
        const POSSIBLE_WORD_ROWS: usize = 5;

        // Write the input UI structure; entered mnemonic label first.
        ConsoleUiLabel::from(s16!("Entered Mnemonic")).write_to(&console);

        // Make space for the mnemonic line.
        console.line_start().new_line();

        // Write the mnemonic info label.
        ConsoleUiLabel::from(s16!("Mnemonic Information")).write_to(&console);

        // Make space for the status line.
        console.line_start().new_line();

        // Write the possible words list label.
        ConsoleUiLabel::from(s16!("Possible Words")).write_to(&console);

        // Make sure we have space to write five rows of possible words.
        console.line_start();
        for _ in 0..POSSIBLE_WORD_ROWS {
            console.new_line();
        }

        // Write the exit message.
        console.in_colours(constants::PROMPT_COLOURS, |c| {
            c.output_utf16(s16!("Press ESC to complete input."))
        });

        // Calculate positions for UI elements.
        let end_position = console.cursor().position();
        let word_list_position = Point::from(0, end_position.y() - POSSIBLE_WORD_ROWS);
        let mnemonic_info_position = word_list_position - Point::from(0, 3);
        let mnemonic_input_position = mnemonic_info_position - Point::from(0, 3);

        // Get the keyboard input provider.
        let keyboard_in = self.system_services.get_keyboard_in();

        // A place to store mnemonic bytes.
        let mut mnemonic_bytes: Option<Box<[u8]>>;
        loop {
            // A flag indicating whether the user should be allowed to input more words.
            let allow_more_words = words.len() < 24;

            // If there's at least one possible word for input, the first gets stored here.
            let mut completion_word = None;

            // Move the cursor position to the possible word list space.
            console.set_cursor_position(word_list_position);
            if allow_more_words {
                // Get the current word's input so far.
                let word_buffer_content = &current_word_buffer[..current_word_buffer_count];

                // Work out the possible words given the current word input.
                let possible_words = WORD_LIST
                    .iter()
                    .filter(|w| {
                        w.content_length() >= current_word_buffer_count
                            && &w.content_slice()[..current_word_buffer_count]
                                == word_buffer_content
                    })
                    .take(POSSIBLE_WORD_ROWS * words_per_row);

                // Track the number of words we've written in the current line.
                let mut line_word_counter = 0;

                // Write the possible word list.
                for word in possible_words {
                    let blanking = 9 - word.content_length();
                    match completion_word {
                        Some(_) => {
                            console
                                .output_utf16(word.clone())
                                .blank_up_to_line_end(blanking);
                        }
                        None => {
                            // Highlight the first word, as that's the one that would be autocompleted on space key press.
                            console.in_colours(constants::PROMPT_COLOURS, |c| {
                                c.output_utf16(word.clone()).blank_up_to_line_end(blanking)
                            });

                            completion_word = Some(word);
                        }
                    }

                    line_word_counter += 1;
                    if words_per_row == line_word_counter {
                        // Handle any remainder of the screen width.
                        console.blank_remaining_line();
                        line_word_counter = 0;
                    }
                }
            }

            // Blank any remaining lines in the word list space.
            while console.cursor().position().y() < end_position.y() {
                console.blank_remaining_line();
            }

            // Parse the mnemonic input.
            let parse_result = (self.mnemonic_parser)(&words);

            // Write information about the current mnemonic input.
            console.set_cursor_position(mnemonic_info_position);
            parse_result.write_to(&console);
            console.blank_remaining_line();

            // Get the byte option from the parse result.
            mnemonic_bytes = parse_result.get_bytes();

            // Write the current input to the input line buffer.
            let mut input_buffer_offset = 0;
            for word in &words {
                // Get the length of the word.
                let word_length = word.content_length();

                // Write the word to the buffer.
                input_buffer[input_buffer_offset..input_buffer_offset + word_length]
                    .copy_from_slice(word.content_slice());

                // Write a space to the buffer.
                input_buffer[input_buffer_offset + word_length] = c16!(" ");

                // Add the word and space's length to the offset.
                input_buffer_offset += word_length + 1;
            }

            if allow_more_words {
                // If there's space for more words, write the current word buffer to the input buffer.
                input_buffer[input_buffer_offset..input_buffer_offset + current_word_buffer_count]
                    .copy_from_slice(&current_word_buffer[..current_word_buffer_count]);

                // Update the offset; we want a null at the end, so add an extra 1.
                input_buffer_offset += current_word_buffer_count + 1;
            }

            // Fill the remaining buffer with null.
            input_buffer[input_buffer_offset - 1..].fill(0);

            // Move the cursor to the mnemonic input line.
            console.set_cursor_position(mnemonic_input_position);
            console.in_colours(
                if completion_word.is_none() && current_word_buffer_count > 0 {
                    // There's no possible words, and we've started writing one; the input is bad.
                    constants::ERROR_COLOURS
                } else {
                    constants::DEFAULT_COLOURS
                },
                |c| {
                    if input_buffer_offset > console_width {
                        // If there's not enough space to write the entire mnemonic, start with an ellipsis.
                        c.output_utf16(s16!("..."))
                            // Then write the tail of the input buffer.
                            .output_utf16(String16::from(
                                // +4 for ellipsis and a cursor space.
                                &input_buffer
                                    [input_buffer_offset - console_width + 4..input_buffer_offset],
                            ))
                    } else {
                        // If there's enough space to write the entire mnemonic, just write it.
                        c.output_utf16(String16::from(&input_buffer[..input_buffer_offset]))
                    }
                },
            );

            // Get the position where the input ends.
            let input_cursor_position = console.cursor().position();

            // Blank then go back to the end of the line.
            console
                .blank_remaining_line()
                .set_cursor_position(input_cursor_position);

            // Show the cursor during input.
            console.set_cursor_visibility(true);

            // A flag indicating whether an exit has been requested.
            let mut exit = false;

            // Only re-draw when there's some actual change.
            loop {
                // Read some input.
                let key = keyboard_in.read_key();

                // Hide the cursor the rest of the time.
                console.set_cursor_visibility(false);

                match key.key() {
                    Key::Behaviour(b) => match b {
                        BehaviourKey::Escape => {
                            console.set_cursor_position(end_position).line_start();
                            exit = true;
                            break;
                        }
                        BehaviourKey::BackSpace => {
                            if current_word_buffer_count > 0 {
                                // If we've started writing a word, pop the last character.
                                current_word_buffer[current_word_buffer_count - 1] = 0;
                                current_word_buffer_count -= 1;
                                break;
                            }

                            if words.len() > 0 {
                                // If we've not started writing a new word, but there are previous words,
                                // move the previous word into the current word buffer.
                                let word = words.pop().unwrap();
                                current_word_buffer_count = word.content_length();
                                current_word_buffer[..current_word_buffer_count]
                                    .copy_from_slice(word.content_slice());
                                break;
                            }
                        }
                        _ => {}
                    },
                    Key::Digit(_) => { /* Ignore digits. */ }
                    Key::Symbol(s) => match s {
                        c16!("a")
                        | c16!("b")
                        | c16!("c")
                        | c16!("d")
                        | c16!("e")
                        | c16!("f")
                        | c16!("g")
                        | c16!("h")
                        | c16!("i")
                        | c16!("j")
                        | c16!("k")
                        | c16!("l")
                        | c16!("m")
                        | c16!("n")
                        | c16!("o")
                        | c16!("p")
                        | c16!("q")
                        | c16!("r")
                        | c16!("s")
                        | c16!("t")
                        | c16!("u")
                        | c16!("v")
                        | c16!("w")
                        | c16!("x")
                        | c16!("y")
                        | c16!("z") => {
                            if allow_more_words
                                && current_word_buffer_count < current_word_buffer.len()
                            {
                                // If there's space, write the character to the current word buffer.
                                current_word_buffer[current_word_buffer_count] = s;
                                current_word_buffer_count += 1;
                                break;
                            }
                        }
                        c16!(" ") => match completion_word {
                            Some(w) => {
                                if allow_more_words {
                                    // Add the word to the word list.
                                    words.push(*w);

                                    // Then clear the current word buffer.
                                    current_word_buffer_count = 0;
                                    current_word_buffer.fill(0);
                                    break;
                                }
                            }
                            None => { /* There's no possible word, so don't do anything. */ }
                        },
                        _ => { /* Ignore any other symbol input. */ }
                    },
                }
            }

            if exit {
                break;
            }
        }

        match mnemonic_bytes {
            Some(bytes) => {
                write_bytes(&self.system_services, self.clipboard_entry_name, &bytes);
                prompt_for_clipboard_write(
                    &self.system_services,
                    ClipboardEntry::Bytes(self.clipboard_entry_name, bytes.into()),
                );

                ProgramExitResult::Success
            }
            None => ProgramExitResult::UserCancelled,
        }
    }
}
