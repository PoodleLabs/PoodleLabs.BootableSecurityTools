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

use super::{ConsoleUiLabel, ConsoleWriteable};
use crate::{
    bitcoin::mnemonics::MnemonicParser,
    console_out::ConsoleOut,
    constants,
    keyboard_in::{BehaviourKey, Key, KeyboardIn},
    system_services::SystemServices,
    ui::Point,
    String16,
};
use alloc::{vec, vec::Vec};
use macros::{c16, s16};

// Readers beware... This is a fairly complicated UI. I'd recommend checking out some of the other UIs first if you haven't
// already, to get familiar with how BST UIs are written so the weirder stuff here isn't as hard to 'get'. Definitely at
// least try USING this UI (mnemonic entropy decoder programs, HD wallet seed generators) before trying to read the code.

pub fn get_mnemonic_input<
    FMnemonicAcceptancePredicate: Fn(&TMnemonicParser::TParseResult) -> bool,
    TMnemonicParser: MnemonicParser,
    TSystemServices: SystemServices,
>(
    acceptance_predicate: FMnemonicAcceptancePredicate,
    system_services: &TSystemServices,
    mnemonic_parser: &TMnemonicParser,
    possible_word_table_rows: usize,
) -> Option<(Vec<String16<'static>>, TMnemonicParser::TParseResult)>
where
    TMnemonicParser::TParseResult: ConsoleWriteable,
{
    let console = system_services.get_console_out();
    let mnemonic_format = mnemonic_parser.mnemonic_format();
    let word_list = mnemonic_format.word_list();

    let longest_word_length = word_list.longest_word_length();
    let max_words = mnemonic_format.max_words();
    let console_width = console.size().width();

    // A buffer for input truncation.
    let mut input_buffer = vec![0u16; max_words * (longest_word_length + 1)];

    // A buffer for the individual mnemonic words.
    let mut words: Vec<String16> = Vec::with_capacity(max_words);

    // A buffer for inputting mnemonic words one at a time.
    let mut current_word_buffer = vec![0u16; longest_word_length];
    let mut current_word_buffer_count = 0;

    // 'Possible word list' dimensions.
    let words_per_row = console_width / (longest_word_length + 1);

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
    for _ in 0..possible_word_table_rows {
        console.new_line();
    }

    // Ensure there's space for the exit message.
    console.in_colours(constants::PROMPT_COLOURS, |c| {
        c.output_utf16(s16!("Press ESC to..."))
    });

    // Calculate positions for UI elements.
    let end_position = console.cursor().position();
    let exit_message_position = Point::from(0, end_position.y());
    let word_list_position = exit_message_position - Point::from(0, possible_word_table_rows);
    let mnemonic_info_position = word_list_position - Point::from(0, 3);
    let mnemonic_input_position = mnemonic_info_position - Point::from(0, 3);

    // Get the keyboard input provider.
    let keyboard_in = system_services.get_keyboard_in();

    loop {
        // A flag indicating whether the user should be allowed to input more words.
        let allow_more_words = words.len() < max_words;

        // If there's at least one possible word for input, the first gets stored here.
        let mut completion_word = None;

        // Move the cursor position to the possible word list space.
        console.set_cursor_position(word_list_position);
        if allow_more_words {
            // Get the current word's input so far.
            let word_buffer_content = &current_word_buffer[..current_word_buffer_count];

            // Work out the possible words given the current word input.
            let possible_words = word_list
                .words()
                .iter()
                .filter(|w| {
                    w.content_length() >= current_word_buffer_count
                        && &w.content_slice()[..current_word_buffer_count] == word_buffer_content
                })
                .take(possible_word_table_rows * words_per_row);

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
        let parse_result = mnemonic_parser.try_decode_bytes(&words);

        // Write information about the current mnemonic input.
        console.set_cursor_position(mnemonic_info_position);
        parse_result.write_to(&console);
        console.blank_remaining_line();

        // We'll write the exit message now, so go to that position.
        console.set_cursor_position(exit_message_position);

        // A place to store mnemonic parse results.
        let output_result: Option<TMnemonicParser::TParseResult>;

        // Check whether the calling program would accept the parse result.
        if (acceptance_predicate)(&parse_result) {
            output_result = Some(parse_result);
            console.in_colours(constants::PROMPT_COLOURS, |c| {
                c.output_utf16(s16!("Press ESC to use mnemonic..."))
            });
        } else {
            output_result = None;
            console.in_colours(constants::PROMPT_COLOURS, |c| {
                // Trailing spaces as a poor man's blanking for the difference between this and 'Press ESC to use mnemonic...'.
                c.output_utf16(s16!("Press ESC to cancel...      "))
            });
        }

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
                        return match output_result {
                            Some(r) => Some((words, r)),
                            None => None,
                        };
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
                Key::Symbol(s) => {
                    if s == c16!(" ") && allow_more_words {
                        // If the user pressed space, and we have room for more words.
                        match completion_word {
                            Some(w) => {
                                // If there's a word we can add, add it to the word list.
                                words.push(*w);

                                // Then clear the current word buffer.
                                current_word_buffer_count = 0;
                                current_word_buffer.fill(0);
                                break;
                            }
                            None => { /* There's no possible word, so don't do anything. */ }
                        }
                    } else if s >= c16!("a")
                        && s <= c16!("z")
                        && allow_more_words
                        && current_word_buffer_count < current_word_buffer.len()
                    {
                        // If there's space, write the character to the current word buffer.
                        current_word_buffer[current_word_buffer_count] = s;
                        current_word_buffer_count += 1;
                        break;
                    }
                }
            }
        }
    }
}
