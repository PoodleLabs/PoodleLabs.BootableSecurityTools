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

use super::{ConsoleUiConfirmationPrompt, ConsoleUiLabel, ConsoleUiList, ConsoleUiTitle};
use crate::{
    characters::Character,
    clipboard::ClipboardEntry,
    console_out::ConsoleOut,
    constants,
    system_services::SystemServices,
    ui::{console::ConsoleWriteable, ConfirmationPrompt},
    String16,
};
use alloc::format;
use macros::{c16, s16};

pub fn prompt_for_clipboard_select<TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    cancel_prompt: String16,
    prompt: String16,
) -> Option<(ClipboardEntry, usize)> {
    ConsoleUiLabel::from(prompt).write_to(&system_services.get_console_out());
    let mut list = ConsoleUiList::from(
        ConsoleUiTitle::from(s16!(" Clipboard Entries "), constants::SMALL_TITLE),
        constants::SELECT_LIST,
        system_services.clipboard().get_entries(),
    );

    loop {
        match list.prompt_for_selection(system_services) {
            Some((e, _, i)) => {
                return Some((e.clone(), i));
            }
            None => {
                if ConsoleUiConfirmationPrompt::from(system_services)
                    .prompt_for_confirmation(cancel_prompt)
                {
                    // User selected nothing then confirmed they wanted to cancel; return nothing.
                    return None;
                }

                // User selected nothing, but then did not confirm cancellation; try again.
            }
        }
    }
}

pub fn prompt_for_clipboard_write<TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    clipboard_entry: ClipboardEntry,
) {
    match prompt_for_clipboard_select(
        system_services,
        s16!("Skip saving to clipboard?"),
        s16!("Select a clipboard to write to"),
    ) {
        Some((_, i)) => {
            system_services
                .clipboard_mut()
                .set_entry(i, clipboard_entry);
        }
        None => {}
    };
}

fn preview_close(truncated: bool) -> String16<'static> {
    if truncated {
        s16!("...)")
    } else {
        s16!(")")
    }
}

impl ConsoleWriteable for ClipboardEntry {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        match self {
            ClipboardEntry::Empty => {
                console.output_utf16(s16!("Empty"));
            }
            ClipboardEntry::Bytes(name, b) => {
                // Output '[NAME] ('
                console.output_utf16(*name).output_utf16(s16!(" ("));
                match b.len() {
                    0 => {
                        // The byte array is empty; output will be '[NAME] (Empty)'
                        console.output_utf16(s16!("Empty"));
                    }
                    1 => {
                        // The byte array has a single value; output will be '[NAME] (v[0])'
                        console.output_utf32(&format!("{}\0", b[0]));
                    }
                    2 => {
                        // The byte array has two values; output will be '[NAME] (v[0], v[1])'
                        console.output_utf32(&format!("{}, {}\0", b[0], b[1]));
                    }
                    _ => {
                        // The byte array has more than two values; output will be '[NAME] ([LEN]: v[0], v[1]...)'
                        console.output_utf32(&format!("{}: {}, {}\0", b.len(), b[0], b[1]));
                    }
                };

                // Output the the bracket close, with an ellipsis if truncating.
                console.output_utf16(preview_close(b.len() > 2));
            }
            ClipboardEntry::String16(name, c) => {
                const TRUNCATE_LENGTH: usize = 16;

                // Write the clipboard entry to a truncated content buffer.
                let mut content_buffer = [0u16; TRUNCATE_LENGTH + 1];
                let mut content_buffer_length = 0;
                let mut i = 0;

                // Read until the content is over, or the buffer is full.
                while content_buffer_length < TRUNCATE_LENGTH && i < c.len() {
                    let character = match c[i] {
                        // Don't write newlines.
                        c16!("\r") | c16!("\n") => None,
                        // Write tabs as spaces.
                        c16!("\t") => Some(c16!(" ")),
                        c => {
                            if c.is_printable() {
                                Some(c)
                            } else {
                                // Don't write non-printable characters.
                                None
                            }
                        }
                    };

                    i += 1;
                    match character {
                        Some(character) => {
                            content_buffer[content_buffer_length] = character;
                            content_buffer_length += 1;
                        }
                        None => {}
                    };
                }

                let output = &content_buffer[..content_buffer_length];

                // Output '[NAME] ('
                console.output_utf16(*name).output_utf16(s16!(" ("));
                if i < c.len() {
                    // The content was truncated; output will be '[NAME] ([LEN]: [FIRST_16_CHARS]...)'
                    console
                        .output_utf32(&format!("{}: \0", c.len()))
                        .output_utf16(String16::from(output));
                } else {
                    // The content will fit within the truncation length; output will be '[NAME] ([CONTENT])'
                    console.output_utf16(String16::from(output));
                }

                // Output the the bracket close, with an ellipsis if truncating.
                console.output_utf16(preview_close(i < c.len()));
            }
        }
    }
}
