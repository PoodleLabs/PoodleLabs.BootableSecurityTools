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
    clipboard::ClipboardEntry,
    console_out::ConsoleOut,
    constants,
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_clipboard_select, prompt_for_data_input, ConsoleUiConfirmationPrompt,
            ConsoleUiList, ConsoleUiTextBox, ConsoleUiTitle, ConsoleWriteable,
        },
        ConfirmationPrompt, DataInput, DataInputType,
    },
    String16,
};
use alloc::format;
use macros::s16;

pub struct ConsoleClipboardManagerProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> ConsoleClipboardManagerProgram<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program for ConsoleClipboardManagerProgram<TSystemServices> {
    fn name(&self) -> String16<'static> {
        s16!("Clipboard Manager")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!(
                "The clipboard is used to transfer data between different programs. Most programs finish by prompting you to (optionally) write data to the clipboard."
            ))
            .new_line()
            .output_utf16_line(s16!("To paste, when presented with an input, you can use CTRL + V, or CTRL + [1-0]."))
            .new_line()
            .output_utf16_line(s16!("Text inputs support pasting text and bytes, while byte and numeric inputs support only bytes."));

        loop {
            match prompt_for_clipboard_select(
                &self.system_services,
                s16!("Exit Clipboard Manager?"),
                s16!("Clipboard entry to view or modify"),
            ) {
                Some((entry, entry_index)) => {
                    console
                        .line_start()
                        .new_line()
                        .in_colours(constants::LABEL_COLOURS, |c| {
                            c.output_utf16(s16!("Clipboard Entry "))
                                .output_utf32_line(&format!("{}:\0", entry_index + 1))
                        });

                    match &entry {
                        ClipboardEntry::Empty => console.output_utf16_line(s16!("Empty")),
                        ClipboardEntry::Bytes(name, content) => console
                            .in_colours(constants::LABEL_COLOURS, |c| {
                                c.output_utf16(*name).output_utf16_line(s16!(":"))
                            })
                            .output_utf32_line(&format!("{:?}\0", content)),
                        ClipboardEntry::String16(name, content) => {
                            ConsoleUiTextBox::from(&self.system_services, constants::TEXT_DISPLAY)
                                .render_text(console.size().width(), *name, &content);
                            console.new_line()
                        }
                    };

                    const EMPTY_OPTIONS: [String16; 1] = [s16!("Write")];
                    const FULL_OPTIONS: [String16; 2] = [s16!("Overwrite"), s16!("Clear")];
                    match ConsoleUiList::from(
                        ConsoleUiTitle::from(s16!("Action"), constants::SMALL_TITLE),
                        constants::SELECT_LIST,
                        if entry != ClipboardEntry::Empty {
                            &FULL_OPTIONS[..]
                        } else {
                            &EMPTY_OPTIONS[..]
                        },
                    )
                    .prompt_for_selection(&self.system_services)
                    {
                        Some((_, _, index)) => {
                            if index == 0 {
                                match prompt_for_data_input(
                                    None,
                                    &[DataInputType::Text, DataInputType::Bytes],
                                    &self.system_services,
                                    s16!("Cancel clipboard write?"),
                                    s16!("Clipboard Write"),
                                ) {
                                    DataInput::Text(t) => {
                                        self.system_services.clipboard_mut().set_entry(
                                            entry_index,
                                            ClipboardEntry::String16(
                                                s16!("Manually Entered Text"),
                                                t.into(),
                                            ),
                                        );
                                    }
                                    DataInput::Bytes(b) => {
                                        self.system_services.clipboard_mut().set_entry(
                                            entry_index,
                                            ClipboardEntry::Bytes(
                                                s16!("Manually Entered Bytes"),
                                                b.into(),
                                            ),
                                        );
                                    }
                                    _ => {}
                                }
                            } else if ConsoleUiConfirmationPrompt::from(&self.system_services)
                                .prompt_for_confirmation(s16!("Clear the clipboard entry?"))
                            {
                                self.system_services
                                    .clipboard_mut()
                                    .set_entry(entry_index, ClipboardEntry::Empty);
                            }
                        }
                        None => {}
                    };
                }
                None => return ProgramExitResult::Success,
            }
        }
    }
}
