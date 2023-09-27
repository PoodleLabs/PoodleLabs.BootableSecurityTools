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
    console_out::ConsoleOut,
    constants,
    keyboard_in::{Key, KeyboardIn},
    system_services::SystemServices,
    ui::ConfirmationPrompt,
    String16,
};
use macros::{c16, s16};

pub struct ConsoleUiConfirmationPrompt<'a, TSystemServices: SystemServices> {
    system_services: &'a TSystemServices,
}

impl<'a, TSystemServices: SystemServices> ConsoleUiConfirmationPrompt<'a, TSystemServices> {
    pub const fn from(system_services: &'a TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<'a, TSystemServices: SystemServices> ConfirmationPrompt
    for ConsoleUiConfirmationPrompt<'a, TSystemServices>
{
    fn prompt_for_confirmation(&self, label: String16) -> bool {
        // Write the label.
        let console = self.system_services.get_console_out();
        ConsoleUiLabel::from(label).write_to(&console);

        // Write the 'confirm' message.
        console.in_colours(constants::PROMPT_COLOURS, |c| {
            c.output_utf16_line(s16!("Press Y to confirm, N to cancel."))
        });

        let keyboard_in = self.system_services.get_keyboard_in();
        loop {
            // Wait for a keypress.
            let key = keyboard_in.read_key();
            match key.key() {
                Key::Symbol(s) => match s {
                    // Key press was 'Y' key; return true.
                    c16!("y") | c16!("Y") => return true,

                    // Key press was 'N' key; return false.
                    c16!("n") | c16!("N") => return false,

                    // Key press was a different symbol key; keep reading key presses.
                    _ => continue,
                },
                // Key press was a not a symbol key; keep reading key presses.
                _ => continue,
            }
        }
    }
}
