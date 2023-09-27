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
    console_out::ConsoleOut,
    constants,
    keyboard_in::{BehaviourKey, Key, KeyboardIn},
    system_services::SystemServices,
    ui::ContinuePrompt,
};
use macros::s16;

pub struct ConsoleUiContinuePrompt<'a, TSystemServices: SystemServices> {
    system_services: &'a TSystemServices,
}

impl<'a, TSystemServices: SystemServices> ConsoleUiContinuePrompt<'a, TSystemServices> {
    pub const fn from(system_services: &'a TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<'a, TSystemServices: SystemServices> ContinuePrompt
    for ConsoleUiContinuePrompt<'a, TSystemServices>
{
    fn prompt_for_continue(&self) {
        // Write the 'continue' message.
        self.system_services
            .get_console_out()
            .line_start()
            .in_colours(constants::PROMPT_COLOURS, |c| {
                c.output_utf16_line(s16!("Press ENTER to continue..."))
            });

        loop {
            // Read a key; if it's the Enter key, return, otherwise just loop for the next key.
            if self.system_services.get_keyboard_in().read_key().key()
                == Key::Behaviour(BehaviourKey::Return)
            {
                return;
            }
        }
    }
}
