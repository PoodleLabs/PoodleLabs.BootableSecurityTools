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

#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod bitcoin;
mod bits;
mod characters;
mod clipboard;
mod console_out;
mod constants;
mod cryptography;
mod global_runtime_immutable;
mod hashing;
mod integers;
mod keyboard_in;
mod programs;
mod string16;
mod system_services;
#[cfg(test)]
mod tests;
mod uefi;
mod ui;

pub use string16::String16;

use console_out::{ConsoleColours, ConsoleOut};
use macros::s16;
use programs::{
    console::get_programs_list, exit_result_handlers::ConsoleDumpingProgramExitResultHandler,
    Program,
};
use system_services::SystemServices;
use ui::{
    console::{ConsoleUiConfirmationPrompt, ConsoleUiProgramSelector},
    ConfirmationPrompt, Point,
};

fn initialize_console<T: SystemServices>(
    system_services: &T,
    colours: ConsoleColours,
) -> T::TConsoleOut {
    let mut console = system_services.get_console_out();
    _ = console
        .reset()
        .set_cursor_visibility(false)
        .set_cursor_position(Point::ZERO)
        .set_colours(colours);

    match system_services.try_get_variable(T::console_resolution_variable_name()) {
        Some(r) => {
            console.set_mode_from_bytes(&r);
        }
        None => {
            let modes = console.get_modes();
            let mut area = 0usize;

            for mode in modes.iter() {
                let a = mode.size().area();
                if a > area && console.set_mode(mode.identifier().clone()) {
                    area = a;
                }
            }
        }
    }

    console.clear().clone()
}

fn run_console_ui<T: SystemServices>(system_services: T) {
    initialize_console(&system_services, constants::DEFAULT_COLOURS);
    let program_selector = ConsoleUiProgramSelector::from(
        constants::BIG_TITLE,
        constants::SELECT_LIST,
        system_services.clone(),
    );

    let exit_handler = ConsoleDumpingProgramExitResultHandler::from(system_services.clone());
    loop {
        get_programs_list(&system_services, &program_selector, &exit_handler).run();
        if ConsoleUiConfirmationPrompt::from(&system_services)
            .prompt_for_confirmation(s16!("Exit Poodle Labs' Bootable Security Tools?"))
        {
            break;
        }
    }
}
