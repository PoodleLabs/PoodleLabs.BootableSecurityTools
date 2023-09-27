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
    programs::{Program, ProgramExitResult},
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_data_input, ConsoleUiContinuePrompt, ConsoleUiTitle, ConsoleWriteable,
        },
        ContinuePrompt, DataInput, DataInputType,
    },
    String16,
};
use alloc::{format, vec::Vec};
use core::cmp::Ordering;
use macros::s16;

pub struct ConsoleValueComparerProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices> ConsoleValueComparerProgram<TSystemServices> {
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program for ConsoleValueComparerProgram<TSystemServices> {
    fn name(&self) -> String16<'static> {
        s16!("Value Comparer")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console.output_utf16_line(s16!("This program compares two values and tells you whether they are identical and, if not, at which point they differ."));

        const CANCEL_PROMPT: String16 = s16!("Cancel Value Comparison?");
        match prompt_for_data_input(
            None,
            &[
                DataInputType::Text,
                DataInputType::Bytes,
                DataInputType::Number,
            ],
            &self.system_services,
            CANCEL_PROMPT,
            s16!("First Value"),
        ) {
            DataInput::None => return ProgramExitResult::UserCancelled,
            DataInput::Text(a) => {
                match prompt_for_data_input(
                    None,
                    &[DataInputType::Text],
                    &self.system_services,
                    CANCEL_PROMPT,
                    s16!("Second Value"),
                ) {
                    DataInput::Text(b) => {
                        compare_lists(&a, &b, &self.system_services);
                        return ProgramExitResult::Success;
                    }
                    _ => return ProgramExitResult::UserCancelled,
                }
            }
            DataInput::Bytes(a) => {
                match prompt_for_data_input(
                    None,
                    &[DataInputType::Bytes],
                    &self.system_services,
                    CANCEL_PROMPT,
                    s16!("Second Value"),
                ) {
                    DataInput::Bytes(b) => {
                        compare_lists(&a, &b, &self.system_services);
                        return ProgramExitResult::Success;
                    }
                    _ => return ProgramExitResult::UserCancelled,
                }
            }
            DataInput::Number(a) => {
                match prompt_for_data_input(
                    None,
                    &[DataInputType::Number],
                    &self.system_services,
                    CANCEL_PROMPT,
                    s16!("Second Value"),
                ) {
                    DataInput::Number(b) => {
                        console.line_start().new_line();
                        match a.cmp(&b) {
                            Ordering::Less => console.in_colours(constants::WARNING_COLOURS, |c| {
                                c.output_utf16_line(s16!(
                                    "The first value is less than the second."
                                ))
                            }),
                            Ordering::Equal => console
                                .in_colours(constants::SUCCESS_COLOURS, |c| {
                                    c.output_utf16_line(s16!("The values are equal."))
                                }),
                            Ordering::Greater => {
                                console.in_colours(constants::WARNING_COLOURS, |c| {
                                    c.output_utf16_line(s16!(
                                        "The first value is greater than the second."
                                    ))
                                })
                            }
                        };

                        ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
                        return ProgramExitResult::Success;
                    }
                    _ => return ProgramExitResult::UserCancelled,
                }
            }
        }
    }
}

fn compare_lists<T: Eq, TSystemServices: SystemServices>(
    a: &Vec<T>,
    b: &Vec<T>,
    system_services: &TSystemServices,
) {
    let console = system_services.get_console_out();
    console.line_start().new_line();

    let shared_length = a.len().min(b.len());
    let sa = &a[0..shared_length];
    let sb = &b[0..shared_length];
    for i in 0..shared_length {
        if sa[i] != sb[i] {
            console.in_colours(constants::WARNING_COLOURS, |c| {
                c.output_utf16(s16!("Values differ at index "))
                    .output_utf32(&format!("{}\0", i))
                    .output_utf16_line(s16!("."))
            });

            ConsoleUiContinuePrompt::from(system_services).prompt_for_continue();
            return;
        }
    }

    if a.len() == b.len() {
        console.in_colours(constants::SUCCESS_COLOURS, |c| {
            c.output_utf16_line(s16!("Values are identical."))
        });
    } else if a.len() < b.len() {
        console.in_colours(constants::WARNING_COLOURS, |c| {
            c.output_utf16(s16!(
                "The first value is a subset of the second; their lengths are "
            ))
            .output_utf32(&format!("{} and {}\0", a.len(), b.len()))
            .output_utf16_line(s16!(" respectively."))
        });
    } else {
        console.in_colours(constants::WARNING_COLOURS, |c| {
            c.output_utf16(s16!(
                "The second value is a subset of the first; their lengths are "
            ))
            .output_utf32(&format!("{} and {}\0", b.len(), a.len()))
            .output_utf16_line(s16!(" respectively."))
        });
    }

    ConsoleUiContinuePrompt::from(system_services).prompt_for_continue();
}
