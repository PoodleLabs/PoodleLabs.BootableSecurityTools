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
            prompt_for_data_input, ConsoleUiConfirmationPrompt, ConsoleUiContinuePrompt,
            ConsoleUiLabel, ConsoleUiList, ConsoleUiTitle, ConsoleWriteable,
        },
        ConfirmationPrompt, ContinuePrompt, DataInput, DataInputType,
    },
    String16,
};
use alloc::vec::Vec;
use macros::{c16, s16};

pub struct ConsoleMnemonicEntropyEncoder<
    TMnemonicLength: Into<usize> + ConsoleWriteable + Copy + 'static,
    FGetAvailableLengths: Fn(usize) -> &'static [TMnemonicLength],
    TSystemServices: SystemServices,
    FMnemonicEncoder: Fn(
        &TSystemServices,
        TMnemonicLength,
        &[u8],
    ) -> Result<Vec<String16<'static>>, Option<String16<'static>>>,
> {
    available_lengths_calculator: FGetAvailableLengths,
    mnemonic_format_name: String16<'static>,
    word_list: &'static [String16<'static>],
    minimum_byte_count: String16<'static>,
    word_list_name: String16<'static>,
    system_services: TSystemServices,
    encoder: FMnemonicEncoder,
    name: String16<'static>,
}

impl<
        TMnemonicLength: Into<usize> + ConsoleWriteable + Copy + 'static,
        FGetAvailableLengths: Fn(usize) -> &'static [TMnemonicLength],
        TSystemServices: SystemServices,
        FMnemonicEncoder: Fn(
            &TSystemServices,
            TMnemonicLength,
            &[u8],
        ) -> Result<Vec<String16<'static>>, Option<String16<'static>>>,
    >
    ConsoleMnemonicEntropyEncoder<
        TMnemonicLength,
        FGetAvailableLengths,
        TSystemServices,
        FMnemonicEncoder,
    >
{
    pub const fn from(
        available_lengths_calculator: FGetAvailableLengths,
        mnemonic_format_name: String16<'static>,
        word_list: &'static [String16<'static>],
        minimum_byte_count: String16<'static>,
        word_list_name: String16<'static>,
        system_services: TSystemServices,
        encoder: FMnemonicEncoder,
        name: String16<'static>,
    ) -> Self {
        Self {
            available_lengths_calculator,
            mnemonic_format_name,
            minimum_byte_count,
            system_services,
            word_list_name,
            word_list,
            encoder,
            name,
        }
    }
}

impl<
        TMnemonicLength: Into<usize> + ConsoleWriteable + Copy + 'static,
        FGetAvailableLengths: Fn(usize) -> &'static [TMnemonicLength],
        TSystemServices: SystemServices,
        FMnemonicEncoder: Fn(
            &TSystemServices,
            TMnemonicLength,
            &[u8],
        ) -> Result<Vec<String16<'static>>, Option<String16<'static>>>,
    > Program
    for ConsoleMnemonicEntropyEncoder<
        TMnemonicLength,
        FGetAvailableLengths,
        TSystemServices,
        FMnemonicEncoder,
    >
{
    fn name(&self) -> String16<'static> {
        self.name
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16(s16!("This program encodes entropy into the "))
            .output_utf16(self.mnemonic_format_name)
            .output_utf16(s16!(" Mnemonic Format utilizing the "))
            .output_utf16(self.word_list_name)
            .output_utf16_line(s16!(" word list. Given more bits than required for a given mnemonic length, the trailing bits will be used."));

        const CANCEL_PROMPT_STRING: String16<'static> = s16!("Exit Mnemonic Encoder program?");
        let (bytes, mnemonic_length) = loop {
            // Prompt for input bytes.
            let bytes = match prompt_for_data_input(
                None,
                &[DataInputType::Bytes],
                &self.system_services,
                CANCEL_PROMPT_STRING,
                s16!("Entropy Bytes"),
            ) {
                DataInput::Bytes(b) => b,
                _ => return ProgramExitResult::UserCancelled,
            };

            let available_mnemonic_lengths = (self.available_lengths_calculator)(bytes.len());
            if available_mnemonic_lengths.len() == 0 {
                // We can't create a mnemonic with the provided bytes; prompt the user for new bytes.
                console
                    .line_start()
                    .new_line()
                    .in_colours(constants::ERROR_COLOURS, |c| {
                        c.output_utf16(s16!("Cannot encode a "))
                            .output_utf16(self.mnemonic_format_name)
                            .output_utf16(s16!(
                                " mnemonic with the provided number of bytes; at least "
                            ))
                            .output_utf16(self.minimum_byte_count)
                            .output_utf16_line(s16!(" are required."))
                    });
            } else if available_mnemonic_lengths.len() == 1 {
                // There's one possible length; select it.
                break (bytes, available_mnemonic_lengths[0]);
            } else {
                // There are multiple possible lengths; have the user select one.
                let mut available_mnemonic_length_list = ConsoleUiList::from(
                    ConsoleUiTitle::from(s16!(" Mnemonic Length "), constants::SMALL_TITLE),
                    constants::SELECT_LIST,
                    available_mnemonic_lengths,
                );

                break loop {
                    console.line_start().new_line();
                    match available_mnemonic_length_list.prompt_for_selection(&self.system_services)
                    {
                        Some((l, _, _)) => break (bytes, *l),
                        None => {
                            if ConsoleUiConfirmationPrompt::from(&self.system_services)
                                .prompt_for_confirmation(CANCEL_PROMPT_STRING)
                            {
                                return ProgramExitResult::UserCancelled;
                            }
                        }
                    }
                };
            }
        };

        // Generate the mnemonic's words.
        let mut mnemonic_words =
            match (self.encoder)(&self.system_services, mnemonic_length, &bytes) {
                Ok(words) => words,
                Err(message) => {
                    match message {
                        Some(message) => {
                            // We can't create a mnemonic with the provided bytes for some reason; print the error.
                            console
                                .line_start()
                                .new_line()
                                .in_colours(constants::ERROR_COLOURS, |c| {
                                    c.output_utf16_line(message)
                                });
                            ConsoleUiContinuePrompt::from(&self.system_services)
                                .prompt_for_continue();
                            return ProgramExitResult::String16Error(
                                message.content_slice().into(),
                            );
                        }
                        None => {
                            // The user cancelled mnemonic generation.
                            return ProgramExitResult::UserCancelled;
                        }
                    }
                }
            };

        // Allocate a u16 vector to hold the full mnemonic with spaces.
        let mut mnemonic = Vec::with_capacity(
            (mnemonic_words.len() - 1)
                + mnemonic_words
                    .iter()
                    .map(|w| w.content_length())
                    .sum::<usize>(),
        );

        // Write the mnemonic's words to the u16 vector.
        for i in 0..mnemonic_words.len() {
            mnemonic.extend(mnemonic_words[i].content_iterator().by_ref());
            if i < mnemonic_words.len() - 1 {
                // Append a space if not the last word.
                mnemonic.push(c16!(" "));
            }

            // Clear the mnemonic word in the underlying vector (will be cleared on dealloc, but to be safe).
            mnemonic_words[i] = self.word_list[0]
        }

        console
            .line_start()
            .new_line()
            .in_colours(constants::SUCCESS_COLOURS, |c| {
                c.output_utf16_line(s16!("Encoded mnemonic successfully."))
            })
            .in_colours(constants::WARNING_COLOURS, |c| {
                c.output_utf16_line(s16!(
                    "NOTE: You will not be prompted to clipboard it. Write it down."
                ))
            });

        ConsoleUiLabel::from(s16!("Mnemonic")).write_to(&console);
        console.output_utf16_line(String16::from(&mnemonic));
        ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
        ProgramExitResult::Success
    }
}
