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

use super::{
    mnemonic_entropy_decoder::{ConsoleMnemonicEntropyDecoder, MnemonicByteParseResult},
    mnemonic_entropy_encoder::ConsoleMnemonicEntropyEncoder,
};
use crate::{
    bitcoin::mnemonics::{
        bip_39,
        electrum::{
            self, required_bits_of_entropy_for_mnemonic_length, try_generate_electrum_mnemonic,
            try_parse_electrum_mnemonic, ElectrumMnemonicLength, ElectrumMnemonicParsingResult,
            ElectrumMnemonicVersion,
        },
    },
    console_out::ConsoleOut,
    constants,
    programs::{
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program,
    },
    system_services::SystemServices,
    ui::{
        console::{
            ConsoleUiConfirmationPrompt, ConsoleUiLabel, ConsoleUiList, ConsoleUiTitle,
            ConsoleWriteable,
        },
        ConfirmationPrompt,
    },
    String16,
};
use alloc::{boxed::Box, format, sync::Arc, vec::Vec};
use macros::s16;

pub fn get_electrum_mnemonic_program_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector + 'static,
    TProgramExitResultHandler: ProgramExitResultHandler + 'static,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 2] = [
        Arc::from(ConsoleMnemonicEntropyEncoder::from(
            electrum::get_available_mnemonic_lengths,
            s16!("Electrum"),
            &bip_39::WORD_LIST,
            s16!("17"),
            s16!("BIP 39"),
            system_services.clone(),
            mnemonic_encoder,
            s16!("Electrum Entropy Encoder (BIP 39 Words)"),
        )),
        Arc::from(ConsoleMnemonicEntropyDecoder::from(
            s16!("Electrum Mnemonic Bytes"),
            s16!("Electrum"),
            &bip_39::WORD_LIST,
            s16!("BIP 39"),
            system_services.clone(),
            mnemonic_parser,
            bip_39::LONGEST_WORD_LENGTH as usize,
            s16!("Electrum Entropy Decoder (BIP 39 Words)"),
            electrum::MAX_WORD_COUNT,
        )),
    ];

    ProgramList::from(Arc::from(programs), s16!("Electrum Mnemonic Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

impl ConsoleWriteable for ElectrumMnemonicVersion {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console.output_utf16((*self).into());
    }
}

fn mnemonic_encoder<TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    mnemonic_length: ElectrumMnemonicLength,
    bytes: &[u8],
) -> Result<Vec<String16<'static>>, Option<String16<'static>>> {
    // User must select a mnemonic version; allow either Segwit or Legacy.
    let mut mnemonic_version_list = ConsoleUiList::from(
        ConsoleUiTitle::from(s16!(" Mnemonic Version "), constants::SMALL_TITLE),
        constants::SELECT_LIST,
        &[
            ElectrumMnemonicVersion::Segwit,
            ElectrumMnemonicVersion::Legacy,
        ][..],
    );

    let console = system_services.get_console_out();
    let mnemonic_version_selection_label = ConsoleUiLabel::from(s16!("Type of Electrum Mnemonic"));
    let mnemonic_version = loop {
        mnemonic_version_selection_label.write_to(&console);
        match mnemonic_version_list.prompt_for_selection(system_services) {
            Some((v, _, _)) => break *v,
            None => {
                // User cancelled; do we want to exit mnemonic generation?
                if ConsoleUiConfirmationPrompt::from(system_services)
                    .prompt_for_confirmation(s16!("Cancel Electrum Mnemonic Generation?"))
                {
                    return Err(None);
                }
            }
        }
    };

    // We've selected a mnemonic version, so generate the mnemonic.
    match try_generate_electrum_mnemonic(bytes, mnemonic_length, mnemonic_version) {
        Ok((m, i)) => {
            if i > 0 {
                // We had to increment the entropy, so extracted entropy will be input + i.
                console
                    .line_start()
                    .new_line()
                    .in_colours(constants::WARNING_COLOURS, |c| {
                        c.output_utf16(s16!(
                            "Mnemonic generation required incrementing entropy by "
                        ))
                        .output_utf32(&format!("{}\0", i))
                        .output_utf16_line(s16!("."))
                    });
            }

            // Return the mnemonic.
            Ok(m)
        }

        // Return the error message we got when generating the mnemonic.
        Err(e) => Err(Some(e)),
    }
}

fn mnemonic_parser(words: &Vec<String16<'static>>) -> ElectrumMnemonicParsingResult<'static> {
    try_parse_electrum_mnemonic(&words)
}

impl<'a> ConsoleWriteable for ElectrumMnemonicParsingResult<'a> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        match self {
            ElectrumMnemonicParsingResult::InvalidLength => console
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16(s16!("Invalid Length"))
                }),
            ElectrumMnemonicParsingResult::InvalidWordEncountered(_, w, _) => console
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16(s16!("Invalid word: ")).output_utf16(*w)
                }),
            ElectrumMnemonicParsingResult::OldFormat(length, _) => {
                console.in_colours(constants::WARNING_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic is old Electrum mnemonic format."))
                })
            }
            ElectrumMnemonicParsingResult::InvalidVersion(length, _, version_bytes) => console
                .in_colours(constants::WARNING_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic has invalid version bytes: "))
                        .output_utf32(&format!("{:?}\0", version_bytes))
                        .output_utf16(s16!("."))
                }),
            ElectrumMnemonicParsingResult::Bip39(length, _, version) => {
                console.in_colours(constants::WARNING_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic with version: '"))
                        .output_utf16((*version).into())
                        .output_utf16(s16!("' is a BIP 39 mnemonic."))
                })
            }
            ElectrumMnemonicParsingResult::Valid(length, _, version) => {
                console.in_colours(constants::SUCCESS_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic with version: '"))
                        .output_utf16((*version).into())
                        .output_utf16(s16!("'."))
                })
            }
        };
    }
}

impl<'a> MnemonicByteParseResult for ElectrumMnemonicParsingResult<'a> {
    fn get_bytes(self) -> Option<Box<[u8]>> {
        match self {
            ElectrumMnemonicParsingResult::InvalidVersion(_, bytes, _) => Some(bytes),
            ElectrumMnemonicParsingResult::OldFormat(_, bytes) => Some(bytes),
            ElectrumMnemonicParsingResult::Bip39(_, bytes, _) => Some(bytes),
            ElectrumMnemonicParsingResult::Valid(_, bytes, _) => Some(bytes),
            _ => None,
        }
    }

    fn can_get_bytes(&self) -> bool {
        match self {
            ElectrumMnemonicParsingResult::InvalidVersion(..) => true,
            ElectrumMnemonicParsingResult::OldFormat(..) => true,
            ElectrumMnemonicParsingResult::Bip39(..) => true,
            ElectrumMnemonicParsingResult::Valid(..) => true,
            _ => false,
        }
    }
}

impl ConsoleWriteable for ElectrumMnemonicLength {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console
            .output_utf16((*self).into())
            .output_utf16(s16!(" ("))
            .output_utf32(&format!(
                "{}\0",
                required_bits_of_entropy_for_mnemonic_length(*self)
            ))
            .output_utf16(s16!(" bits)"));
    }
}
