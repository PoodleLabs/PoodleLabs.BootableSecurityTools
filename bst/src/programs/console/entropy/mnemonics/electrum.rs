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
    mnemonic_bip_32_seed_deriver::ConsoleMnemonicBip39SeedDeriver,
    mnemonic_entropy_decoder::ConsoleMnemonicEntropyDecoder,
    mnemonic_entropy_encoder::{ConsoleMnemonicEntropyEncoder, MnemonicEncoder},
};
use crate::{
    bitcoin::mnemonics::{electrum, MnemonicFormat},
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
use alloc::{format, sync::Arc, vec::Vec};
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
    let programs: [Arc<dyn Program>; 3] = [
        Arc::from(ConsoleMnemonicEntropyEncoder::from(
            system_services.clone(),
            Encoder,
            s16!("Electrum Entropy Encoder (BIP 39 Words)"),
        )),
        Arc::from(ConsoleMnemonicEntropyDecoder::from(
            s16!("Electrum Mnemonic Bytes"),
            electrum::MnemonicParser,
            system_services.clone(),
            s16!("Electrum Entropy Decoder (BIP 39 Words)"),
        )),
        Arc::from(ConsoleMnemonicBip39SeedDeriver::from(
            system_services.clone(),
            electrum::MnemonicParser,
            s16!("Electrum Mnemonic To BIP 32 Seed (BIP 39 Words)"),
        )),
    ];

    ProgramList::from(Arc::from(programs), s16!("Electrum Mnemonic Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

struct Encoder;

impl MnemonicEncoder for Encoder {
    type TMnemonicLength = electrum::MnemonicLength;

    fn mnemnonic_format(&self) -> MnemonicFormat<Self::TMnemonicLength> {
        electrum::MNEMONIC_FORMAT
    }

    fn try_encode<TSystemServices: SystemServices>(
        &self,
        bytes: &[u8],
        system_services: &TSystemServices,
        mnemonic_length: Self::TMnemonicLength,
    ) -> Result<Vec<String16<'static>>, Option<String16<'static>>> {
        // User must select a mnemonic version; allow either Segwit or Legacy.
        let mut mnemonic_version_list = ConsoleUiList::from(
            ConsoleUiTitle::from(s16!(" Mnemonic Version "), constants::SMALL_TITLE),
            constants::SELECT_LIST,
            &[
                electrum::MnemonicVersion::Segwit,
                electrum::MnemonicVersion::Legacy,
            ][..],
        );

        let console = system_services.get_console_out();
        let mnemonic_version_selection_label =
            ConsoleUiLabel::from(s16!("Type of Electrum Mnemonic"));
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
        match electrum::try_generate_mnemonic(bytes, mnemonic_length, mnemonic_version) {
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
}

impl ConsoleWriteable for electrum::MnemonicVersion {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console.output_utf16((*self).into());
    }
}

impl ConsoleWriteable for electrum::MnemonicLength {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        super::write_mnemonic_length_to(
            (*self).into(),
            electrum::required_bits_of_entropy_for_mnemonic_length(*self),
            console,
        );
    }
}

impl<'a> ConsoleWriteable for electrum::MnemonicParsingResult<'a> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        match self {
            electrum::MnemonicParsingResult::InvalidLength => console
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16(s16!("Invalid Length"))
                }),
            electrum::MnemonicParsingResult::InvalidWordEncountered(_, w, _) => console
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16(s16!("Invalid word: ")).output_utf16(*w)
                }),
            electrum::MnemonicParsingResult::OldFormat(length, _) => {
                console.in_colours(constants::WARNING_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic is old Electrum mnemonic format."))
                })
            }
            electrum::MnemonicParsingResult::InvalidVersion(length, _, version_bytes) => console
                .in_colours(constants::WARNING_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic has invalid version bytes: "))
                        .output_utf32(&format!("{:?}\0", version_bytes))
                        .output_utf16(s16!("."))
                }),
            electrum::MnemonicParsingResult::Bip39(length, _, version) => {
                console.in_colours(constants::WARNING_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic with version: '"))
                        .output_utf16((*version).into())
                        .output_utf16(s16!("' is a BIP 39 mnemonic."))
                })
            }
            electrum::MnemonicParsingResult::Valid(length, _, version) => {
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
