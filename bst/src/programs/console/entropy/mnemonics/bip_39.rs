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
    mnemonic_bip_32_seed_deriver::{ConsoleMnemonicBip39SeedDeriver, MnemonicSeedDeriveResult},
    mnemonic_entropy_decoder::{ConsoleMnemonicEntropyDecoder, MnemonicByteParseResult},
    mnemonic_entropy_encoder::ConsoleMnemonicEntropyEncoder,
};
use crate::{
    bitcoin::mnemonics::bip_39::{
        self, required_bits_of_entropy_for_mnemonic_length, try_generate_bip_39_mnemonic,
        try_parse_bip39_mnemonic, Bip39MnemonicLength, Bip39MnemonicParsingResult,
    },
    console_out::ConsoleOut,
    constants,
    programs::{
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program,
    },
    system_services::SystemServices,
    ui::console::ConsoleWriteable,
    String16,
};
use alloc::{boxed::Box, format, sync::Arc, vec::Vec};
use macros::s16;

pub fn get_bip_39_mnemonic_program_list<
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
            bip_39::get_available_mnemonic_lengths,
            s16!("BIP 39"),
            &bip_39::WORD_LIST,
            s16!("16"),
            s16!("BIP 39"),
            system_services.clone(),
            mnemonic_encoder,
            s16!("BIP 39 Entropy Encoder"),
        )),
        Arc::from(ConsoleMnemonicEntropyDecoder::from(
            s16!("BIP 39 Mnemonic Bytes"),
            s16!("BIP 39"),
            &bip_39::WORD_LIST,
            s16!("BIP 39"),
            system_services.clone(),
            mnemonic_parser,
            bip_39::LONGEST_WORD_LENGTH as usize,
            s16!("BIP 39 Entropy Decoder"),
            bip_39::MAX_WORD_COUNT,
        )),
        Arc::from(ConsoleMnemonicBip39SeedDeriver::from(
            bip_39::NORMALIZATION_SETTINGS,
            bip_39::MNEMONIC_WORD_SPACING,
            s16!("BIP 39"),
            &bip_39::WORD_LIST,
            s16!("BIP 39"),
            system_services.clone(),
            mnemonic_parser,
            bip_39::EXTENSION_PREFIX,
            bip_39::LONGEST_WORD_LENGTH as usize,
            s16!("BIP 39 Mnemonic To BIP 32 Seed"),
            bip_39::SEED_DERIVATION_PBKDF_ITERATIONS,
            bip_39::MAX_WORD_COUNT,
        )),
    ];

    ProgramList::from(Arc::from(programs), s16!("BIP 39 Mnemonic Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

fn mnemonic_encoder<TSystemServices: SystemServices>(
    _system_services: &TSystemServices,
    mnemonic_length: Bip39MnemonicLength,
    bytes: &[u8],
) -> Result<Vec<String16<'static>>, Option<String16<'static>>> {
    match try_generate_bip_39_mnemonic(mnemonic_length, bytes) {
        Some(m) => Ok(m),
        // We should ever expect this to get hit.
        None => Err(Some(s16!(
            "An unknown error occurred while generating the mnemonic."
        ))),
    }
}

fn mnemonic_parser(words: &Vec<String16<'static>>) -> Bip39MnemonicParsingResult<'static> {
    try_parse_bip39_mnemonic(&words)
}

impl<'a> ConsoleWriteable for Bip39MnemonicParsingResult<'a> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        match self {
            Bip39MnemonicParsingResult::InvalidLength => console
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16(s16!("Invalid Length"))
                }),
            Bip39MnemonicParsingResult::InvalidWordEncountered(_, w, _) => console
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16(s16!("Invalid word: ")).output_utf16(*w)
                }),
            Bip39MnemonicParsingResult::InvalidChecksum(length, _, checksum, expected_checksum) => {
                console.in_colours(constants::WARNING_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic failed checksum; expected "))
                        .output_utf32(&format!("{}, got {}.\0", expected_checksum, checksum))
                })
            }
            Bip39MnemonicParsingResult::Valid(length, _, checksum) => {
                console.in_colours(constants::SUCCESS_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic passed checksum of "))
                        .output_utf32(&format!("{}.\0", checksum))
                })
            }
        };
    }
}

impl<'a> MnemonicByteParseResult for Bip39MnemonicParsingResult<'a> {
    fn get_bytes(self) -> Option<Box<[u8]>> {
        match self {
            Bip39MnemonicParsingResult::InvalidChecksum(_, bytes, _, _) => Some(bytes),
            Bip39MnemonicParsingResult::Valid(_, bytes, _) => Some(bytes),
            _ => None,
        }
    }

    fn can_get_bytes(&self) -> bool {
        match self {
            Bip39MnemonicParsingResult::InvalidChecksum(..) => true,
            Bip39MnemonicParsingResult::Valid(..) => true,
            _ => false,
        }
    }
}

impl<'a> MnemonicSeedDeriveResult for Bip39MnemonicParsingResult<'a> {
    fn can_derive_seed(&self) -> bool {
        match self {
            Bip39MnemonicParsingResult::InvalidChecksum(..) => true,
            Bip39MnemonicParsingResult::Valid(..) => true,
            _ => false,
        }
    }
}

impl ConsoleWriteable for Bip39MnemonicLength {
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
