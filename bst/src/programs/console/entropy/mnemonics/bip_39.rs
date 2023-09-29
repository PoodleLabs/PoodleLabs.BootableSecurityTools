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
    bitcoin::mnemonics::{bip_39, MnemonicFormat},
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
use alloc::{format, sync::Arc, vec::Vec};
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
            system_services.clone(),
            Encoder,
            s16!("BIP 39 Entropy Encoder"),
        )),
        Arc::from(ConsoleMnemonicEntropyDecoder::from(
            s16!("BIP 39 Mnemonic Bytes"),
            bip_39::MnemonicParser,
            system_services.clone(),
            s16!("BIP 39 Entropy Decoder"),
        )),
        Arc::from(ConsoleMnemonicBip39SeedDeriver::from(
            system_services.clone(),
            bip_39::MnemonicParser,
            s16!("BIP 39 Mnemonic To BIP 32 Seed"),
        )),
    ];

    ProgramList::from(Arc::from(programs), s16!("BIP 39 Mnemonic Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

struct Encoder;

impl MnemonicEncoder for Encoder {
    type TMnemonicLength = bip_39::MnemonicLength;

    fn mnemnonic_format(&self) -> MnemonicFormat<Self::TMnemonicLength> {
        bip_39::MNEMONIC_FORMAT
    }

    fn try_encode<TSystemServices: SystemServices>(
        &self,
        bytes: &[u8],
        _system_services: &TSystemServices,
        mnemonic_length: Self::TMnemonicLength,
    ) -> Result<Vec<String16<'static>>, Option<String16<'static>>> {
        match bip_39::try_generate_mnemonic(mnemonic_length, bytes) {
            Some(m) => Ok(m),
            // We should never expect this to get hit.
            None => Err(Some(s16!(
                "An unknown error occurred while generating the mnemonic."
            ))),
        }
    }
}

impl ConsoleWriteable for bip_39::MnemonicLength {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        super::write_mnemonic_length_to(
            (*self).into(),
            bip_39::required_bits_of_entropy_for_mnemonic_length(*self),
            console,
        );
    }
}

impl<'a> ConsoleWriteable for bip_39::MnemonicParsingResult<'a> {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        match self {
            bip_39::MnemonicParsingResult::InvalidLength => console
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16(s16!("Invalid Length"))
                }),
            bip_39::MnemonicParsingResult::InvalidWordEncountered(_, w, _) => console
                .in_colours(constants::ERROR_COLOURS, |c| {
                    c.output_utf16(s16!("Invalid word: ")).output_utf16(*w)
                }),
            bip_39::MnemonicParsingResult::InvalidChecksum(
                length,
                _,
                checksum,
                expected_checksum,
            ) => console.in_colours(constants::WARNING_COLOURS, |c| {
                c.output_utf16((*length).into())
                    .output_utf16(s16!(" Mnemonic failed checksum; expected "))
                    .output_utf32(&format!("{}, got {}.\0", expected_checksum, checksum))
            }),
            bip_39::MnemonicParsingResult::Valid(length, _, checksum) => {
                console.in_colours(constants::SUCCESS_COLOURS, |c| {
                    c.output_utf16((*length).into())
                        .output_utf16(s16!(" Mnemonic passed checksum of "))
                        .output_utf32(&format!("{}.\0", checksum))
                })
            }
        };
    }
}
