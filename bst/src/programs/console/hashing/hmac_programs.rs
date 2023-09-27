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

use super::write_hash;
use crate::{
    clipboard::ClipboardEntry,
    console_out::ConsoleOut,
    constants,
    hashing::{Hasher, Sha256, Sha512, RIPEMD160},
    programs::{
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program, ProgramExitResult,
    },
    system_services::SystemServices,
    ui::console::{
        prompt_for_bytes_from_any_data_type, prompt_for_clipboard_write, ConsoleUiTitle,
        ConsoleWriteable,
    },
    String16,
};
use alloc::{format, sync::Arc};
use core::marker::PhantomData;
use macros::s16;

struct HmacProgram<
    const HASH_SIZE: usize,
    const BLOCK_SIZE: usize,
    THasher: Hasher<HASH_SIZE, BLOCK_SIZE>,
    TSystemServices: SystemServices,
> {
    clipboard_entry_name: String16<'static>,
    phantom_hasher: PhantomData<THasher>,
    system_services: TSystemServices,
}

impl<
        const HASH_SIZE: usize,
        const BLOCK_SIZE: usize,
        THasher: Hasher<HASH_SIZE, BLOCK_SIZE>,
        TSystemServices: SystemServices,
    > HmacProgram<HASH_SIZE, BLOCK_SIZE, THasher, TSystemServices>
{
    const fn from(
        clipboard_entry_name: String16<'static>,
        system_services: TSystemServices,
    ) -> Self {
        Self {
            phantom_hasher: PhantomData,
            clipboard_entry_name,
            system_services,
        }
    }
}

impl<
        const HASH_SIZE: usize,
        const BLOCK_SIZE: usize,
        THasher: Hasher<HASH_SIZE, BLOCK_SIZE>,
        TSystemServices: SystemServices,
    > Program for HmacProgram<HASH_SIZE, BLOCK_SIZE, THasher, TSystemServices>
{
    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16(s16!(
                "This program performs HMAC on a key and message using the "
            ))
            .output_utf16(THasher::algorithm_name())
            .output_utf16(s16!(" algorithm, producing a "))
            .output_utf32(&format!("{}\0", HASH_SIZE))
            .output_utf16(s16!(" byte ("))
            .output_utf32(&format!("{}\0", HASH_SIZE * 8))
            .output_utf16_line(s16!(" bit) hash."));

        const CANCEL_PROMPT_STRING: String16<'static> = s16!("Exit HMAC program?");
        let key_bytes = match prompt_for_bytes_from_any_data_type(
            &self.system_services,
            CANCEL_PROMPT_STRING,
            s16!("HMAC Key"),
        ) {
            Err(e) => return e,
            Ok(b) => b,
        };

        let message_bytes = match prompt_for_bytes_from_any_data_type(
            &self.system_services,
            CANCEL_PROMPT_STRING,
            s16!("HMAC Message"),
        ) {
            Err(e) => return e,
            Ok(b) => b,
        };

        let hash = THasher::new()
            .build_hmac(&key_bytes)
            .get_hmac(&message_bytes);
        write_hash(&self.system_services, &hash);
        prompt_for_clipboard_write(
            &self.system_services,
            ClipboardEntry::Bytes(self.clipboard_entry_name, hash[..].into()),
        );

        ProgramExitResult::Success
    }

    fn name(&self) -> String16<'static> {
        THasher::algorithm_name()
    }
}

pub fn get_hmac_programs_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector,
    TProgramExitResultHandler: ProgramExitResultHandler,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 3] = [
        Arc::from(HmacProgram::<20, 64, RIPEMD160, TSystemServices>::from(
            s16!("RIPEMD160 HMAC Hash"),
            system_services.clone(),
        )),
        Arc::from(HmacProgram::<32, 64, Sha256, TSystemServices>::from(
            s16!("SHA256 HMAC Hash"),
            system_services.clone(),
        )),
        Arc::from(HmacProgram::<64, 128, Sha512, TSystemServices>::from(
            s16!("SHA512 HMAC Hash"),
            system_services.clone(),
        )),
    ];

    ProgramList::from(Arc::from(programs), s16!("HMAC Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}
