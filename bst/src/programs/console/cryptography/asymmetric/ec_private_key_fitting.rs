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
    hashing::{Hasher, Sha512},
    integers::BigUnsigned,
    programs::{
        console::{cryptography::asymmetric::prompt_for_curve_selection, write_bytes},
        Program, ProgramExitResult,
    },
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_clipboard_write, prompt_for_data_input, ConsoleUiTitle, ConsoleWriteable,
        },
        DataInput, DataInputType,
    },
    String16,
};
use alloc::vec;
use core::cmp::Ordering;
use macros::s16;

const ITERATIVE_HASHING_KEY: &[u8] = "Extremely Large Numer Private Key".as_bytes();

pub struct ConsoleEllipticCurvePrivateKeyFittingProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices>
    ConsoleEllipticCurvePrivateKeyFittingProgram<TSystemServices>
{
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program
    for ConsoleEllipticCurvePrivateKeyFittingProgram<TSystemServices>
{
    fn name(&self) -> String16<'static> {
        s16!("Elliptic Curve Private Key Fitter")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!("This program fits private keys >= N to an elliptic curve's valid keyspace via iterative hashing."));
        const CANCEL_PROMPT: String16 = s16!("Cancel private key fitting?");

        // Select a curve.
        let curve = match prompt_for_curve_selection(&self.system_services, CANCEL_PROMPT) {
            None => return ProgramExitResult::UserCancelled,
            Some(c) => c,
        };

        // Get the data to fit into a private key.
        let mut private_key = loop {
            match prompt_for_data_input(
                None,
                &[DataInputType::Number],
                &self.system_services,
                CANCEL_PROMPT,
                s16!("Private Key"),
            ) {
                DataInput::Number(mut b) => {
                    if b.is_zero() {
                        // Zero is an invalid private key.
                        console.in_colours(constants::ERROR_COLOURS, |c| {
                            c.line_start()
                                .new_line()
                                .output_utf16(s16!("Zero is not a valid private key."))
                        });

                        continue;
                    } else if b.cmp(curve.n) != Ordering::Less {
                        // The key is >= N; we need to hash it to fit.
                        console.in_colours(constants::WARNING_COLOURS, |c| {
                            c.line_start()
                                .new_line()
                                .output_utf16(s16!("Private key >= N; fitting it now..."))
                        });

                        let mut hasher = Sha512::new();
                        let mut hash_buffer = vec![0u8; Sha512::HASH_SIZE];
                        let mut hmac = hasher.build_hmac(ITERATIVE_HASHING_KEY);
                        break loop {
                            hmac.write_hmac_to(&b.borrow_digits(), &mut hash_buffer);
                            // Take the first X bytes where X is the private key length for the curve.
                            hash_buffer.truncate(curve.key_length);

                            // Give the hash buffer to a BigUnsigned; we'll compare and, if it's a valid private key, use it.
                            let integer = BigUnsigned::from_vec(hash_buffer);
                            if integer.is_non_zero() && integer.cmp(curve.n) == Ordering::Less {
                                // Zero out the original integer, reset the hasher, and exit the loop with our new value.
                                b.zero();
                                hasher.reset();
                                break integer;
                            }

                            // Increment the oversized private key.
                            b.add_be_bytes(&[1]);

                            // Take back ownership of the hash buffer.
                            hash_buffer = integer.extract_be_bytes();

                            // Reset the hash buffer to the correct length.
                            hash_buffer.truncate(0);
                            hash_buffer.extend((0..Sha512::HASH_SIZE).into_iter().map(|_| 0))
                        };
                    }

                    // The key was not zero, and not oversized; we can use it as-is.
                    console.in_colours(constants::SUCCESS_COLOURS, |c| {
                        c.line_start()
                            .new_line()
                            .output_utf16(s16!("Private key < N; no fitting required.."))
                    });

                    break b;
                }
                _ => return ProgramExitResult::UserCancelled,
            };
        };

        write_bytes(
            &self.system_services,
            s16!("Private Key"),
            private_key.borrow_digits(),
        );

        prompt_for_clipboard_write(
            &self.system_services,
            crate::clipboard::ClipboardEntry::Bytes(
                curve.private_key_clipboard_name,
                private_key.borrow_digits().into(),
            ),
        );

        private_key.zero();
        ProgramExitResult::Success
    }
}
