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
    programs::{
        console::{cryptography::asymmetric::prompt_for_curve_selection, write_bytes},
        Program, ProgramExitResult,
    },
    system_services::SystemServices,
    ui::{
        console::{
            prompt_for_clipboard_write, prompt_for_data_input, ConsoleUiContinuePrompt,
            ConsoleUiTitle, ConsoleWriteable,
        },
        ContinuePrompt, DataInput, DataInputType,
    },
    String16,
};
use core::cmp::Ordering;
use macros::s16;

pub struct ConsoleEllipticCurvePublicKeyDerivationProgram<TSystemServices: SystemServices> {
    system_services: TSystemServices,
}

impl<TSystemServices: SystemServices>
    ConsoleEllipticCurvePublicKeyDerivationProgram<TSystemServices>
{
    pub const fn from(system_services: TSystemServices) -> Self {
        Self { system_services }
    }
}

impl<TSystemServices: SystemServices> Program
    for ConsoleEllipticCurvePublicKeyDerivationProgram<TSystemServices>
{
    fn name(&self) -> String16<'static> {
        s16!("Elliptic Curve Public Key Derivation")
    }

    fn run(&self) -> ProgramExitResult {
        let console = self.system_services.get_console_out();
        console.clear();

        ConsoleUiTitle::from(self.name(), constants::BIG_TITLE).write_to(&console);
        console
            .output_utf16_line(s16!("This program derives a public key from a private key using Elliptic Curve cryptography."));
        const CANCEL_PROMPT: String16 = s16!("Cancel public key derivation?");

        // Select a curve.
        let mut curve = match prompt_for_curve_selection(&self.system_services, CANCEL_PROMPT) {
            None => return ProgramExitResult::UserCancelled,
            Some(c) => c,
        };

        // Get the private key to derive a public key from.
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
                        // Private keys must be less than the N value of the curve. We'll ask the user what to do.
                        console.in_colours(constants::ERROR_COLOURS, |c| {
                            c.line_start().new_line()
                                .output_utf16_line(s16!(
                                    "The input is >= the curve's N value; we cannot derive a public key from it directly."))
                                .output_utf16_line(s16!("You may wish to use the private key fitter program."))
                        });

                        b.zero();
                        continue;
                    }

                    // The key was not zero, and not oversized; we can use it.
                    break b;
                }
                _ => return ProgramExitResult::UserCancelled,
            };
        };

        console.in_colours(constants::SUCCESS_COLOURS, |c| {
            c.line_start()
                .new_line()
                .output_utf16(s16!("Deriving public key..."))
        });

        let point =
            match curve
                .multiplication_context
                .multiply_point(curve.g_x, curve.g_y, &private_key)
            {
                Some(point) => point,
                None => {
                    console.in_colours(constants::ERROR_COLOURS, |c| {
                        c.line_start().new_line().output_utf16(s16!(
                            "Failed to derive a public key; this shouldn't have happened."
                        ))
                    });

                    ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
                    return ProgramExitResult::String16Error(
                        s16!("Public key derivation failure.")
                            .content_slice()
                            .into(),
                    );
                }
            };

        // We're done with the private key; zero it.
        private_key.zero();

        // Serialize the public key for output.
        let serialized_point = match (curve.point_serializer)(point) {
            Some(serialized_point) => serialized_point,
            None => {
                console.in_colours(constants::ERROR_COLOURS, |c| {
                    c.line_start().new_line().output_utf16(s16!(
                        "Failed to serialize the public key; this shouldn't have happened."
                    ))
                });

                ConsoleUiContinuePrompt::from(&self.system_services).prompt_for_continue();
                return ProgramExitResult::String16Error(
                    s16!("Public key serialization failure.")
                        .content_slice()
                        .into(),
                );
            }
        };

        write_bytes(&self.system_services, s16!("Public Key"), &serialized_point);
        prompt_for_clipboard_write(
            &self.system_services,
            crate::clipboard::ClipboardEntry::Bytes(
                curve.public_key_clipboard_name,
                serialized_point,
            ),
        );

        ProgramExitResult::Success
    }
}
