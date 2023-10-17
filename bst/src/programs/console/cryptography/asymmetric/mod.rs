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

mod ec_public_key_derivation;

use crate::{
    console_out::ConsoleOut,
    constants,
    cryptography::asymmetric::ecc::{
        secp256k1, EllipticCurvePoint, EllipticCurvePointMultiplicationContext,
    },
    integers::BigUnsigned,
    programs::{
        exit_result_handlers::ProgramExitResultHandler,
        program_lists::{ProgramList, ProgramListProgram, ProgramSelector},
        Program,
    },
    system_services::SystemServices,
    ui::{
        console::{ConsoleUiConfirmationPrompt, ConsoleUiList, ConsoleUiTitle, ConsoleWriteable},
        ConfirmationPrompt,
    },
    String16,
};
use alloc::sync::Arc;
use ec_public_key_derivation::ConsoleEllipticCurvePublicKeyDerivationProgram;
use macros::s16;

pub fn get_asymmetric_cryptography_program_list<
    'a,
    TSystemServices: SystemServices,
    TProgramSelector: ProgramSelector + 'static,
    TProgramExitResultHandler: ProgramExitResultHandler + 'static,
>(
    system_services: &TSystemServices,
    program_selector: &TProgramSelector,
    exit_result_handler: &TProgramExitResultHandler,
) -> ProgramListProgram<TProgramSelector, TProgramExitResultHandler> {
    let programs: [Arc<dyn Program>; 1] = [Arc::from(
        ConsoleEllipticCurvePublicKeyDerivationProgram::from(system_services.clone()),
    )];
    ProgramList::from(Arc::from(programs), s16!("Asymmetric Programs"))
        .as_program(program_selector.clone(), exit_result_handler.clone())
}

struct CurveOption {
    curve_context_builder: fn() -> SelectedCurveContext,
    name: String16<'static>,
}

impl CurveOption {
    const SECP256K1: Self = Self::from(Self::secp256k1_context_builder, s16!("secp256k1"));

    pub const fn from(
        curve_context_builder: fn() -> SelectedCurveContext,
        name: String16<'static>,
    ) -> Self {
        Self {
            curve_context_builder,
            name,
        }
    }

    fn secp256k1_context_builder() -> SelectedCurveContext {
        SelectedCurveContext::from(
            secp256k1::point_multiplication_context(),
            |p| match secp256k1::serialized_public_key_bytes(p) {
                Some(b) => Some(b[..].into()),
                None => None,
            },
            secp256k1::g_x(),
            secp256k1::g_y(),
            secp256k1::n(),
            32,
        )
    }
}

impl ConsoleWriteable for CurveOption {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console.output_utf16(self.name);
    }
}

struct SelectedCurveContext {
    multiplication_context: EllipticCurvePointMultiplicationContext,
    point_serializer: fn(EllipticCurvePoint) -> Option<Arc<[u8]>>,
    g_x: &'static BigUnsigned,
    g_y: &'static BigUnsigned,
    n: &'static BigUnsigned,
    key_length: usize,
}

impl SelectedCurveContext {
    pub const fn from(
        multiplication_context: EllipticCurvePointMultiplicationContext,
        point_serializer: fn(EllipticCurvePoint) -> Option<Arc<[u8]>>,
        g_x: &'static BigUnsigned,
        g_y: &'static BigUnsigned,
        n: &'static BigUnsigned,
        key_length: usize,
    ) -> Self {
        Self {
            multiplication_context,
            point_serializer,
            key_length,
            g_x,
            g_y,
            n,
        }
    }
}

fn prompt_for_curve_selection<TSystemServices: SystemServices>(
    system_services: &TSystemServices,
    cancellation_prompt: String16,
) -> Option<SelectedCurveContext> {
    loop {
        system_services.get_console_out().line_start().new_line();
        match ConsoleUiList::from(
            ConsoleUiTitle::from(s16!("Elliptic Curve"), constants::SMALL_TITLE),
            constants::SELECT_LIST,
            &[CurveOption::SECP256K1][..],
        )
        .prompt_for_selection(system_services)
        {
            Some((c, _, _)) => break Some((c.curve_context_builder)()),
            None => {
                if ConsoleUiConfirmationPrompt::from(system_services)
                    .prompt_for_confirmation(cancellation_prompt)
                {
                    break None;
                }
            }
        }
    }
}
