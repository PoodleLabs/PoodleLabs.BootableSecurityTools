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
    text_box::PasteResult, ConsoleUiLabel, ConsoleUiList, ConsoleUiListStyles, ConsoleUiTextBox,
    ConsoleUiTextBoxStyles, ConsoleUiTitle, ConsoleUiTitleStyles, ConsoleWriteable,
};
use crate::{
    clipboard::ClipboardEntry,
    integers::{
        NumericBaseWithCharacterPredicate, NumericBases, NumericCollector,
        NumericCollectorRoundBase,
    },
    system_services::SystemServices,
    String16,
};
use macros::s16;

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsoleUiNumericInputStyles {
    numeric_base_selection_title_styles: ConsoleUiTitleStyles,
    numeric_base_selection_list_styles: ConsoleUiListStyles,
    text_input_styles: ConsoleUiTextBoxStyles,
}

#[allow(dead_code)]
impl ConsoleUiNumericInputStyles {
    pub const fn from(
        numeric_base_selection_title_styles: ConsoleUiTitleStyles,
        numeric_base_selection_list_styles: ConsoleUiListStyles,
        text_input_styles: ConsoleUiTextBoxStyles,
    ) -> Self {
        Self {
            numeric_base_selection_title_styles,
            numeric_base_selection_list_styles,
            text_input_styles,
        }
    }

    pub const fn with_numeric_base_selection_title_styles(
        self,
        numeric_base_selection_title_styles: ConsoleUiTitleStyles,
    ) -> Self {
        Self::from(
            numeric_base_selection_title_styles,
            self.numeric_base_selection_list_styles,
            self.text_input_styles,
        )
    }

    pub const fn with_numeric_base_selection_list_styles(
        self,
        numeric_base_selection_list_styles: ConsoleUiListStyles,
    ) -> Self {
        Self::from(
            self.numeric_base_selection_title_styles,
            numeric_base_selection_list_styles,
            self.text_input_styles,
        )
    }

    pub const fn with_text_input_styles(self, text_input_styles: ConsoleUiTextBoxStyles) -> Self {
        Self::from(
            self.numeric_base_selection_title_styles,
            self.numeric_base_selection_list_styles,
            text_input_styles,
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ConsoleUiNumericInput<'a, TSystemServices: SystemServices> {
    system_services: &'a TSystemServices,
    styles: ConsoleUiNumericInputStyles,
}

impl<'a, TSystemServices: SystemServices> ConsoleUiNumericInput<'a, TSystemServices> {
    pub const fn from(
        system_services: &'a TSystemServices,
        styles: ConsoleUiNumericInputStyles,
    ) -> Self {
        Self {
            system_services,
            styles,
        }
    }

    pub fn get_numeric_input(
        &self,
        input_width: usize,
        label: String16<'static>,
        base: Option<NumericBaseWithCharacterPredicate>,
    ) -> Option<NumericCollector> {
        let base = match base {
            // We've specified a base; we don't need to ask the user to select one.
            Some(base) => base,
            None => {
                // We didn't have a pre-defined base, so ask the user to select one.
                ConsoleUiLabel::from(label).write_to(&self.system_services.get_console_out());
                match ConsoleUiList::<'a, NumericBases, &[NumericBases]>::from(
                    ConsoleUiTitle::from(
                        s16!(" Input Base "),
                        self.styles.numeric_base_selection_title_styles,
                    ),
                    self.styles.numeric_base_selection_list_styles,
                    &NumericBases::BASES,
                )
                .prompt_for_selection(self.system_services)
                {
                    Some((base, _, _)) => Into::<NumericBaseWithCharacterPredicate>::into(*base),
                    None => return None,
                }
            }
        };

        // Get text input from the user.
        let text_input =
            ConsoleUiTextBox::from(self.system_services, self.styles.text_input_styles)
                .get_text_input(
                    input_width,
                    |clipboard_entry, scroll_text, _| match clipboard_entry {
                        // Handle a byte paste.
                        ClipboardEntry::Bytes(_, b) => {
                            // Write the bytes in the same base as the numeric input.
                            for character in base.base().build_string_from_bytes(&b, false) {
                                scroll_text.insert_character(character);
                            }

                            // No fancy UI needed, no redraw needed.
                            PasteResult::ContinueAsNormal
                        }
                        // We can't write text to a numeric input, so any other paste types just get ignored.
                        _ => PasteResult::ContinueAsNormal,
                    },
                    label,
                    base.base().small_title(),
                    // Disallow input of non-base and non-whitespace characters.
                    Some(base.whitespace_allowed_character_predicate()),
                );

        if text_input.len() == 0 {
            // User didn't input anything; return none.
            None
        } else {
            // User wrote input. Start collecting the numeric content.
            let base = base.base();
            let mut numeric_collector = NumericCollector::new();
            for character in text_input {
                match base.value_from(character) {
                    Some(value) => {
                        // The character is associated with a numeric value; collect it.
                        _ = numeric_collector
                            .try_add_round(value, NumericCollectorRoundBase::SubByte(base.base()));
                    }
                    None => { /* The character is not associated with a numeric value; skip it. */ }
                };
            }

            // Return the numeric collector.
            Some(numeric_collector)
        }
    }
}
