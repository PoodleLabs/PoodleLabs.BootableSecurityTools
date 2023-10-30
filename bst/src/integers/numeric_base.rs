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

use super::BigUnsigned;
use crate::{
    characters::Character, console_out::ConsoleOut, ui::console::ConsoleWriteable, String16,
};
use alloc::vec::Vec;
use macros::{s16, u16_array};

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum NumericBases {
    Binary,
    Octal,
    Decimal,
    Hexadecimal,
    Base32,
    Base58,
    Base64,
    Base64Uri,
}

impl NumericBases {
    pub const BASES: [NumericBases; 8] = [
        NumericBases::Binary,
        NumericBases::Octal,
        NumericBases::Decimal,
        NumericBases::Hexadecimal,
        NumericBases::Base32,
        NumericBases::Base58,
        NumericBases::Base64,
        NumericBases::Base64Uri,
    ];
}

impl Into<&NumericBase> for NumericBases {
    fn into(self) -> &'static NumericBase {
        match self {
            NumericBases::Binary => &NumericBase::BASE_2,
            NumericBases::Octal => &NumericBase::BASE_8,
            NumericBases::Decimal => &NumericBase::BASE_10,
            NumericBases::Hexadecimal => &NumericBase::BASE_16,
            NumericBases::Base32 => &NumericBase::BASE_32,
            NumericBases::Base58 => &NumericBase::BASE_58,
            NumericBases::Base64 => &NumericBase::BASE_64,
            NumericBases::Base64Uri => &NumericBase::BASE_64_URI,
        }
    }
}

impl From<&NumericBase> for NumericBases {
    fn from(value: &NumericBase) -> Self {
        value.enum_value
    }
}

macro_rules! base_and_predicate {
    ($($name:ident)*) => {
        $(
            NumericBaseWithCharacterPredicate::from(
                // We ignore whitespace when we're inputting an integer. It makes writing big integers nicer.
                |c| c.is_whitespace() || NumericBase::$name.value_from(c).is_some(),
                &NumericBase::$name,
            )
        )*
    };
}

impl Into<NumericBaseWithCharacterPredicate> for NumericBases {
    fn into(self) -> NumericBaseWithCharacterPredicate {
        match self {
            NumericBases::Binary => base_and_predicate!(BASE_2),
            NumericBases::Octal => base_and_predicate!(BASE_8),
            NumericBases::Decimal => base_and_predicate!(BASE_10),
            NumericBases::Hexadecimal => base_and_predicate!(BASE_16),
            NumericBases::Base32 => base_and_predicate!(BASE_32),
            NumericBases::Base58 => base_and_predicate!(BASE_58),
            NumericBases::Base64 => base_and_predicate!(BASE_64),
            NumericBases::Base64Uri => base_and_predicate!(BASE_64_URI),
        }
    }
}

impl From<NumericBaseWithCharacterPredicate> for NumericBases {
    fn from(value: NumericBaseWithCharacterPredicate) -> Self {
        value.base.enum_value
    }
}

impl ConsoleWriteable for NumericBases {
    fn write_to<T: ConsoleOut>(&self, console: &T) {
        console.output_utf16(Into::<&NumericBase>::into(*self).name);
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct NumericBaseWithCharacterPredicate {
    whitespace_allowed_character_predicate: fn(character: u16) -> bool,
    base: &'static NumericBase,
}

impl NumericBaseWithCharacterPredicate {
    const fn from(
        whitespace_allowed_character_predicate: fn(character: u16) -> bool,
        base: &'static NumericBase,
    ) -> Self {
        Self {
            whitespace_allowed_character_predicate,
            base,
        }
    }

    pub const fn whitespace_allowed_character_predicate(&self) -> fn(character: u16) -> bool {
        self.whitespace_allowed_character_predicate
    }

    pub const fn base(&self) -> &NumericBase {
        self.base
    }
}

#[derive(PartialEq)]
pub struct NumericBase {
    // We can 'ignore' case.
    alternate_characters: Option<&'static [u16]>,
    // The small title styling is currently a little bit hacky; we want spaces on either side of the base name.
    small_title: String16<'static>,
    // The characters in our base, in order. Index 0 is our 0 character. That's usually, but not always, '0'.
    characters: &'static [u16],
    enum_value: NumericBases,
    name: String16<'static>,
    digits_per_byte: f64,
    base: u8,
}

impl NumericBase {
    pub const BASE_2: Self = Self::build(
        None,
        s16!(" Binary "),
        &u16_array!("01"),
        NumericBases::Binary,
        s16!("Binary"),
        8f64,
        2,
    );

    pub const BASE_8: Self = Self::build(
        None,
        s16!(" Octal "),
        &u16_array!("01234567"),
        NumericBases::Octal,
        s16!("Octal"),
        8f64 / 3f64,
        8,
    );

    pub const BASE_10: Self = Self::build(
        None,
        s16!(" Decimal "),
        &u16_array!("0123456789"),
        NumericBases::Decimal,
        s16!("Decimal"),
        2.4082399653118495617,
        10,
    );

    pub const BASE_16: Self = Self::build(
        Some(&u16_array!("0123456789ABCDEF")),
        s16!(" Hexadecimal "),
        &u16_array!("0123456789abcdef"),
        NumericBases::Hexadecimal,
        s16!("Hexadecimal"),
        2f64,
        16,
    );

    pub const BASE_32: Self = Self::build(
        Some(&u16_array!("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")),
        s16!(" Base-32 "),
        &u16_array!("abcdefghijklmnopqrstuvwxyz234567"),
        NumericBases::Base32,
        s16!("Base-32"),
        1.6,
        32,
    );

    pub const BASE_58: Self = Self::build(
        None,
        s16!(" Base-58 "),
        &u16_array!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
        NumericBases::Base58,
        s16!("Base-58"),
        1.365658237309761,
        58,
    );

    pub const BASE_64: Self = Self::build(
        None,
        s16!(" Base-64 "),
        &u16_array!("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
        NumericBases::Base64,
        s16!("Base-64"),
        4f64 / 3f64,
        64,
    );

    pub const BASE_64_URI: Self = Self::build(
        None,
        s16!(" Base-64 URI "),
        &u16_array!("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
        NumericBases::Base64Uri,
        s16!("Base-64 URI"),
        4f64 / 3f64,
        64,
    );

    const fn build(
        alternate_characters: Option<&'static [u16]>,
        small_title: String16<'static>,
        characters: &'static [u16],
        enum_value: NumericBases,
        name: String16<'static>,
        digits_per_byte: f64,
        base: u8,
    ) -> Self {
        Self {
            alternate_characters,
            digits_per_byte,
            small_title,
            characters,
            enum_value,
            name,
            base,
        }
    }

    pub const fn small_title(&self) -> String16<'static> {
        self.small_title
    }

    pub const fn base(&self) -> u8 {
        self.base
    }

    pub fn value_from(&self, character: u16) -> Option<u8> {
        match Self::value_from_character_set(character, self.characters) {
            // The character is in the core character set for this numeric base.
            Some(v) => Some(v),
            // The character is not in the core character set for this numeric base.
            None => match self.alternate_characters {
                // There is an alternate character set; check that.
                Some(alt) => Self::value_from_character_set(character, alt),
                // There's no alternate character set; the character doesn't correspond to a numeric value.
                None => None,
            },
        }
    }

    pub fn build_string_from_big_unsigned(
        &self,
        unsigned_integer: &mut BigUnsigned,
        null_terminate: bool,
        pad_to_length: usize,
    ) -> Vec<u16> {
        let mut remainder = 0u8;
        let mut vec = Vec::new();
        // Pop the next digit off the unsigned integer.
        while unsigned_integer.is_non_zero() {
            assert!(unsigned_integer.divide_u8_with_remainder(self.base, &mut remainder));
            // We're working from right to left, so we insert at 0.
            vec.insert(0, self.characters[remainder as usize]);
        }

        // Pad to the specified length.
        while vec.len() < pad_to_length {
            vec.insert(0, self.characters[0])
        }

        // Add a trailing null terminator if requested.
        if null_terminate {
            vec.push(0);
        }

        vec
    }

    pub fn build_string_from_bytes(&self, bytes: &[u8], null_terminate: bool) -> Vec<u16> {
        // For bytes, we want our leading zeroes.
        self.build_string_from_big_unsigned(
            &mut BigUnsigned::from_be_bytes(bytes),
            null_terminate,
            (bytes.len() as f64 * self.digits_per_byte) as usize,
        )
    }

    fn value_from_character_set(character: u16, character_set: &[u16]) -> Option<u8> {
        match character_set.iter().position(|c| *c == character) {
            // The character was found in the character set; return the index it was found at.
            Some(v) => Some(v as u8),
            None => None,
        }
    }
}
