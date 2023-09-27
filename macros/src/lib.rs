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

#![recursion_limit = "32"]
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Error, LitInt, LitStr};

#[proc_macro]
pub fn s16(input: TokenStream) -> TokenStream {
    let input: LitStr = parse_macro_input!(input);
    let input = input.value();
    if input.is_empty() {
        return quote!(crate::String16::from_static(&[0u16])).into();
    }

    let input = input.encode_utf16();
    quote!(crate::String16::from_static(&[ #(#input),*, 0 ])).into()
}

#[proc_macro]
pub fn u16_array(input: TokenStream) -> TokenStream {
    let input: LitStr = parse_macro_input!(input);
    let input = input.value();
    if input.is_empty() {
        return quote!([0u16; 0]).into();
    }

    let input = input.encode_utf16();
    quote!([ #(#input),* ]).into()
}

#[proc_macro]
pub fn c16(input: TokenStream) -> TokenStream {
    let input: LitStr = parse_macro_input!(input);
    let input = input.value();
    if input.len() != 1 {
        return Error::new_spanned(input, "Exactly one character must be specified.")
            .into_compile_error()
            .into();
    }

    let input_u16 = Box::from_iter(input.encode_utf16());
    if input_u16.len() == 1 {
        quote!(#(#input_u16),*).into()
    } else {
        Error::new_spanned(
            input,
            "Cannot represent the provided character as a single UTF16 codepoint.",
        )
        .into_compile_error()
        .into()
    }
}

#[proc_macro]
pub fn log2_range(input: TokenStream) -> TokenStream {
    let end: LitInt = parse_macro_input!(input);
    let end: usize = match end.base10_parse() {
        Ok(i) => i,
        Err(_) => {
            return Error::new_spanned(end.base10_digits(), "Invalid end specified.")
                .into_compile_error()
                .into()
        }
    };

    let values = (2..end).into_iter().map(|i| (i as f64).log2());
    quote!([ #(#values),* ]).into()
}
