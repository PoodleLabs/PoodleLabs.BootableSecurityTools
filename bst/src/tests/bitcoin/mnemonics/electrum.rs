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
    bitcoin::mnemonics::{
        bip_39::Bip39MnemonicLength,
        electrum::{
            try_generate_electrum_mnemonic, try_parse_electrum_mnemonic,
            ElectrumMnemonicParsingResult, ElectrumMnemonicVersion,
        },
    },
    String16,
};
use hex_literal::hex;

#[derive(Debug)]
struct TestVector {
    mnemonic_version: ElectrumMnemonicVersion,
    output_bytes: &'static [u8],
    input_bytes: &'static [u8],
    mnemonic: &'static str,
    iterations: usize,
}

impl TestVector {
    pub const fn from(
        mnemonic_version: ElectrumMnemonicVersion,
        output_bytes: &'static [u8],
        input_bytes: &'static [u8],
        mnemonic: &'static str,
        iterations: usize,
    ) -> Self {
        Self {
            mnemonic_version,
            output_bytes,
            input_bytes,
            iterations,
            mnemonic,
        }
    }
}

const TEST_VECTORS: [TestVector; 13] = [
    TestVector::from(
        ElectrumMnemonicVersion::Segwit,
        &hex!("0000000000000000000000000000002811"),
        &hex!("0000000000000000000000000000000000"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absent acquire",
        10257,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Segwit,
        &hex!("0000000000000000000000000000002811"),
        &hex!("0000000000000000000000000000000007"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absent acquire",
        10250,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Segwit,
        &hex!("0000000000000000000000000000002811"),
        &hex!("0000000000000000000000000000002811"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absent acquire",
        0,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Segwit,
        &hex!("0000000000000000000000000000002811"),
        &hex!("F000000000000000000000000000002811"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absent acquire",
        0,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Legacy,
        &hex!("0000000000000000000000000000000061"),
        &hex!("0000000000000000000000000000000000"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon around",
        97,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Legacy,
        &hex!("0000000000000000000000000000000061"),
        &hex!("000000000000000000000000000000000a"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon around",
        87,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Legacy,
        &hex!("0000000000000000000000000000000061"),
        &hex!("0000000000000000000000000000000061"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon around",
        0,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Legacy,
        &hex!("0000000000000000000000000000000061"),
        &hex!("E000000000000000000000000000000061"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon around",
        0,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Segwit,
        &hex!("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEF2A5"),
        &hex!("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"),
        "upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz rookie feed",
        951,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Segwit,
        &hex!("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEF2A5"),
        &hex!("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEF2A5"),
        "upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz rookie feed",
        0,
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Segwit,
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        0
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Segwit,
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc383"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        1
    ),
    TestVector::from(
        ElectrumMnemonicVersion::Segwit,
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("ffb0a779f83feddb0e39aa0dde898cc383"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        1
    ),
];

#[test]
fn mnemonic_generation_and_parsing() {
    for test_vector in TEST_VECTORS {
        println!("{}", test_vector.mnemonic);
        let words = test_vector
            .mnemonic
            .split(|c: char| c.is_whitespace())
            .filter(|s| s.len() > 0)
            .map(|s| s.encode_utf16().collect::<Vec<u16>>())
            .collect::<Vec<Vec<u16>>>();

        let word_strings = words
            .iter()
            .map(|w| String16::from(w))
            .collect::<Vec<String16>>();

        let mnemonic_length = match words.len() {
            12 => Bip39MnemonicLength::Twelve,
            15 => Bip39MnemonicLength::Fifteen,
            18 => Bip39MnemonicLength::Eighteen,
            21 => Bip39MnemonicLength::TwentyOne,
            24 => Bip39MnemonicLength::TwentyFour,
            _ => panic!(
                "Test vector {:?} has an invalid mnemonic length of {}.",
                test_vector,
                words.len()
            ),
        };

        match try_generate_electrum_mnemonic(
            test_vector.input_bytes,
            mnemonic_length,
            test_vector.mnemonic_version,
        ) {
            Ok((w, i)) => {
                assert_eq!(w, word_strings);
                assert_eq!(i, test_vector.iterations);

                match try_parse_electrum_mnemonic(&w) {
                    ElectrumMnemonicParsingResult::Valid(l, b, v) => {
                        assert_eq!(l, mnemonic_length);
                        assert_eq!(v, test_vector.mnemonic_version);
                        assert_eq!(&b[..], test_vector.output_bytes);
                    }
                    _ => panic!("Test vector {:?} failed mnemonic parsing.", test_vector,),
                }
            }
            Err(w) => panic!(
                "Test vector {:?} failed mnemonic generation: {}.",
                test_vector,
                String::from_utf16(w.content_slice()).unwrap(),
            ),
        }
    }
}
