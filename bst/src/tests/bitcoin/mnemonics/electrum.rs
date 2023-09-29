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

use crate::{bitcoin::mnemonics::electrum, String16};
use hex_literal::hex;
use macros::s16;

#[derive(Debug)]
struct TestVector {
    extension_phrase: Option<String16<'static>>,
    mnemonic_version: electrum::MnemonicVersion,
    expected_seed: &'static [u8],
    output_bytes: &'static [u8],
    input_bytes: &'static [u8],
    mnemonic: &'static str,
    iterations: usize,
}

impl TestVector {
    pub const fn from(
        extension_phrase: Option<String16<'static>>,
        mnemonic_version: electrum::MnemonicVersion,
        expected_seed: &'static [u8],
        output_bytes: &'static [u8],
        input_bytes: &'static [u8],
        mnemonic: &'static str,
        iterations: usize,
    ) -> Self {
        Self {
            extension_phrase,
            mnemonic_version,
            expected_seed,
            output_bytes,
            input_bytes,
            iterations,
            mnemonic,
        }
    }
}

const TEST_VECTORS: [TestVector; 19] = [
    TestVector::from(
        None,
        electrum::MnemonicVersion::Segwit,
        &hex!("1747666e9b3d06c0242bd98bea990c8778d8e2e31ec55136b83d42adb36d5eb0df577f2901c38bcab80383ff3239079b71c5530cd97419556b38e7d0544f6f33"),
        &hex!("0000000000000000000000000000002811"),
        &hex!("0000000000000000000000000000000000"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absent acquire",
        10257,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Segwit,
        &hex!("1747666e9b3d06c0242bd98bea990c8778d8e2e31ec55136b83d42adb36d5eb0df577f2901c38bcab80383ff3239079b71c5530cd97419556b38e7d0544f6f33"),
        &hex!("0000000000000000000000000000002811"),
        &hex!("0000000000000000000000000000000007"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absent acquire",
        10250,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Segwit,
        &hex!("1747666e9b3d06c0242bd98bea990c8778d8e2e31ec55136b83d42adb36d5eb0df577f2901c38bcab80383ff3239079b71c5530cd97419556b38e7d0544f6f33"),
        &hex!("0000000000000000000000000000002811"),
        &hex!("0000000000000000000000000000002811"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absent acquire",
        0,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Segwit,
        &hex!("1747666e9b3d06c0242bd98bea990c8778d8e2e31ec55136b83d42adb36d5eb0df577f2901c38bcab80383ff3239079b71c5530cd97419556b38e7d0544f6f33"),
        &hex!("0000000000000000000000000000002811"),
        &hex!("F000000000000000000000000000002811"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absent acquire",
        0,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Legacy,
        &hex!("1ea27b761af2325549fef0edcadc8eae028988b91f3abe94a5a4e549ba7b61dc36c28fa2a55c7191aa0211bced362286f88480ce2e065950985b790c769b9401"),
        &hex!("0000000000000000000000000000000061"),
        &hex!("0000000000000000000000000000000000"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon around",
        97,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Legacy,
        &hex!("1ea27b761af2325549fef0edcadc8eae028988b91f3abe94a5a4e549ba7b61dc36c28fa2a55c7191aa0211bced362286f88480ce2e065950985b790c769b9401"),
        &hex!("0000000000000000000000000000000061"),
        &hex!("000000000000000000000000000000000a"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon around",
        87,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Legacy,
        &hex!("1ea27b761af2325549fef0edcadc8eae028988b91f3abe94a5a4e549ba7b61dc36c28fa2a55c7191aa0211bced362286f88480ce2e065950985b790c769b9401"),
        &hex!("0000000000000000000000000000000061"),
        &hex!("0000000000000000000000000000000061"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon around",
        0,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Legacy,
        &hex!("1ea27b761af2325549fef0edcadc8eae028988b91f3abe94a5a4e549ba7b61dc36c28fa2a55c7191aa0211bced362286f88480ce2e065950985b790c769b9401"),
        &hex!("0000000000000000000000000000000061"),
        &hex!("E000000000000000000000000000000061"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon around",
        0,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Segwit,
        &hex!("f5feb1a1b5a5bea6afda908f9028c36091782111e557faa1dc0f0483ce4c2127c64e1b7bd213a57b7ad45abb30efdb649b5d8c10326958a5a97a5502c86e7c2b"),
        &hex!("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEF2A5"),
        &hex!("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"),
        "upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz rookie feed",
        951,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Segwit,
        &hex!("f5feb1a1b5a5bea6afda908f9028c36091782111e557faa1dc0f0483ce4c2127c64e1b7bd213a57b7ad45abb30efdb649b5d8c10326958a5a97a5502c86e7c2b"),
        &hex!("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEF2A5"),
        &hex!("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEF2A5"),
        "upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz roof tape upon jazz rookie feed",
        0,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Segwit,
        &hex!("aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        0,
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Segwit,
        &hex!("aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc383"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        1
    ),
    TestVector::from(
        None,
        electrum::MnemonicVersion::Segwit,
        &hex!("aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("ffb0a779f83feddb0e39aa0dde898cc383"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        1
    ),
    TestVector::from(
        Some(s16!("did you ever hear the tragedy of darth plagueis the wise?")),
        electrum::MnemonicVersion::Segwit,
        &hex!("4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        0,
    ),
    TestVector::from(
        Some(s16!("did you ever hear the tragedy of darth plagueis the wise?")),
        electrum::MnemonicVersion::Segwit,
        &hex!("4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc383"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        1
    ),
    TestVector::from(
        Some(s16!("did you ever hear the tragedy of darth plagueis the wise?")),
        electrum::MnemonicVersion::Segwit,
        &hex!("4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("ffb0a779f83feddb0e39aa0dde898cc383"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        1
    ),
    TestVector::from(
        Some(s16!("   DID     \t you ever  \n hear tHe tragedy of darth plagueis the wise?\r\n\t  ")),
        electrum::MnemonicVersion::Segwit,
        &hex!("4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        0,
    ),
    TestVector::from(
        Some(s16!("   DID     \t you ever  \n hear tHe tragedy of darth plagueis the wise?\r\n\t  ")),
        electrum::MnemonicVersion::Segwit,
        &hex!("4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc383"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        1
    ),
    TestVector::from(
        Some(s16!("   DID     \t you ever  \n hear tHe tragedy of darth plagueis the wise?\r\n\t  ")),
        electrum::MnemonicVersion::Segwit,
        &hex!("4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f"),
        &hex!("0fb0a779f83feddb0e39aa0dde898cc384"),
        &hex!("ffb0a779f83feddb0e39aa0dde898cc383"),
        "wild father tree among universe such mobile favorite target dynamic credit identify",
        1
    ),
];

#[test]
fn mnemonic_generation_and_parsing() {
    for test_vector in TEST_VECTORS {
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
            12 => electrum::MnemonicLength::Twelve,
            15 => electrum::MnemonicLength::Fifteen,
            18 => electrum::MnemonicLength::Eighteen,
            21 => electrum::MnemonicLength::TwentyOne,
            24 => electrum::MnemonicLength::TwentyFour,
            _ => panic!(
                "Test vector {:?} has an invalid mnemonic length of {}.",
                test_vector,
                words.len()
            ),
        };

        match electrum::try_generate_mnemonic(
            test_vector.input_bytes,
            mnemonic_length,
            test_vector.mnemonic_version,
        ) {
            Ok((words, i)) => {
                assert_eq!(words, word_strings);
                assert_eq!(i, test_vector.iterations);

                match electrum::try_parse_electrum_mnemonic(&words) {
                    electrum::MnemonicParsingResult::Valid(l, b, v) => {
                        assert_eq!(l, mnemonic_length);
                        assert_eq!(v, test_vector.mnemonic_version);
                        assert_eq!(&b[..], test_vector.output_bytes);

                        let extension_vec = match test_vector.extension_phrase {
                            Some(s) => s.content_slice().to_vec(),
                            None => Vec::new(),
                        };

                        assert_eq!(
                            electrum::BIP_32_DERIVATION_SETTINGS
                                .derive_hd_wallet_seed(extension_vec, words),
                            test_vector.expected_seed
                        );
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
