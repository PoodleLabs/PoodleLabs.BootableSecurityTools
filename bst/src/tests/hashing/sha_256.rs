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

use crate::hashing::{Hasher, Sha256};
use hex_literal::hex;

macro_rules! test_hashes {
    ($($name:ident: $values:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (data, expected_hash) = $values;
            assert_eq!(Sha256::new().get_hash_of(data), expected_hash);
        }
    )*
    }
}

test_hashes!(
    no_data: (&[0u8;0], hex!("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")),
    hello_world: ("Hello World!".as_bytes(), hex!("7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9069")),
    just_under_one_block: ("The quick brown fox jumps over the lazy dog. What did the quick".as_bytes(), hex!("2B9EBF2D55E8FB605AEF2B8D2AF299877D595C218B776C5FDF270E00154A58B6")),
    one_block_exactly: ("The quick brown fox jumps over the lazy dog. What did the quick ".as_bytes(), hex!("A1A7B6AEB3BCBBCA780BF242F5C6F2D471DDF9772DC90CA5FA96A2E27B022581")),
    a_block_and_a_bit: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do?".as_bytes(), hex!("4519928B3BB9A0C07959CDABAC260486078E66706AD4173F98B78BFA9B1CCAB2")),
    just_under_two_blocks: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy do".as_bytes(), hex!("A617B544C923CBCB12A32D69AB8FC0A5D1F1DF128FFF273E0D85FD7119B9D3C7")),
    two_blocks_exactly: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy dog".as_bytes(), hex!("66FC0848FBE1FD4C673E3909A7C73C94EF427B22DCB65BCE1E22BC142D85B4B7")),
    two_blocks_and_a_bit: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy dog do? Probably just lay there, idk.".as_bytes(), hex!("A4F1B82E5DB90905489352FB4E976768401F85B07A69E38CA25CE94385168765")),
);
