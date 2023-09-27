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

use crate::hashing::{Hasher, RIPEMD160};
use hex_literal::hex;

macro_rules! test_hashes {
    ($($name:ident: $values:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (data, expected_hash) = $values;
            assert_eq!(RIPEMD160::new().get_hash_of(data), expected_hash);
        }
    )*
    }
}

test_hashes!(
    no_data: (&[0u8;0], hex!("9c1185a5c5e9fc54612808977ee8f548b2258d31")),
    hello_world: ("Hello World!".as_bytes(), hex!("8476ee4631b9b30ac2754b0ee0c47e161d3f724c")),
    just_under_one_block: ("The quick brown fox jumps over the lazy dog. What did the quick".as_bytes(), hex!("55dbbe9b03d1f1e76a8bc17fdf8373b2c58a5858")),
    one_block_exactly: ("The quick brown fox jumps over the lazy dog. What did the quick ".as_bytes(), hex!("653c600fd927102610f3537b2a67111f91c62bc8")),
    a_block_and_a_bit: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do?".as_bytes(), hex!("fffad2c87e010cffc76b3a498538df18c633eb99")),
    just_under_two_blocks: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy do".as_bytes(), hex!("ef3f89b1c0a45fab9c3cbc6a6510f3e7ba2a626d")),
    two_blocks_exactly: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy dog".as_bytes(), hex!("42600203452040150845eb816d7926883e44c78d")),
    two_blocks_and_a_bit: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy dog do? Probably just lay there, idk.".as_bytes(), hex!("0f292d25b1e0aa07accf2d5df2a6f0c3461778b3")),
);
