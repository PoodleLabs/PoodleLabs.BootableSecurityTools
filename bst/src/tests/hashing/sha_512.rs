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

use crate::hashing::{Hasher, Sha512};
use hex_literal::hex;

macro_rules! test_hashes {
    ($($name:ident: $values:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (data, expected_hash) = $values;
            assert_eq!(Sha512::new().get_hash_of(data), expected_hash);
        }
    )*
    }
}

test_hashes!(
    no_data: (&[0u8;0], hex!("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E")),
    hello_world: ("Hello World!".as_bytes(), hex!("861844D6704E8573FEC34D967E20BCFEF3D424CF48BE04E6DC08F2BD58C729743371015EAD891CC3CF1C9D34B49264B510751B1FF9E537937BC46B5D6FF4ECC8")),
    just_under_one_block: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy do".as_bytes(), hex!("D9F148E97B0EB11630EC47D1E284EBB69AA8D20A348B898C6ED7EDDA0E5DF2029B6715878073CC0D356F198295F5B9F6C352567AD953260A57FD6C8C40232FA8")),
    one_block_exactly: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy dog".as_bytes(), hex!("260D6B4465BD79661BC8446C7A62F642B1D5D681D5F802D341FF6FF2EDB97CCC0FC896C8640A25C37A67D8F9DBAD5D52DD6393E69B7DC879006B36BAE0D2BB3D")),
    a_block_and_a_bit: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy dog do? Probably just lay there, idk.".as_bytes(), hex!("69B7922FAC9B350673DEB3F40EB565953197AACB244272FC75DB95906AA09C029F7A86658DCB156205DCDCC74C4375F20F59FAD700031396E2B585868F16D742")),
    just_under_two_blocks: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy dog do? Probably just lay there, idk. The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over".as_bytes(), hex!("37B8817BC6517A891353209E37E628166CB7981BCA140CBE3DEE7127188399F790FA952D5A87572AEFFD7480480142E30CA403A128B77C13B4609041CBFFC505")),
    two_blocks_exactly: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy dog do? Probably just lay there, idk. The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over ".as_bytes(), hex!("EC5D881005C070A3194BEC69181320CFD33E508016B7E2ACD7D0960A6336A367FAC2B24C405F07E3FFBFD194B883DFDB4C369911BE92A67AC48D2EFF5D18DEB8")),
    two_blocks_and_a_bit: ("The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog. What did the lazy dog do? Probably just lay there, idk. The quick brown fox jumps over the lazy dog. What did the quick brown fox do? It jumped over the lazy dog.".as_bytes(), hex!("F778B04D8747719EC060AC4F578D74F321D1663045147AD4B9ADF4673921E4BD3C32A2D618C22828D3D082D4A65758AF13C685C52E94E6F9A94A294579229FBB")),
);
