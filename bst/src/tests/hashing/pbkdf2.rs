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

fn test_pbkdf2<
    const BLOCK_SIZE: usize,
    const HASH_SIZE: usize,
    const KEY_SIZE: usize,
    THasher: Hasher<HASH_SIZE, BLOCK_SIZE>,
>(
    expected_result: [u8; KEY_SIZE],
    iterations: u32,
    password: &[u8],
    salt: &[u8],
) {
    let mut output = [0u8; KEY_SIZE];
    THasher::new()
        .build_hmac(password)
        .pbkdf2(salt, iterations, &mut output);
    assert_eq!(output, expected_result)
}

macro_rules! sha512 {
    ($($name:ident: $key_length:literal $values:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (password, salt, iterations, expected_result) = $values;
            test_pbkdf2::<128, 64, $key_length, Sha512>(expected_result, iterations, password, salt)
        }
    )*
    }
}

sha512!(
    empty_password: 64 (
        &[0u8; 0],
        "test salt".as_bytes(),
        1000,
        hex!("8390e4b76b19ec05ff074ec88d0b8670a5f2fae0860d94dcfdf10e0459a252da9e36b2dfc6d3da95fcb7f8bfafadff6767bb462427ba1440ff9733e9f2d24baf")),
    empty_salt: 64 (
        "test password".as_bytes(),
        &[0u8; 0],
        1000,
        hex!("09d4124b97b21d3d46215886f8d1a31e6fff2a6c143e83647aefb860fbe7947c52e1ebd3500bc2a5571695b3efb34a41f6c601792ee565e250a5741d5f34f024")),
    short_key: 40 (
        "test password".as_bytes(),
        "test salt".as_bytes(),
        1000,
        hex!("f56f8a6236537c73f57912c84219c710421bef9833c0b41f45bb76e66e588d214cb2e3c3b5be16ed")),
    hash_length_key: 64 (
        "test password test password test password test password test password test password test password test password test password test password test password".as_bytes(),
        "test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt test salt".as_bytes(),
        1000,
        hex!("be13f244457ccf9d32444ce924966d8b7a6f6d02ef33362130ccdfdb3890cc8b7e6e2ba8d33c2f499bf3b93ec3d2562b074c02fbd9dc5ac6cf7d0c36a94fe46c")),
    more_than_hash_length_key: 512 (
        "ac24b21aa60346fc85952a833bb0d259664e8037ec6f1959f62a6405cf19799d43334a7eb402cf8b6ecf59972a0944228c9dfa6892189d0fd39a405996bd85cff59feb67c4054213b0e1292ef83927a6".as_bytes(),
        "b0e07cd1eafb4beb82b3da932be1d31acb2efa8623ce4e5086bfbfc1b46930dfd876e34962eb2da2084c4cb3a9ab6d897c4339e8780d46369a0954fa5584f628c4ecea65c07b4af9b09e6b9ab85d67fa".as_bytes(),
        1000,
        hex!("68ff4d255113e3811941e76e1f3c66afa057d8b20567284a0549bb97feebf7a01bb0a76ce8f14afbbc543b1fefdb815a35a1de0b641e30477598573f21fa3472c7d24a52d9c73e8a01943f1f176c5587288f31835bf287affa2e53ffc338e8eb2d59dafb422b7f51cdcf5ae882734637868fb93479e378ecd0f37c4ad4606bef75dfdf30e00299ab2031b05b6b3252baf2c1c0a6d8082d29f6a865c7e561ccf273c7474c8283cf768dd2fdf36d3a5e680f6db56685c3657756e50b36fa46096cd6f682b087d240b757643845908333bf5f7a37d789613c0e114eb7c223e874c2f20cc0fef6bebac96217bcfc3774750a83a5a952bafcdfd0b62189bc7ef949feaed228fd062ff698b61cc4c9bde8ec9f963779e50603c78b831ba215442ca803ac16b985894e000e1578816dcb995e11435ab58e7c6dceba733c41a127a5e5df0971240d039cd4dd01ff2eb9bca8d41893ea26fb35e86b4c15d3895bc3b6d26b3d0263cfa5e06b8d8544fa8eb29ef6cc4707bdfdde4388f363c0313126063f7543dd1039e2852a578d845d202587a40c0c5f635b395223804ed4c0065074011ea5c73b10d0251173d6c80aff6a1b8fabc37d518f97cb076dd134a09371ed8a82348a2f1cf23b065f50bf035cf9c992359c822bded63a8e4ad654404ee59028daf8b5efea1c53ddf14db20edb240f0eddd9d40de2757a07810af5d12f64b4f9f7")),
    one_iteration: 69 (
        "ac24b21aa60346fc85952a833bb0d259664e8037ec6f1959f62a6405cf19799d43334a7eb402cf8b6ecf59972a0944228c9dfa6892189d0fd39a405996bd85cff59feb67c4054213b0e1292ef83927a6".as_bytes(),
        "b0e07cd1eafb4beb82b3da932be1d31acb2efa8623ce4e5086bfbfc1b46930dfd876e34962eb2da2084c4cb3a9ab6d897c4339e8780d46369a0954fa5584f628c4ecea65c07b4af9b09e6b9ab85d67fa".as_bytes(),
        1,
        hex!("502f76137e6a96ba0fd3884ce457b7811f735fb5ec6d91456aa6ad0a454a8bf5f624135eab5f6d86d9750b6552a905115885797fe8d90a226b88fde0dca80636deff785443")),
    many_iterations: 312 (
        "ac24b21aa60346fc85952a833bb0d259664e8037ec6f1959f62a6405cf19799d43334a7eb402cf8b6ecf59972a0944228c9dfa6892189d0fd39a405996bd85cff59feb67c4054213b0e1292ef83927a6".as_bytes(),
        "b0e07cd1eafb4beb82b3da932be1d31acb2efa8623ce4e5086bfbfc1b46930dfd876e34962eb2da2084c4cb3a9ab6d897c4339e8780d46369a0954fa5584f628c4ecea65c07b4af9b09e6b9ab85d67fa".as_bytes(),
        10000,
        hex!("6433e176ec6612573002d44aeeafcc16f19bb3a838bfb6de0199feacc60d3bad95213f0bb816f1f826693b80152a0d7c9c9c17493ad5cb48c4ea54294270f2e5d72a5ab416056c044d77acc3a2b531a00ca726413766ef2bf4852dd2cc3d45cc340a549922992098cc5a42ba0af5e5b45c087feb1a4ea445be214954e30bdc2bb77c9fa6cbe8fd34c426be766a764f1d6bfd9d5ce2578245d9888be3df434e4a72086c4d9d199e53e8a8848adb20dd126123acdc80d3ea636fc0b3a141bb11843f37fb3c220f70e58dc0b707afeaeb9e2d9b170ccaf481d0a02daa197aad1ed0fef9ebfd69a59bc3686d8692075215cc50def93ff06e8abce8a7107b04caac5b0fd29293ee4a5dca08a2f759b703f4ae7d79d7342d8459605979b459a717b645d61f0f6ab257eca86ecc4f89abbfaef4731a0586997db9f6")),
);

#[test]
#[should_panic]
fn zero_iterations_panics() {
    let mut output = [0u8; 128];
    Sha512::new().build_hmac("test password".as_bytes()).pbkdf2(
        "test salt".as_bytes(),
        0,
        &mut output,
    );
}
