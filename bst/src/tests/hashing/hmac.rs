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

use crate::hashing::{Hasher, Sha256, Sha512, RIPEMD160};
use hex_literal::hex;

fn test_hmac<
    const HASH_SIZE: usize,
    const BLOCK_SIZE: usize,
    THasher: Hasher<HASH_SIZE, BLOCK_SIZE>,
>(
    expected_result: &[u8],
    message: &[u8],
    key: &[u8],
) {
    assert_eq!(
        THasher::new().build_hmac(key).get_hmac(message),
        expected_result
    )
}

macro_rules! ripemd160 {
    ($($name:ident: $values:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (key, message, expected_result) = $values;
            test_hmac::<20, 64, RIPEMD160>(expected_result, message, key)
        }
    )*
    }
}

macro_rules! sha256 {
    ($($name:ident: $values:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (key, message, expected_result) = $values;
            test_hmac::<32, 64, Sha256>(expected_result, message, key)
        }
    )*
    }
}

macro_rules! sha512 {
    ($($name:ident: $values:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (key, message, expected_result) = $values;
            test_hmac::<64, 128, Sha512>(expected_result, message, key)
        }
    )*
    }
}

ripemd160!(
    rmd160_empty_key: (&[0u8; 0], &[32u8; 128], &hex!("379C26EB9C6873A3190853C2C7F3189277194300")),
    rmd160_empty_message: (&[34u8; 128], &[0u8; 0], &hex!("E0C280F7BEC656FA5CD0A39FAD15FACE50CCC5B4")),
    rmd160_sub_block_message: (&[34u8; 128], &[38u8; 10], &hex!("88E490F64D48636CADC344B6E142D8A531245DA5")),
    rmd160_one_block_message: (&[34u8; 128], &[39u8; 64], &hex!("FA5AE10A6DC3B4D71ABD460A97840FD4280DCEB9")),
    rmd160_one_and_a_bit_block_message: (&[34u8; 128], &[120u8; 80], &hex!("7345AB680BD903DCC81B615D024785465486B37E")),
    rmd160_two_block_message: (&[34u8; 128], &[83u8; 128], &hex!("C4E88C23CD4D947F2220517E687E32D8CDA3C202")),
    rmd160_sub_block_key: (&[55u8; 12], &[43u8; 128], &hex!("E664C906770E2255712A2DA85DC400A4017C2F63")),
    rmd160_one_block_key: (&[92u8; 64], &[43u8; 128], &hex!("B3C348389CFD52AF7679C906CA6A587869E6B0A3")),
    rmd160_one_and_a_bit_block_key: (&[60u8; 70], &[43u8; 128], &hex!("A752C54F465296E8555E6A2125CCE33BBD9DB6AA")),
    rmd160_two_block_key: (&[101u8; 128], &[43u8; 128], &hex!("AA46BFDCC6DC8F2CD687D3249745D47B86DFCCF3")),
);

sha256!(
    sha256_empty_key: (&[0u8; 0], &[32u8; 128], &hex!("6907CCD896B9B8830C762868B55A77AFAFE52F175081C072D7A9A2882B5D6138")),
    sha256_empty_message: (&[34u8; 128], &[0u8; 0], &hex!("9FF3C2D9AEBE203B475E420D316DC9447057228B896FDA754F779F91CB1C2C68")),
    sha256_sub_block_message: (&[34u8; 128], &[38u8; 10], &hex!("836F5D5ABE67D586B89FD5D823CD1A6B9F0062C812EF4220E71ABAD39C516164")),
    sha256_one_block_message: (&[34u8; 128], &[39u8; 64], &hex!("27A1F4AFE768505EBDE5015BC33F184ED75A0D879303A47F1C815A31CFF57E43")),
    sha256_one_and_a_bit_block_message: (&[34u8; 128], &[120u8; 80], &hex!("2B9C90E23670F1B401BFF2C83BF76D6344BF0F0B8F7B81C8FECDBD66349ECEE5")),
    sha256_two_block_message: (&[34u8; 128], &[83u8; 128], &hex!("BCC7EBA16878A0CBFC3DD74AE01FD5BF3587FEBB7E43CBF5CB91072255C527E7")),
    sha256_sub_block_key: (&[55u8; 12], &[43u8; 128], &hex!("87D0842B1BF18F51C37886D5CD61FCE6F925726748FE66F8C666D35F48889A80")),
    sha256_one_block_key: (&[92u8; 64], &[43u8; 128], &hex!("E7C768BB7B798B5A23C43CAAF6970592BFD277704273AC39AFA0877C4F5CFC07")),
    sha256_one_and_a_bit_block_key: (&[60u8; 70], &[43u8; 128], &hex!("EC7DBD28BD3BAD21409ED421D95C6531E7F09FD8C3C1066B665E367C8BAE9407")),
    sha256_two_block_key: (&[101u8; 128], &[43u8; 128], &hex!("C566C7590A49D01D6D43846FF1AB22D5C18B2DD0F4B1796B16655A5C3482427B")),
);

sha512!(
    sha512_empty_key: (&[0u8; 0], &[32u8; 256], &hex!("E5861C3F562D82E3DB7385728586D14C075962F5214A7993656B984087730FA15FF661D01CDFBCCA33C9FD0E1E7459D7823464ED0F925A99EDEA3E7FF5BDFE66")),
    sha512_empty_message: (&[34u8; 256], &[0u8; 0], &hex!("D81A26F14C8C682DC89CF3120565FCD4BDFFC64A2C04BE7D4C3CCCF3B1BF3AD781672E349A9CDD665C11BB4DDF68DEEC6F955B6DD43C78226B720D246E2C6A48")),
    sha512_sub_block_message: (&[34u8; 256], &[38u8; 10], &hex!("57CED79376F411BAA92125C1B0CDB796C5A3C18E006847BBD2D61BED2D263F0F10379200E980B52B7E60901C0082D9EB29A32B1C298CB165EC4D268240A7D318")),
    sha512_one_block_message: (&[34u8; 256], &[39u8; 128], &hex!("A23258385966C81381908991E1EF96A6987C895C195B25DAF601F6B9458E12D2181AC82C6D2AC98F2C095D060987342444F4387DC0286415B68E19FD8C87BCBB")),
    sha512_one_and_a_bit_block_message: (&[34u8; 256], &[120u8; 221], &hex!("6BAC270CC3157E8DF27F6094B019D1784357DC9B0C1985F2C4069B7E2FA208A795B0E73B265FA33D44467FD39C861A5F6DCCBCFA554BFEB72209656DB8E86AF9")),
    sha512_two_block_message: (&[34u8; 256], &[83u8; 256], &hex!("09344BAF0F6A7F2D74544A913F18BEA03EE4D677F022AE58D7FAAAC33C2CC4767577F4D25D2498051B3D871091B49B906883B55278A1A3F0EF6F77C2CC33F4E0")),
    sha512_sub_block_key: (&[55u8; 100], &[43u8; 256], &hex!("D9B6C3AC9EF06C3845F551D2BD846B95A409B84BE1A24F8F8FC56FA39067DCFB7553AA02AA3E579115C90B1D7EAE6B0E524BFBF1E5C74F922DE22061E5213728")),
    sha512_one_block_key: (&[92u8; 128], &[43u8; 256], &hex!("9FA0F0346DE2518481AE20175595B5C426EDAB9F3BD889CFF6D1F27079FE93AD68A18322BFB64A4423FAB11A07BB38593AA6DA3B4708BAB7C79F11A11B103D07")),
    sha512_one_and_a_bit_block_key: (&[60u8; 199], &[43u8; 256], &hex!("EFDA85E9ECEADE716848D0B781F727EE11856ACB08D3932CA57D874BB70D9D4F8FE8D4084C76A205B117A803BA47D00767ECDF6768552AEA48FF6A6B730E5432")),
    sha512_two_block_key: (&[101u8; 256], &[43u8; 256], &hex!("0F2EB3A71583226DDCACF52062897C629E65214966DC462A3C284FEE917D7E7224E178C459BFA1FD378E9B13191DB1A5B40A2EEB5E943AF7B90E30F1A77D3E73")),
);
