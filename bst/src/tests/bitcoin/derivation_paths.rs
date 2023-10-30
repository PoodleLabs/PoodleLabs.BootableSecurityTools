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
    bitcoin::{
        hd_wallets::{
            Bip32DerivationPathPoint, Bip32SerializedExtendedKey,
            HARDENED_CHILD_DERIVATION_THRESHOLD,
        },
        Hash160,
    },
    cryptography::asymmetric::ecc::{secp256k1, EllipticCurvePoint},
    hashing::{Hasher, Sha512},
    integers::{BigSigned, BigUnsigned},
};
use hex_literal::hex;
use macros::s16;

#[test]
pub fn private_child_key_derivation_yields_expected_results() {
    // abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about master private key.
    let private_parent_key = Bip32SerializedExtendedKey::from_bytes(&hex!("0488ADE40000000000000000007923408DADD3C7B56EED15567707AE5E5DCA089DE972E07F3B860450E2A3B70E001837C1BE8E2995EC11CDA2B066151BE2CFB48ADF9E47B151D46ADAB3A21CDF67")).unwrap();

    let mut sha512 = Sha512::new();
    let mut hash160 = Hash160::new();
    let mut current_key = private_parent_key;
    let mut private_key_buffer = BigUnsigned::with_capacity(32);
    let mut working_point =
        EllipticCurvePoint::from(BigSigned::with_capacity(32), BigSigned::with_capacity(32));
    let mut multiplication_context = secp256k1::point_multiplication_context();

    // m/44'/0'/0'/1
    let derivation_path = [
        Bip32DerivationPathPoint::from(44 | HARDENED_CHILD_DERIVATION_THRESHOLD),
        Bip32DerivationPathPoint::from(0 | HARDENED_CHILD_DERIVATION_THRESHOLD),
        Bip32DerivationPathPoint::from(0 | HARDENED_CHILD_DERIVATION_THRESHOLD),
        Bip32DerivationPathPoint::from(1),
    ];

    for point in derivation_path {
        current_key = point
            .try_derive_key_material_and_chain_code_from(
                &mut sha512,
                &mut hash160,
                &current_key,
                &mut private_key_buffer,
                &mut working_point,
                &mut multiplication_context,
            )
            .unwrap();
    }

    assert_eq!(
        current_key,
        Bip32SerializedExtendedKey::from_bytes(&hex!("0488ADE4046CC9F25200000001505A8425594B8BA73AB572F6C77B5802C29A4FFBEBF89C020899FB9AB2EAB8C600AD2F3FE15F9E93726ABF77AEFDE4933E6B4234210B6FD08C7D4D728C76AB7603")).unwrap()
    );
}

#[test]
pub fn public_child_key_derivation_yields_expected_results() {
    // abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about master public key.
    let public_parent_key = Bip32SerializedExtendedKey::from_bytes(&hex!("0488B21E0000000000000000007923408DADD3C7B56EED15567707AE5E5DCA089DE972E07F3B860450E2A3B70E03D902F35F560E0470C63313C7369168D9D7DF2D49BF295FD9FB7CB109CCEE0494")).unwrap();

    let mut sha512 = Sha512::new();
    let mut hash160 = Hash160::new();
    let mut current_key = public_parent_key;
    let mut private_key_buffer = BigUnsigned::with_capacity(32);
    let mut working_point =
        EllipticCurvePoint::from(BigSigned::with_capacity(32), BigSigned::with_capacity(32));
    let mut multiplication_context = secp256k1::point_multiplication_context();

    // m/1/2
    let derivation_path = [
        Bip32DerivationPathPoint::from(1),
        Bip32DerivationPathPoint::from(2),
    ];

    for point in derivation_path {
        current_key = point
            .try_derive_key_material_and_chain_code_from(
                &mut sha512,
                &mut hash160,
                &current_key,
                &mut private_key_buffer,
                &mut working_point,
                &mut multiplication_context,
            )
            .unwrap();
    }

    assert_eq!(
        current_key,
        Bip32SerializedExtendedKey::from_bytes(&hex!("0488B21E02C8424CFD0000000245BA2A780031C76AAF6DC3F6D641B9D0944DBCE192A908A38C8A0793E4328B8903EFAFD4F36463D657F500AC7C1D4F2A90BB5B69E767602882B418B2F2D9FB10B4")).unwrap()
    );
}

#[test]
pub fn public_child_key_derivation_doesnt_do_hardened_derivation() {
    // abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about master public key.
    let public_parent_key = Bip32SerializedExtendedKey::from_bytes(&hex!("0488B21E0000000000000000007923408DADD3C7B56EED15567707AE5E5DCA089DE972E07F3B860450E2A3B70E03D902F35F560E0470C63313C7369168D9D7DF2D49BF295FD9FB7CB109CCEE0494")).unwrap();

    let mut sha512 = Sha512::new();
    let mut hash160 = Hash160::new();
    let mut private_key_buffer = BigUnsigned::with_capacity(32);
    let mut working_point =
        EllipticCurvePoint::from(BigSigned::with_capacity(32), BigSigned::with_capacity(32));
    let mut multiplication_context = secp256k1::point_multiplication_context();

    // m/0'
    assert_eq!(
        Bip32DerivationPathPoint::from(0 | HARDENED_CHILD_DERIVATION_THRESHOLD)
            .try_derive_key_material_and_chain_code_from(
                &mut sha512,
                &mut hash160,
                &public_parent_key,
                &mut private_key_buffer,
                &mut working_point,
                &mut multiplication_context,
            ),
        Err(s16!("Cannot derive hardened child key from a public key."))
    );
}
