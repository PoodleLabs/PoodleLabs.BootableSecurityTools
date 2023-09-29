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
    hashing::{Hasher, Sha512},
    integers::BigInteger,
};

const KEY_DERIVATION_KEY_BYTES: &[u8] = "Bitcoin seed".as_bytes();

static mut SECP256K1_N: Option<BigInteger> = None;

#[repr(C)]
pub struct ExtendedPrivateKey {
    chain_code: [u8; 32],
    key_material: [u8; 32],
}

#[repr(C)]
pub struct SerializedExtendedKey {
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u8,
    chain_code: [u8; 32],
    key_material: [u8; 32],
}

pub fn try_derive_master_key(bytes: &[u8]) -> Option<ExtendedPrivateKey> {
    if bytes.len() < 16 || bytes.len() > 64 {
        // BIP 32 defines a valid seed byte sequence S of length 128 to 512 bits.
        return None;
    }

    let mut hasher = Sha512::new();
    let mut hmac = hasher.build_hmac(KEY_DERIVATION_KEY_BYTES);
    let mut hmac_result = hmac.get_hmac(bytes);

    let mut key_integer = BigInteger::from_be_bytes(&hmac_result[..32]);
    if !key_integer.is_non_zero() || &key_integer >= secp256k1_n() {
        // The key must be in the range: 0 < K < N. This shouldn't ever be hit.
        return None;
    }

    // Zero out key integer copy of key.
    key_integer.multiply(0);

    // Key is the first 32 bytes, Chain Code is the last 32 bytes.
    let mut chain_code = [0u8; 32];
    let mut key_material = [0u8; 32];
    chain_code.copy_from_slice(&hmac_result[32..]);
    key_material.copy_from_slice(&hmac_result[..32]);

    // Fill HMAC copy of key & chain code.
    hmac_result.fill(0);

    Some(ExtendedPrivateKey {
        chain_code,
        key_material,
    })
}

fn secp256k1_n() -> &'static BigInteger {
    match unsafe { SECP256K1_N.as_ref() } {
        Some(i) => i,
        None => {
            let i = BigInteger::from_be_bytes(&[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
                0xD0, 0x36, 0x41, 0x41,
            ]);

            unsafe { SECP256K1_N = Some(i) };
            secp256k1_n()
        }
    }
}
