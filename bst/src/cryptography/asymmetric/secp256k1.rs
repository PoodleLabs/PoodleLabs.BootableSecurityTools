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

use crate::{global_runtime_immutable::GlobalRuntimeImmutable, integers::BigUnsigned};

// secp256k1 private keys are a 256 bit integer, while their public keys consist of two 256 bit coordinates.
// Due to the properties of the secp256k1 curve, however, public keys can be represented with a single coordinate, and a flag indicating
// whether the missing coordinate is even or odd. This means we can represent any secp256k1 key with 33 bytes; the first byte is a 'flag' indicating
// how the following 32 bytes should be interpreted.
// In the case of a private key, the flag is 0.
const PRIVATE_KEY_TAG: u8 = 0x00;

// Public keys where the missing coordinate is even have a flag of 2.
const PUBLIC_KEY_TAG_EVEN: u8 = 0x02;

// Public keys where the missing coordinate is odd have a flag of 3.
const PUBLIC_KEY_TAG_ODD: u8 = 0x03;

// The maximum value for a secp256k1 private key.
// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
static mut N: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| {
        BigUnsigned::from_be_bytes(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ])
    });

// The additive coefficient for point doubling.
static mut A: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_be_bytes(&[0x01]));

// The order of the finite field; the modulus to use when performing scalar multiplication.
// p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
// = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
static mut P: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| {
        BigUnsigned::from_be_bytes(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xFF, 0xFF, 0xFC, 0x2F,
        ])
    });

// The starting X coordinate for scalar multiplication.
// Gx = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
static mut GX: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| {
        BigUnsigned::from_be_bytes(&[
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ])
    });

// The starting Y coordinate for scalar multiplication.
// Gy = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
static mut GY: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| {
        BigUnsigned::from_be_bytes(&[
            0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11,
            0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F,
            0xFB, 0x10, 0xD4, 0xB8,
        ])
    });

pub fn n() -> &'static BigUnsigned {
    unsafe { N.value() }
}

fn a() -> &'static BigUnsigned {
    unsafe { A.value() }
}

fn p() -> &'static BigUnsigned {
    unsafe { P.value() }
}

fn gx() -> &'static BigUnsigned {
    unsafe { GX.value() }
}

fn gy() -> &'static BigUnsigned {
    unsafe { GY.value() }
}

pub fn serialized_private_key_bytes(key: &[u8]) -> [u8; 33] {
    let mut bytes = [0u8; 33];
    bytes[0] = PRIVATE_KEY_TAG;
    bytes[1..].copy_from_slice(key);
    bytes
}
