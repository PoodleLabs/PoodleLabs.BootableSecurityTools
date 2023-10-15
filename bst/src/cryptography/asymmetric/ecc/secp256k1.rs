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

use super::{EllipticCurvePoint, EllipticCurvePointMultiplicationContext, PRIVATE_KEY_PREFIX};
use crate::{global_runtime_immutable::GlobalRuntimeImmutable, integers::BigUnsigned};

// The secp256k1 parameters are:
//
// Prime finite field:
// p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
//   = 2^256 − 2^32 − 2^9 − 2^8 − 2^7 − 2^6 − 2^4 − 1
static mut P: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| {
        BigUnsigned::from_be_bytes(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xFF, 0xFF, 0xFC, 0x2F,
        ])
    });

// Point doubling coefficient:
// a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
//   = 0
static mut A: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_be_bytes(&[0x00]));

// Curve coefficient:
// b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007
//   = 7
#[allow(dead_code)]
static mut B: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_be_bytes(&[0x07]));

// Generator Point:
// Xg = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
static mut G_X: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| {
        BigUnsigned::from_be_bytes(&[
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ])
    });

// Yg = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
static mut G_Y: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| {
        BigUnsigned::from_be_bytes(&[
            0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11,
            0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F,
            0xFB, 0x10, 0xD4, 0xB8,
        ])
    });

// Order (number of points reachable from the generator point):
// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
static mut N: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| {
        BigUnsigned::from_be_bytes(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ])
    });

pub fn point_multiplication_context() -> EllipticCurvePointMultiplicationContext {
    EllipticCurvePointMultiplicationContext::new(n(), p(), a(), 32)
}

pub fn serialized_private_key_bytes(key: &[u8]) -> [u8; 33] {
    let mut bytes = [0u8; 33];
    bytes[0] = PRIVATE_KEY_PREFIX;
    bytes[1..].copy_from_slice(key);
    bytes
}

pub fn serialized_public_key_bytes(key: EllipticCurvePoint) -> Option<[u8; 33]> {
    key.try_serialize_compressed()
}

pub fn g_x() -> &'static BigUnsigned {
    unsafe { G_X.value() }
}

pub fn g_y() -> &'static BigUnsigned {
    unsafe { G_Y.value() }
}

pub fn n() -> &'static BigUnsigned {
    unsafe { N.value() }
}

fn p() -> &'static BigUnsigned {
    unsafe { P.value() }
}

fn a() -> &'static BigUnsigned {
    unsafe { A.value() }
}
