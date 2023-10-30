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

use super::{Bip32KeyType, Bip32SerializedExtendedKey};
use crate::{
    bitcoin::Hash160,
    cryptography::asymmetric::ecc::{
        self, secp256k1, EllipticCurvePoint, EllipticCurvePointMultiplicationContext,
    },
    hashing::{Hasher, Sha512},
    integers::BigUnsigned,
    String16,
};
use core::cmp::Ordering;
use macros::s16;

// If a point in a derivation path is >= 2^31, we should derive a hardened key. If it's < 2^31, we should derive a normal key.
// Hardened children can only be derived from the parent private key; this is desirable as the compromise of both an extended public key parent and
// and non-hardened child private key descending from it is equivalent to knowing the parent extended private key, compromising the entire branch.
pub const HARDENED_CHILD_DERIVATION_THRESHOLD: u32 = 0b10000000000000000000000000000000;
pub const MAX_DERIVATION_POINT: u32 = 0b01111111111111111111111111111111;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum IlValidationResult {
    Ok,
    NextIteration,
    ReturnError(String16<'static>),
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bip32DerivationPathPoint(u32);

impl Bip32DerivationPathPoint {
    pub const fn is_for_hardened_key(&self) -> bool {
        self.0 >= HARDENED_CHILD_DERIVATION_THRESHOLD
    }

    pub const fn numeric_value(&self) -> u32 {
        self.0
    }

    pub fn try_derive_key_material_and_chain_code_from(
        &self,
        sha512: &mut Sha512,
        hash160: &mut Hash160,
        parent_key: &Bip32SerializedExtendedKey,
        private_key_buffer: &mut BigUnsigned,
        point_buffer: &mut EllipticCurvePoint,
        multiplication_context: &mut EllipticCurvePointMultiplicationContext,
    ) -> Result<Bip32SerializedExtendedKey, String16<'static>> {
        if parent_key.depth() == u8::MAX {
            return Err(s16!("Maximum key depth reached."));
        }

        let key_version = match parent_key.try_get_key_version() {
            Ok(t) => t,
            Err(s) => return Err(s),
        };

        // In the (extremely) rare case where a derived child key = 0 or >= N, we move on to the next index.
        let mut index = self.0;

        // Child key derivation requires hashing either:
        // serialized_private_key CAT index
        // or
        // serialized_public_key CAT index
        // Index is 4 bytes long, and the serialized key material is always 33 bytes long.
        let mut data = [0u8; 37];

        // The hash we calculate is the SHA512 HMAC of the data described above, using the parent chain code as the HMAC key.
        let mut hmac = sha512.build_hmac(parent_key.chain_code());
        let mut hmac_buffer = [0u8; Sha512::HASH_SIZE];

        let (parent_public_key, key_material): ([u8; 33], [u8; 33]) = match key_version.key_type() {
            Bip32KeyType::Private => {
                // Write the private key to the private key buffer.
                private_key_buffer.copy_digits_from(parent_key.key_material());

                // Derive the EC point for the public key.
                let point = match multiplication_context.multiply_point(
                    secp256k1::g_x(),
                    secp256k1::g_y(),
                    &private_key_buffer,
                ) {
                    Some(p) => p,
                    None => return Err(s16!("Failed to derive parent public key.")),
                };

                // Serialize the derived public key.
                let parent_public_key = match secp256k1::serialized_public_key_bytes(point) {
                    Some(k) => k,
                    None => return Err(s16!("Failed to serialize parent public key.")),
                };

                if self.is_for_hardened_key() {
                    // Deriving a hardened child uses the serialized private key for the hash data.
                    data[..33].copy_from_slice(parent_key.key_material());
                } else {
                    // Deriving a non-hardened child uses the serialized public key for the hash data.
                    data[..33].copy_from_slice(&parent_public_key);
                };

                // We're done with the EC multiplication context, and can borrow a working buffer from it.
                let working_buffer = multiplication_context
                    .borrow_working_buffer()
                    .borrow_unsigned_mut();

                let key_material = loop {
                    // The hash data's last 4 bytes are the index.
                    data[33..].copy_from_slice(&index.to_be_bytes());
                    hmac.write_hmac_to(&data, &mut hmac_buffer);

                    working_buffer.copy_digits_from(&hmac_buffer[..32]);
                    match Self::validate_key_material(&working_buffer, &mut index) {
                        IlValidationResult::Ok => {}
                        IlValidationResult::NextIteration => continue,
                        IlValidationResult::ReturnError(e) => return Err(e),
                    }

                    // Add parent private key and child private key material.
                    private_key_buffer.add_big_unsigned(&working_buffer);

                    // Calculate the remainder of the sum of the key materials divided by N.
                    private_key_buffer
                        .divide_big_unsigned_with_remainder(secp256k1::n(), working_buffer);

                    // Copy the resulting key into a new key material buffer.
                    let mut key_material = [0u8; 33];
                    key_material[33 - working_buffer.digit_count()..]
                        .copy_from_slice(working_buffer.borrow_digits());

                    // Zero our working buffers; we're done with them.
                    private_key_buffer.zero();
                    working_buffer.zero();

                    // Return our key material from the loop.
                    break key_material;
                };

                (parent_public_key, key_material)
            }
            Bip32KeyType::Public => {
                if self.is_for_hardened_key() {
                    return Err(s16!("Cannot derive hardened child key from a public key."));
                }

                // As we can only derive non-hardened children from a public key, and for non-hardened children, the
                // hash data starts with the serialized public key, we just copy the key material into the data buffer.
                data[..33].copy_from_slice(parent_key.key_material());

                // The parent key is a public key; copy out the serialized value.
                let mut parent_public_key = [0u8; 33];
                parent_public_key.copy_from_slice(parent_key.key_material());

                // We're going to manually write coordinates to the point buffer; first we need to manually ensure it's not set to infinity.
                unsafe {
                    point_buffer.set_not_infinity();
                }

                let (x, y) = point_buffer.borrow_coordinates_mut();
                // Write the X coordinate of the parent public key into the working point.
                x.copy_digits_from(&parent_public_key[1..], false);

                // Ensure the working point's Y value is positive.
                y.set_sign(false);

                // Calculate the Y coordinate of the parent public key's point and write into the working point Y coordinate.
                multiplication_context.calculate_y_from_x(
                    parent_public_key[0] == ecc::COMPRESSED_Y_IS_EVEN_IDENTIFIER,
                    x.borrow_unsigned(),
                    y.borrow_unsigned_mut(),
                );

                let key_material = loop {
                    // The hash data's last 4 bytes are the index.
                    data[33..].copy_from_slice(&index.to_be_bytes());
                    hmac.write_hmac_to(&data, &mut hmac_buffer);

                    // Write the child key material to the private key buffer.
                    private_key_buffer.copy_digits_from(&hmac_buffer[..32]);
                    match Self::validate_key_material(&private_key_buffer, &mut index) {
                        IlValidationResult::Ok => {}
                        IlValidationResult::NextIteration => continue,
                        IlValidationResult::ReturnError(e) => return Err(e),
                    }

                    // Derive the EC point for the child.
                    let mut point = match multiplication_context.multiply_point(
                        secp256k1::g_x(),
                        secp256k1::g_y(),
                        &private_key_buffer,
                    ) {
                        Some(p) => p,
                        None => return Err(s16!("Failed to derive parent public key.")),
                    };

                    // Add the parent point to the child point.
                    point.add(
                        point_buffer,
                        multiplication_context.borrow_addition_context(),
                    );

                    // Zero the working buffer; we're done with it.
                    private_key_buffer.zero();

                    // Serialize the point and return it from the loop as our key material.
                    match secp256k1::serialized_public_key_bytes(point) {
                        Some(k) => break k,
                        None => return Err(s16!("Failed to serialize child public key.")),
                    }
                };

                (parent_public_key, key_material)
            }
        };

        // The chain code is the last 32 bytes of the HMAC result.
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&hmac_buffer[32..]);

        // Zero out the HMAC buffer; we don't need it anymore.
        hmac_buffer.fill(0);

        Ok(Bip32SerializedExtendedKey::from(
            parent_key.clone_version_bytes(),
            parent_key.depth() + 1,
            hash160.fingerprint(&parent_public_key),
            index.to_be_bytes(),
            chain_code,
            key_material,
        ))
    }

    fn validate_key_material(key_material: &BigUnsigned, index: &mut u32) -> IlValidationResult {
        if key_material.is_zero() || key_material.cmp(secp256k1::n()) != Ordering::Less {
            // If the key material == 0 or >= N, we need to move to the next index.
            if (*index & MAX_DERIVATION_POINT) == MAX_DERIVATION_POINT {
                // We've run out of indexes; we can't derive a child key.
                return IlValidationResult::ReturnError(s16!("Ran out of key derivation space; this is extremely unlikely to happen, and should be investigated."));
            } else {
                // Increment and try again.
                *index += 1;
                IlValidationResult::NextIteration
            }
        } else {
            // The key material is valid.
            IlValidationResult::Ok
        }
    }
}

pub struct Bip32CkdDerivationContext {
    sha512: Sha512,
    hash160: Hash160,
    private_key_buffer: BigUnsigned,
    point_buffer: EllipticCurvePoint,
    multiplication_context: EllipticCurvePointMultiplicationContext,
}

impl Bip32CkdDerivationContext {
    pub fn new() -> Self {
        Self {
            multiplication_context: secp256k1::point_multiplication_context(),
            point_buffer: EllipticCurvePoint::infinity(32),
            private_key_buffer: BigUnsigned::with_capacity(32),
            hash160: Hash160::new(),
            sha512: Sha512::new(),
        }
    }

    pub fn derive<F: Fn(&Bip32DerivationPathPoint)>(
        &mut self,
        progress_reporter: F,
        parent_key: Bip32SerializedExtendedKey,
        derivation_path: &[Bip32DerivationPathPoint],
    ) -> Result<Bip32SerializedExtendedKey, String16<'static>> {
        let mut current_key = parent_key;
        for point in derivation_path {
            progress_reporter(point);

            let new_key = match point.try_derive_key_material_and_chain_code_from(
                &mut self.sha512,
                &mut self.hash160,
                &current_key,
                &mut self.private_key_buffer,
                &mut self.point_buffer,
                &mut self.multiplication_context,
            ) {
                Ok(k) => k,
                Err(e) => {
                    // Something went wrong; we shouldn't expect this to actually happen.
                    // Clear all our working values and return the error.
                    return Err(e);
                }
            };

            // Zero out the previous key.
            current_key.zero();

            // Continue with the newly derived key.
            current_key = new_key;
        }

        Ok(current_key)
    }

    pub fn reset(&mut self) {
        self.point_buffer.set_infinity();
        self.private_key_buffer.zero();
        self.hash160.reset();
        self.sha512.reset();
    }
}

impl From<u32> for Bip32DerivationPathPoint {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl Into<u32> for Bip32DerivationPathPoint {
    fn into(self) -> u32 {
        self.0
    }
}
