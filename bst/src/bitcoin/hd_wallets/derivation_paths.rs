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

use super::{fingerprint_key_with, Bip32KeyType, SerializedExtendedKey};
use crate::{
    cryptography::asymmetric::ecc::{secp256k1, EllipticCurvePointMultiplicationContext},
    hashing::{Hasher, Sha256, Sha512, RIPEMD160},
    integers::BigUnsigned,
    String16,
};
use macros::s16;

// If a point in a derivation path is >= 2^31, we should derive a hardened key. If it's < 2^31, we should derive a normal key.
// Hardened children can only be derived from the parent private key; this is desirable as the compromise of both an extended public key parent and
// and non-hardened child private key descending from it is equivalent to knowing the parent extended private key, compromising the entire branch.
const HARDENED_CHILD_DERIVATION_THRESHOLD: u32 = 0b10000000000000000000000000000000;

const MAX_DERIVATION_POINT: u32 = !HARDENED_CHILD_DERIVATION_THRESHOLD;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum IlValidationResult {
    Ok,
    NextIteration,
    ReturnError(String16<'static>),
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct DerivationPathPoint(u32);

impl DerivationPathPoint {
    pub const fn is_for_hardened_key(&self) -> bool {
        self.0 >= HARDENED_CHILD_DERIVATION_THRESHOLD
    }

    pub fn try_derive_key_material_and_chain_code_from(
        &self,
        sha512: &mut Sha512,
        sha256: &mut Sha256,
        ripemd160: &mut RIPEMD160,
        key: &SerializedExtendedKey,
        multiplication_context: &mut EllipticCurvePointMultiplicationContext,
    ) -> Result<SerializedExtendedKey, String16<'static>> {
        if key.depth() == u8::MAX {
            return Err(s16!("Maximum key depth reached."));
        }

        let key_version = match key.try_get_key_version() {
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
        let mut hmac = sha512.build_hmac(key.chain_code());
        let mut hmac_buffer = [0u8; Sha512::HASH_SIZE];

        let (parent_public_key, key_material, chain_code): ([u8; 33], [u8; 33], [u8; 32]) =
            match key_version.key_type() {
                Bip32KeyType::Private => {
                    if self.is_for_hardened_key() {
                        // Deriving a hardened child uses the serialized private key for the hash data.
                        data[..33].copy_from_slice(key.key_material());
                    } else {
                        // Deriving a non-hardened child uses the serialized public key for the hash data.

                        // Parse the private key as a big unsigned integer.
                        let mut key = BigUnsigned::from_be_bytes(&key.key_material());

                        // Derive the EC point for the public key.
                        let point = match multiplication_context.multiply_point(
                            secp256k1::g_x(),
                            secp256k1::g_y(),
                            &key,
                        ) {
                            Some(p) => p,
                            None => return Err(s16!("Failed to derive parent public key.")),
                        };

                        // Zero out the private key integer; we don't need it anymore.
                        key.zero();

                        // Serialize the derived public key and copy to the data buffer.
                        match secp256k1::serialized_public_key_bytes(point) {
                            Some(k) => data[..33].copy_from_slice(&k),
                            None => return Err(s16!("Failed to serialize parent public key.")),
                        };
                    };

                    loop {
                        // The hash data's last 4 bytes are the index.
                        data[33..].copy_from_slice(&index.to_be_bytes());
                        hmac.write_hmac_to(&data, &mut hmac_buffer);

                        let key_material = &hmac_buffer[..32];
                        match Self::validate_key_material(key_material, &mut index) {
                            IlValidationResult::Ok => {}
                            IlValidationResult::NextIteration => continue,
                            IlValidationResult::ReturnError(e) => return Err(e),
                        }

                        // privKey = key_material + parent_key_material (mod n)
                        let chain_code = &hmac_buffer[32..];
                        break todo!();
                    }
                }
                Bip32KeyType::Public => {
                    if self.is_for_hardened_key() {
                        return Err(s16!("Cannot derive hardened child key from a public key."));
                    }

                    // As we can only derive non-hardened children from a public key, and for non-hardened children, the
                    // hash data starts with the serialized public key, we just copy the key material into the data buffer.
                    data[..33].copy_from_slice(key.key_material());

                    loop {
                        // The hash data's last 4 bytes are the index.
                        data[33..].copy_from_slice(&index.to_be_bytes());
                        hmac.write_hmac_to(&data, &mut hmac_buffer);

                        let key_material = &hmac_buffer[..32];
                        match Self::validate_key_material(key_material, &mut index) {
                            IlValidationResult::Ok => {}
                            IlValidationResult::NextIteration => continue,
                            IlValidationResult::ReturnError(e) => return Err(e),
                        }

                        // pubKey = parse_point(parent_key_material) + point(il)
                        let chain_code = &hmac_buffer[32..];
                        break todo!();
                    }
                }
            };

        Ok(SerializedExtendedKey::from(
            key.clone_version_bytes(),
            key.depth() + 1,
            fingerprint_key_with(&parent_public_key, sha256, ripemd160),
            index.to_be_bytes(),
            chain_code,
            key_material,
        ))
    }

    fn validate_key_material(key_material: &[u8], index: &mut u32) -> IlValidationResult {
        if key_material.iter().all(|d| *d == 0) {
            // If the key material == 0 or >= N, we need to move to the next index.
            // TODO: Check if key_material >= N
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

impl From<u32> for DerivationPathPoint {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl Into<u32> for DerivationPathPoint {
    fn into(self) -> u32 {
        self.0
    }
}
