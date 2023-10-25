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

mod derivation_paths;
mod key_types;
mod serialized_extended_key;

pub use derivation_paths::{
    Bip32DerivationPathPoint, HARDENED_CHILD_DERIVATION_THRESHOLD, MAX_DERIVATION_POINT,
};
pub use key_types::{Bip32KeyNetwork, Bip32KeyType, Bip32KeyVersion};
pub use serialized_extended_key::SerializedExtendedKey;

use super::hash_160_with;
use crate::{
    cryptography::asymmetric::ecc::secp256k1,
    hashing::{Hasher, Sha256, Sha512, RIPEMD160},
    integers::BigUnsigned,
};

// The key used for HMAC-based BIP 32 master key derivation.
const KEY_DERIVATION_KEY_BYTES: &[u8] = "Bitcoin seed".as_bytes();

pub fn try_derive_master_key(
    key_network: Bip32KeyNetwork,
    bytes: &[u8],
) -> Option<SerializedExtendedKey> {
    if bytes.len() < 16 || bytes.len() > 64 {
        // BIP 32 defines a valid seed byte sequence S of length 128 to 512 bits.
        return None;
    }

    // BIP 32 master keys are derived via a SHA512 HMAC.
    let mut hasher = Sha512::new();
    let mut hmac = hasher.build_hmac(KEY_DERIVATION_KEY_BYTES);
    let mut hmac_result = hmac.get_hmac(bytes);

    let mut key_integer = BigUnsigned::from_be_bytes(&hmac_result[..32]);
    if !key_integer.is_non_zero() || &key_integer >= secp256k1::n() {
        // The key must be in the range: 0 < K < N. This shouldn't ever be hit in reality.
        return None;
    }

    // Zero out key integer copy of key.
    key_integer.zero();

    // Key is the first 32 bytes, Chain Code is the last 32 bytes.
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&hmac_result[32..]);

    // The serialized form of a private key is left-padded with a single 0 byte.
    let key_material = secp256k1::serialized_private_key_bytes(&hmac_result[..32]);

    // Fill HMAC copy of key & chain code.
    hmac_result.fill(0);

    Some(SerializedExtendedKey::from(
        key_network.private_key_version_bytes(),
        0,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        chain_code,
        key_material,
    ))
}

pub fn fingerprint_key_with(
    public_key: &[u8],
    sha256: &mut Sha256,
    ripemd160: &mut RIPEMD160,
) -> [u8; 4] {
    let mut fingerprint = [0u8; 4];
    let mut hash_160 = hash_160_with(public_key, sha256, ripemd160);
    fingerprint.copy_from_slice(&hash_160[..4]);
    ripemd160.reset();
    hash_160.fill(0);
    sha256.reset();
    fingerprint
}
