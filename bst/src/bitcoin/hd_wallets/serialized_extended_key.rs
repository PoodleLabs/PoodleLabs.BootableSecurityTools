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

use super::{Bip32KeyType, Bip32KeyVersion};
use crate::String16;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct SerializedExtendedKey {
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: [u8; 4],
    chain_code: [u8; 32],
    key_material: [u8; 33],
}

impl SerializedExtendedKey {
    pub const fn from(
        version: [u8; 4],
        depth: u8,
        parent_fingerprint: [u8; 4],
        child_number: [u8; 4],
        chain_code: [u8; 32],
        key_material: [u8; 33],
    ) -> Self {
        Self {
            parent_fingerprint,
            key_material,
            child_number,
            chain_code,
            version,
            depth,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 78 {
            return None;
        }

        let mut chain_code = [0u8; 32];
        let mut key_material = [0u8; 33];

        chain_code.copy_from_slice(&bytes[13..13 + 32]);
        key_material.copy_from_slice(&bytes[13 + 32..13 + 32 + 33]);

        Some(Self {
            version: [bytes[0], bytes[1], bytes[2], bytes[3]],
            depth: bytes[4],
            parent_fingerprint: [bytes[5], bytes[6], bytes[7], bytes[8]],
            child_number: [bytes[9], bytes[10], bytes[11], bytes[12]],
            chain_code,
            key_material,
        })
    }

    pub const fn clone_version_bytes(&self) -> [u8; 4] {
        self.version
    }

    pub const fn parent_fingerprint(&self) -> &[u8] {
        &self.parent_fingerprint
    }

    pub const fn child_number(&self) -> &[u8] {
        &self.child_number
    }

    pub const fn key_material(&self) -> &[u8] {
        &self.key_material
    }

    pub const fn chain_code(&self) -> &[u8] {
        &self.chain_code
    }

    pub const fn depth(&self) -> u8 {
        self.depth
    }

    pub fn to_public_key(&self, key_material: [u8; 33]) -> Option<Self> {
        let network = match self.try_get_key_version() {
            Ok(t) => {
                if t.key_type() != Bip32KeyType::Private {
                    return None;
                }

                t.key_network()
            }
            Err(_) => return None,
        };

        Some(Self {
            parent_fingerprint: self.parent_fingerprint,
            version: network.public_key_version_bytes(),
            child_number: self.child_number,
            chain_code: self.chain_code,
            depth: self.depth,
            key_material,
        })
    }

    pub fn try_get_key_version(&self) -> Result<Bip32KeyVersion, String16<'static>> {
        u32::from_be_bytes(self.version).try_into()
    }

    pub fn as_bytes(&self) -> [u8; 78] {
        let mut bytes = [0u8; 78];
        bytes[00..04].copy_from_slice(&self.version);
        bytes[000004] = self.depth;
        bytes[05..09].copy_from_slice(&self.parent_fingerprint);
        bytes[09..13].copy_from_slice(&self.child_number);
        bytes[13..45].copy_from_slice(&self.chain_code);
        bytes[45..78].copy_from_slice(&self.key_material);
        bytes
    }

    pub fn zero(mut self) {
        self.version.fill(0);
        self.depth = 0;
        self.parent_fingerprint.fill(0);
        self.child_number.fill(0);
        self.chain_code.fill(0);
        self.key_material.fill(0);
    }
}
