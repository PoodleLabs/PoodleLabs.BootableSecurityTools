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

use crate::String16;
use macros::s16;

// Serialized keys are prefixed with version bytes.
const MAIN_NET_PRIVATE_KEY_VERSION: u32 = 0x0488ADE4;
const TEST_NET_PRIVATE_KEY_VERSION: u32 = 0x04358394;
const MAIN_NET_PUBLIC_KEY_VERSION: u32 = 0x0488B21E;
const TEST_NET_PUBLIC_KEY_VERSION: u32 = 0x043587CF;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum Bip32KeyType {
    Private,
    Public,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum Bip32KeyNetwork {
    MainNet,
    TestNet,
}

impl Bip32KeyNetwork {
    pub const fn private_key_version_bytes(&self) -> [u8; 4] {
        match self {
            Bip32KeyNetwork::MainNet => MAIN_NET_PRIVATE_KEY_VERSION.to_be_bytes(),
            Bip32KeyNetwork::TestNet => TEST_NET_PRIVATE_KEY_VERSION.to_be_bytes(),
        }
    }

    pub const fn public_key_version_bytes(&self) -> [u8; 4] {
        match self {
            Bip32KeyNetwork::MainNet => MAIN_NET_PUBLIC_KEY_VERSION.to_be_bytes(),
            Bip32KeyNetwork::TestNet => TEST_NET_PUBLIC_KEY_VERSION.to_be_bytes(),
        }
    }
}

impl Into<String16<'static>> for Bip32KeyNetwork {
    fn into(self) -> String16<'static> {
        match self {
            Bip32KeyNetwork::MainNet => s16!("Main Net"),
            Bip32KeyNetwork::TestNet => s16!("Test Net"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bip32KeyTypeAndNetwork {
    key_network: Bip32KeyNetwork,
    key_type: Bip32KeyType,
}

impl Bip32KeyTypeAndNetwork {
    const fn from(key_network: Bip32KeyNetwork, key_type: Bip32KeyType) -> Self {
        Self {
            key_network,
            key_type,
        }
    }

    pub const fn key_network(&self) -> Bip32KeyNetwork {
        self.key_network
    }

    pub const fn key_type(&self) -> Bip32KeyType {
        self.key_type
    }
}

impl TryFrom<u32> for Bip32KeyTypeAndNetwork {
    type Error = String16<'static>;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            MAIN_NET_PRIVATE_KEY_VERSION => {
                Ok(Self::from(Bip32KeyNetwork::MainNet, Bip32KeyType::Private))
            }
            TEST_NET_PRIVATE_KEY_VERSION => {
                Ok(Self::from(Bip32KeyNetwork::TestNet, Bip32KeyType::Private))
            }
            MAIN_NET_PUBLIC_KEY_VERSION => {
                Ok(Self::from(Bip32KeyNetwork::MainNet, Bip32KeyType::Public))
            }
            TEST_NET_PUBLIC_KEY_VERSION => {
                Ok(Self::from(Bip32KeyNetwork::TestNet, Bip32KeyType::Public))
            }
            _ => Err(s16!("Unknown key version bytes.")),
        }
    }
}
