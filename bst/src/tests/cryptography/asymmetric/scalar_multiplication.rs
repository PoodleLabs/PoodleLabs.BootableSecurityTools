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

use crate::{integers::BigUnsigned, tests::PARALLELIZED_TEST_THREAD_COUNT};
use rand::random;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

const RANDOM_ITERATIONS: usize = 10;

#[test]
fn secp256k1_derive_pubkey_random_privkey() {
    (0..PARALLELIZED_TEST_THREAD_COUNT).into_par_iter().for_each(|i| {
        let secp_context = secp256k1::Secp256k1::new();
        let iterations = if i == PARALLELIZED_TEST_THREAD_COUNT - 1 {
            RANDOM_ITERATIONS / PARALLELIZED_TEST_THREAD_COUNT + RANDOM_ITERATIONS % PARALLELIZED_TEST_THREAD_COUNT
        } else {
            RANDOM_ITERATIONS / PARALLELIZED_TEST_THREAD_COUNT
        };

        let mut context =
            crate::cryptography::asymmetric::ecc::secp256k1::point_multiplication_context();

        for _ in 0..iterations {
            let private_key = BigUnsigned::from_be_bytes(
                &(0..32)
                    .into_iter()
                    .map(|_| random::<u8>())
                    .collect::<Vec<u8>>(),
            );

            match context.multiply_point(
                crate::cryptography::asymmetric::ecc::secp256k1::g_x(),
                crate::cryptography::asymmetric::ecc::secp256k1::g_y(),
                &private_key,
            ) {
                Some(p) => {
                    let expected_serialized_key_bytes =
                        secp256k1::SecretKey::from_slice(&private_key.clone_be_bytes())
                            .unwrap()
                            .public_key(&secp_context)
                            .serialize();

                    let actual_serialized_key_bytes = crate::cryptography::asymmetric::ecc::secp256k1::serialized_public_key_bytes(p).unwrap();

                    println!("priv: {:?}", private_key.clone_be_bytes());
                    println!("exp: {:?}", expected_serialized_key_bytes);
                    println!("act: {:?}", actual_serialized_key_bytes);
                    assert_eq!(
                        actual_serialized_key_bytes,
                        expected_serialized_key_bytes
                    );
                }
                None => {
                    assert!(private_key.is_zero());
                }
            };
        }
    });
}
