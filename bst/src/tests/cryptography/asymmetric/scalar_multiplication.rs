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
    cryptography::asymmetric::ecc::COMPRESSED_Y_IS_EVEN_IDENTIFIER, integers::BigUnsigned,
    tests::PARALLELIZED_TEST_THREAD_COUNT,
};
use core::cmp::Ordering;
use rand::{random, thread_rng, Rng};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

const RANDOM_ITERATIONS: usize = 16;

#[test]
fn secp256k1_derive_pubkey_zero_privkey() {
    let mut context =
        crate::cryptography::asymmetric::ecc::secp256k1::point_multiplication_context();
    assert_eq!(
        context.multiply_point(
            crate::cryptography::asymmetric::ecc::secp256k1::g_x(),
            crate::cryptography::asymmetric::ecc::secp256k1::g_y(),
            &BigUnsigned::with_capacity(0)
        ),
        None
    );
}

#[test]
fn secp256k1_derive_pubkey_n_privkey() {
    let mut context =
        crate::cryptography::asymmetric::ecc::secp256k1::point_multiplication_context();
    assert_eq!(
        context.multiply_point(
            crate::cryptography::asymmetric::ecc::secp256k1::g_x(),
            crate::cryptography::asymmetric::ecc::secp256k1::g_y(),
            &crate::cryptography::asymmetric::ecc::secp256k1::n(),
        ),
        None
    );
}

#[test]
fn secp256k1_derive_pubkey_n_plus_one_privkey() {
    let mut context =
        crate::cryptography::asymmetric::ecc::secp256k1::point_multiplication_context();
    let mut n_plus_one = crate::cryptography::asymmetric::ecc::secp256k1::n().clone();
    n_plus_one.add(&[1]);

    assert_eq!(
        context.multiply_point(
            crate::cryptography::asymmetric::ecc::secp256k1::g_x(),
            crate::cryptography::asymmetric::ecc::secp256k1::g_y(),
            &n_plus_one,
        ),
        None
    );
}

#[test]
fn secp256k1_derive_pubkey_more_bytes_than_n_privkey() {
    let mut context =
        crate::cryptography::asymmetric::ecc::secp256k1::point_multiplication_context();
    let mut n_plus_one = crate::cryptography::asymmetric::ecc::secp256k1::n().clone();
    n_plus_one.add(&[1]);

    assert_eq!(
        context.multiply_point(
            crate::cryptography::asymmetric::ecc::secp256k1::g_x(),
            crate::cryptography::asymmetric::ecc::secp256k1::g_y(),
            &n_plus_one,
        ),
        None
    );
}

#[test]
fn secp256k1_derive_pubkey_random_privkey() {
    (0..PARALLELIZED_TEST_THREAD_COUNT).into_par_iter().for_each(|i| {
        let iterations = if i == PARALLELIZED_TEST_THREAD_COUNT - 1 {
            RANDOM_ITERATIONS / PARALLELIZED_TEST_THREAD_COUNT + RANDOM_ITERATIONS % PARALLELIZED_TEST_THREAD_COUNT
        } else {
            RANDOM_ITERATIONS / PARALLELIZED_TEST_THREAD_COUNT
        };

        let mut decompression_buffer_x = BigUnsigned::with_capacity(2);
        let mut decompression_buffer_y = BigUnsigned::with_capacity(2);
        let mut expected_decompressed_y_buffer = BigUnsigned::with_capacity(2);
        let mut context =
            crate::cryptography::asymmetric::ecc::secp256k1::point_multiplication_context();
        let secp_context = secp256k1::Secp256k1::new();
        let mut padded_private_key = [0u8; 32];

        for j in 0..iterations {
            let private_key = BigUnsigned::from_be_bytes(
                &(0..thread_rng().gen_range(1..33))
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
                    // secp256k1 library requires exactly 32 bytes.
                    padded_private_key[..32 - private_key.byte_count()].fill(0);
                    private_key.copy_be_bytes_to(&mut padded_private_key[32 - private_key.byte_count()..]);
                    let expected_serialized_key_bytes =
                        secp256k1::SecretKey::from_slice(&padded_private_key)
                            .unwrap()
                            .public_key(&secp_context)
                            .serialize();

                    println!("{},{}P: {:?}", i, j, p);

                    expected_decompressed_y_buffer.set_equal_to(&p.borrow_coordinates().1.borrow_unsigned());
                    let actual_serialized_key_bytes = crate::cryptography::asymmetric::ecc::secp256k1::serialized_public_key_bytes(p).unwrap();

                    println!("{},{}E: {:?}", i, j, expected_serialized_key_bytes);
                    println!("{},{}A: {:?}", i, j, actual_serialized_key_bytes);

                    // Assert public key is as expected.
                    assert_eq!(
                        actual_serialized_key_bytes,
                        expected_serialized_key_bytes
                    );

                    // Decompress the point and assert the decompressed Y coordinate is the same as the original point.
                    decompression_buffer_x.copy_be_bytes_from(&expected_serialized_key_bytes[1..]);
                    context.calculate_y_from_x(
                        expected_serialized_key_bytes[0] == COMPRESSED_Y_IS_EVEN_IDENTIFIER,
                        &decompression_buffer_x,
                        &mut decompression_buffer_y);

                        assert_eq!(
                            decompression_buffer_y,
                            expected_decompressed_y_buffer
                        )
                }
                None => {
                    println!("{},{}: None", i, j);
                    assert!(private_key.is_zero() || private_key.cmp(crate::cryptography::asymmetric::ecc::secp256k1::n()) != Ordering::Less);
                }
            };

            println!("{},{} complete.", i, j);
        }
    });
}
