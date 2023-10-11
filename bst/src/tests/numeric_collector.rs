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

use crate::integers::{NumericCollector, NumericCollectorRoundBase};

#[test]
fn numeric_collector_multiplies_by_base_and_adds_round() {
    let rounds = [
        (1, NumericCollectorRoundBase::SubByte(2)),
        (0, NumericCollectorRoundBase::SubByte(2)),
        (0, NumericCollectorRoundBase::SubByte(2)),
        (1, NumericCollectorRoundBase::SubByte(2)),
        (1, NumericCollectorRoundBase::SubByte(3)),
        (2, NumericCollectorRoundBase::SubByte(3)),
        (3, NumericCollectorRoundBase::SubByte(4)),
        (0, NumericCollectorRoundBase::SubByte(4)),
        (2, NumericCollectorRoundBase::SubByte(5)),
        (5, NumericCollectorRoundBase::SubByte(6)),
        (4, NumericCollectorRoundBase::SubByte(7)),
        (1, NumericCollectorRoundBase::SubByte(8)),
        (3, NumericCollectorRoundBase::SubByte(9)),
        (8, NumericCollectorRoundBase::SubByte(10)),
        (7, NumericCollectorRoundBase::SubByte(11)),
        (9, NumericCollectorRoundBase::SubByte(12)),
        (11, NumericCollectorRoundBase::SubByte(13)),
        (10, NumericCollectorRoundBase::SubByte(14)),
        (15, NumericCollectorRoundBase::SubByte(16)),
        (253, NumericCollectorRoundBase::SubByte(254)),
        (200, NumericCollectorRoundBase::SubByte(255)),
        (101, NumericCollectorRoundBase::WholeByte),
    ];

    for i in 1..rounds.len() {
        let mut numeric_collector = NumericCollector::new();
        for j in 0..i {
            let (round_value, round_base) = rounds[j];
            numeric_collector
                .try_add_round(round_value, round_base)
                .unwrap();
        }

        let mut byte_array = [0u8; 8];
        let collected_numeric = numeric_collector.extract_trimmed_bytes();
        byte_array[8 - collected_numeric.data().len()..].copy_from_slice(collected_numeric.data());

        let mut expected_bits = 0f64;
        let mut expected_value = 0u64;
        for j in 0..i {
            let (round_value, round_base) = rounds[j];
            let base = match round_base {
                NumericCollectorRoundBase::SubByte(b) => b as u64,
                NumericCollectorRoundBase::WholeByte => 256u64,
            };

            expected_value *= base;
            expected_value += round_value as u64;
            expected_bits += (base as f64).log2();
        }

        assert_eq!(u64::from_be_bytes(byte_array), expected_value);
        assert_eq!(collected_numeric.bit_count(), expected_bits);
        assert_eq!(
            collected_numeric.trimmed_byte_count(),
            ((expected_value as f64).log(256f64).ceil() as usize).max(1)
        );
        assert_eq!(
            collected_numeric.padded_byte_count(),
            (expected_bits / 8f64).ceil() as usize
        );
    }
}
