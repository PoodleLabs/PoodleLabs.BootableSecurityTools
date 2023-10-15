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
    cryptography::asymmetric::ecc::{EccPoint, EllipticCurvePointAdditionContext},
    global_runtime_immutable::GlobalRuntimeImmutable,
    integers::{BigSigned, BigUnsigned},
};

static mut P: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_be_bytes(&2551u16.to_be_bytes()));

static mut A: GlobalRuntimeImmutable<BigUnsigned, fn() -> BigUnsigned> =
    GlobalRuntimeImmutable::from(|| BigUnsigned::from_be_bytes(&5u16.to_be_bytes()));
// B = 1326

#[test]
fn point_addition() {
    let mut context = point_addition_context();

    let p1 = point(22, 2321);
    let p2 = point(605, 851);
    let p3 = point(1777, 1229);
    let p4 = point(2444, 1207);
    let p5 = point(993, 1231);

    // Infinity
    let inf = EccPoint::infinity(4);
    let mut p = inf.clone();

    // Inf + Inf = Inf
    p = add(p, &inf, &inf, &mut context);
    assert_eq!(p, inf);

    // Inf + P = P
    p = add(p, &inf, &p1, &mut context);
    assert_eq!(p, p1);

    p = add(p, &inf, &p2, &mut context);
    assert_eq!(p, p2);

    p = add(p, &inf, &p3, &mut context);
    assert_eq!(p, p3);

    p = add(p, &inf, &p4, &mut context);
    assert_eq!(p, p4);

    p = add(p, &inf, &p5, &mut context);
    assert_eq!(p, p5);

    // P + Inf = P
    p = add(p, &p1, &inf, &mut context);
    assert_eq!(p, p1);

    p = add(p, &p2, &inf, &mut context);
    assert_eq!(p, p2);

    p = add(p, &p3, &inf, &mut context);
    assert_eq!(p, p3);

    p = add(p, &p4, &inf, &mut context);
    assert_eq!(p, p4);

    p = add(p, &p5, &inf, &mut context);
    assert_eq!(p, p5);

    // P + P = Double
    let mut e = inf.clone();

    e = double(e, &p1, &mut context);
    p = add(p, &p1, &p1, &mut context);
    assert_eq!(p, e);

    e = double(e, &p2, &mut context);
    p = add(p, &p2, &p2, &mut context);
    assert_eq!(p, e);

    e = double(e, &p3, &mut context);
    p = add(p, &p3, &p3, &mut context);
    assert_eq!(p, e);

    e = double(e, &p4, &mut context);
    p = add(p, &p4, &p4, &mut context);
    assert_eq!(p, e);

    e = double(e, &p5, &mut context);
    p = add(p, &p5, &p5, &mut context);
    assert_eq!(p, e);

    ////////////
    // P1 + Q //
    ////////////
    // (22, 2321) + (605, 851) = (1777, 1229)
    p = add(p, &p1, &p2, &mut context);
    assert_eq!(p, point(1777, 1229));

    // (22, 2321) + (1777, 1229) = (993, 1231)
    p = add(p, &p1, &p3, &mut context);
    assert_eq!(p, point(993, 1231));

    // (22, 2321) + (2444, 1207) = (1070, 929)
    p = add(p, &p1, &p4, &mut context);
    assert_eq!(p, point(1070, 929));

    // (22, 2321) + (993, 1231) = (2444, 1207)
    p = add(p, &p1, &p5, &mut context);
    assert_eq!(p, point(2444, 1207));

    ////////////
    // P2 + Q //
    ////////////
    // (605, 851) + (22, 2321) = (1777, 1229)
    p = add(p, &p2, &p1, &mut context);
    assert_eq!(p, point(1777, 1229));

    // (605, 851) + (1777, 1229) = (2444, 1207)
    p = add(p, &p2, &p3, &mut context);
    assert_eq!(p, point(2444, 1207));

    // (605, 851) + (2444, 1207) = (140, 192)
    p = add(p, &p2, &p4, &mut context);
    assert_eq!(p, point(140, 192));

    // (605, 851) + (993, 1231) = (1070, 929)
    p = add(p, &p2, &p5, &mut context);
    assert_eq!(p, point(1070, 929));

    ////////////
    // P3 + Q //
    ////////////
    // (1777, 1229) + (22, 2321) = (993, 1231)
    p = add(p, &p3, &p1, &mut context);
    assert_eq!(p, point(993, 1231));

    // (1777, 1229) + (605, 851) = (2444, 1207)
    p = add(p, &p3, &p2, &mut context);
    assert_eq!(p, point(2444, 1207));

    // (1777, 1229) + (2444, 1207) = (130, 2438)
    p = add(p, &p3, &p4, &mut context);
    assert_eq!(p, point(130, 2438));

    // (1777, 1229) + (993, 1231) = (140, 192)
    p = add(p, &p3, &p5, &mut context);
    assert_eq!(p, point(140, 192));

    ////////////
    // P4 + Q //
    ////////////
    // (2444, 1207) + (22, 2321) = (1070, 929)
    p = add(p, &p4, &p1, &mut context);
    assert_eq!(p, point(1070, 929));

    // (2444, 1207) + (605, 851) = (140, 192)
    p = add(p, &p4, &p2, &mut context);
    assert_eq!(p, point(140, 192));

    // (2444, 1207) + (1777, 1229) = (130, 2438)
    p = add(p, &p4, &p3, &mut context);
    assert_eq!(p, point(130, 2438));

    // (2444, 1207) + (993, 1231) = (1851, 587)
    p = add(p, &p4, &p5, &mut context);
    assert_eq!(p, point(1851, 587));

    ////////////
    // P5 + Q //
    ////////////
    // (993, 1231) + (22, 2321) = (2444, 1207)
    p = add(p, &p5, &p1, &mut context);
    assert_eq!(p, point(2444, 1207));

    // (993, 1231) + (605, 851) = (1070, 929)
    p = add(p, &p5, &p2, &mut context);
    assert_eq!(p, point(1070, 929));

    // (993, 1231) + (1777, 1229) = (140, 192)
    p = add(p, &p5, &p3, &mut context);
    assert_eq!(p, point(140, 192));

    // (993, 1231) + (2444, 1207) = (1851, 587)
    p = add(p, &p5, &p4, &mut context);
    assert_eq!(p, point(1851, 587));
}

#[test]
fn point_doubling() {
    let mut context = point_addition_context();
    let mut p = EccPoint::infinity(4);

    // (22, 2321) + (22, 2321) = (605, 851)
    p = double(p, &point(22, 2321), &mut context);
    assert_eq!(p, point(605, 851));

    // (605, 851) + (605, 851) = (993, 1231)
    p = double(p, &point(605, 851), &mut context);
    assert_eq!(p, point(993, 1231));

    // (1777, 1229) + (1777, 1229) = (1070, 929)
    p = double(p, &point(1777, 1229), &mut context);
    assert_eq!(p, point(1070, 929));

    // (2444, 1207) + (2444, 1207) = (2483, 1068)
    p = double(p, &point(2444, 1207), &mut context);
    assert_eq!(p, point(2483, 1068));

    // (993, 1231) + (993, 1231) = (130, 2438)
    p = double(p, &point(993, 1231), &mut context);
    assert_eq!(p, point(130, 2438));
}

fn point_addition_context() -> EllipticCurvePointAdditionContext {
    EllipticCurvePointAdditionContext::from(p(), a(), 4)
}

fn p() -> &'static BigUnsigned {
    unsafe { P.value() }
}

fn a() -> &'static BigUnsigned {
    unsafe { A.value() }
}

fn point(x: u16, y: u16) -> EccPoint {
    EccPoint::from(
        BigSigned::from_unsigned(false, BigUnsigned::from_be_bytes(&x.to_be_bytes())),
        BigSigned::from_unsigned(false, BigUnsigned::from_be_bytes(&y.to_be_bytes())),
    )
}

fn add(
    mut p: EccPoint,
    augend: &EccPoint,
    addend: &EccPoint,
    addition_context: &mut EllipticCurvePointAdditionContext,
) -> EccPoint {
    p.set_equal_to(augend);
    p.add(addend, addition_context);
    p
}

fn double(
    mut p: EccPoint,
    point: &EccPoint,
    addition_context: &mut EllipticCurvePointAdditionContext,
) -> EccPoint {
    p.set_equal_to(point);
    p.double(addition_context);
    p
}
