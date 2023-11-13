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

// An Elliptic Curve is an algebraic curve made up of points with the following equation:
// y^2 = x^3 + ax + b
// With the additional constraint that 4a^3 + 27b^2 != 0, to avoid a singularity where the behaviour becomes
// undefined at certain x coordinates.
//
// The definition of an elliptic curve includes an additional special point which lies beyond the curve,
// which we call infinity. It is the neutral element, in that where P is a point on the curve,
// and I is the infinite point, I + P = P, P + I = P, and I + I = I. It can be thought of as 0.
//
// Bezout's Theorum states that any line which intersects the curve will intersect the curve at exactly three points.
//
// The group law for an elliptic curve is that P + Q + R = Infinity. With Infinity being the neutral element,
// P + Q = -R
//
// Note: the below illustrations were 'drawn' in VS Codium; they must be viewed with a monospace font with
// support for all included characters, with minimal line spacing.
// They are, of course, rough approximations, due to the medium.
//
// An Elliptic Curve looks something like this:
//_____________________________________________________________________________________________________
//|                                                 |                                 ▄▉▉▀            |
//|                                                 |                                ▄▉▀              |
//|                                                 |                              ▄▉▉▀               |
//|                                                 |                            ▄▉▉▀                 |
//|                                                 |                          ▄▉▉▀                   |
//|                             ▄▄▄▄▄▄▄▄▄           |                       ▄▉▉▉▀                     |
//|                          ▄▄▉▀▀▀▀▀▀▀▀▉▉▉▉▄       |                    ▄▉▉▉▀                        |
//|                       ▄▄▉▀▀            ▀▉▉▉▉▄   |                ▄▉▉▉▉▀                           |
//|                     ▄▉▀▀                   ▀▉▉▉▉▄            ▄▉▉▉▉▀                               |
//|                   ▄▉▀                          ▀▉▉▉▉▄    ▄▉▉▉▉▀                                   |
//|                  ▄▉▀                            |  ▀▉▉▉▉▉▉▀                                       |
//|                 ▄▉▀                             |                                                 |
//|                ▄▉▀                              |                                                 |
//|               ▄▉▀                               |                                                 |
//|              ▄▉▀                                |                                                 |
//|              ▉▉                                 |                                                 |
//|             ▉▉▀                                 |                                                 |
//|-------------▉▉----------------------------------+-------------------------------------------------| X
//|             ▉▉▄                                 |                                                 |
//|              ▉▉                                 |                                                 |
//|              ▀▉▄                                |                                                 |
//|               ▀▉▄                               |                                                 |
//|                ▀▉▄                              |                                                 |
//|                 ▀▉▄                             |                                                 |
//|                  ▀▉▄                            |  ▄▉▉▉▉▉▉▄                                       |
//|                   ▀▉▄                          ▄▉▉▉▉▀    ▀▉▉▉▉▄                                   |
//|                     ▀▉▄▄                   ▄▉▉▉▉▀            ▀▉▉▉▉▄                               |
//|                       ▀▀▉▄▄            ▄▉▉▉▉▀   |                ▀▉▉▉▉▄                           |
//|                          ▀▀▉▄▄▄▄▄▄▄▄▉▉▉▉▀       |                    ▀▉▉▉▄                        |
//|                             ▀▀▀▀▀▀▀▀▀           |                       ▀▉▉▉▄                     |
//|                                                 |                          ▀▉▉▄                   |
//|                                                 |                            ▀▉▉▄                 |
//|                                                 |                              ▀▉▉▄               |
//|                                                 |                                ▀▉▄              |
//|                                                 |                                 ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y
//
// Elliptic Curve Cryptograpy requires the addition of points on a curve, P and Q, for a third point R.
// This is achieved by drawing a line between points P and Q, then making R the inverse of the point at
// which the line intersects the curve for the third time:
//_____________________________________________________________________________________________________
//|                                                 |                                 ▄▉▉▀            |
//|                                                 |                                ▄▉▀              |
//|                                                 |                              ▄▉▉▀               |
//|                                                 |                            ▄▉▉▀                 |
//|                                                 |                          ▄▉▉▀                   |
//|                             ▄▄▄▄▄▄▄▄▄           |                       ▄▉▉▉▀              _____--|
//|                          ▄▄▉▀▀▀▀▀▀▀▀▉▉▉▉▄       |                    ▄▉▉▉▀  _____-----¯¯¯¯¯       |
//|                       ▄▄▉▀▀            ▀▉▉▉▉▄   |       _____----▄R▉▉▉▀¯¯¯¯¯                      |
//|                     ▄▉▀▀                 __▀▉▉Q▉▄--¯¯¯¯¯     ▄▉▉▉▉▀                               |
//|                   ▄▉▀     _____-----¯¯¯¯¯      ▀▉▉▉▉▄    ▄▉▉▉▉▀   :                               |
//|            _____-▄P--¯¯¯¯¯                      |  ▀▉▉▉▉▉▉▀       :                               |
//|__-----¯¯¯¯¯     ▄▉▀                             |                 :                               |
//|                ▄▉▀                              |                 :                               |
//|               ▄▉▀                               |                 :                               |
//|              ▄▉▀                                |                 :                               |
//|              ▉▉                                 |                 :                               |
//|             ▉▉▀                                 |                 :                               |
//|-------------▉▉----------------------------------+-----------------+-------------------------------| X
//|             ▉▉▄                                 |                 :                               |
//|              ▉▉                                 |                 :                               |
//|              ▀▉▄                                |                 :                               |
//|               ▀▉▄                               |                 :                               |
//|                ▀▉▄                              |                 :                               |
//|                 ▀▉▄                             |                 :                               |
//|                  ▀▉▄                            |  ▄▉▉▉▉▉▉▄       :                               |
//|                   ▀▉▄                          ▄▉▉▉▉▀    ▀▉▉▉▉▄   :                               |
//|                     ▀▉▄▄                   ▄▉▉▉▉▀            ▀▉▉▉▉▄                               |
//|                       ▀▀▉▄▄            ▄▉▉▉▉▀   |                ▀r▉▉▉▄                           |
//|                          ▀▀▉▄▄▄▄▄▄▄▄▉▉▉▉▀       |                    ▀▉▉▉▄                        |
//|                             ▀▀▀▀▀▀▀▀▀           |                       ▀▉▉▉▄                     |
//|                                                 |                          ▀▉▉▄                   |
//|                                                 |                            ▀▉▉▄                 |
//|                                                 |                              ▀▉▉▄               |
//|                                                 |                                ▀▉▄              |
//|                                                 |                                 ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y
// Where P = (Xp, Yp), Q = (Xq, Yq):
// The slope of the line intersecting both points is: (Yp - Yq) / (Xp - Xq)
// The inverse of the third point R, r is:
// Xr = slope^2 - Xp - Xq
// Yr = Yp + (slope * (Xp - Xr))
//
// Note that there is one point on the curve where Y = 0, and for all other X coordinates, there are
// exactly two possible Y coordinates, which are the inverse of one another.
//
// When two points have the same X coordinate, but different Y coordinates, the line between them is
// vertical; the third intersected point is infinity. The inverse of infinity, being the neutral element,
// is infinity, so R = r.
//
//                                 Inf                    Inf                Inf
//__________________________________R______________________R__________________R________________________
//|                                 :               |      :                  :       ▄▉▉▀            |
//|                                 :               |      :                  :      ▄▉▀              |
//|                                 :               |      :                  :    ▄▉▉▀               |
//|                                 :               |      :                  :  ▄▉▉▀                 |
//|                                 :               |      :                  :▄▉▉▀                   |
//|                             ▄▄▄▄▄▄▄▄▄           |      :                ▄▉P▉▀                     |
//|                          ▄▄▉▀▀▀▀P▀▀▀▉▉▉▉▄       |      :             ▄▉▉▉▀:                       |
//|                       ▄▄▉▀▀     :      ▀▉▉▉▉▄   |      :         ▄▉▉▉▉▀   :                       |
//|                     ▄▉▀▀        :          ▀▉▉▉▉▄      :     ▄▉▉▉▉▀       :                       |
//|                   ▄▉▀           :              ▀▉▉▉▉▄  : ▄▉▉▉▉▀           :                       |
//|                  ▄▉▀            :               |  ▀▉▉▉Q▉▉▀               :                       |
//|                 ▄▉▀             :               |      :                  :                       |
//|                ▄▉▀              :               |      :                  :                       |
//|               ▄▉▀               :               |      :                  :                       |
//|              ▄▉▀                :               |      :                  :                       |
//|              ▉▉                 :               |      :                  :                       |
//|             ▉▉▀                 :               |      :                  :                       |
//|------------>▉▉<-Y=0-------------+---------------+------+------------------+-----------------------| X
//|             ▉▉▄                 :               |      :                  :                       |
//|              ▉▉                 :               |      :                  :                       |
//|              ▀▉▄                :               |      :                  :                       |
//|               ▀▉▄               :               |      :                  :                       |
//|                ▀▉▄              :               |      :                  :                       |
//|                 ▀▉▄             :               |      :                  :                       |
//|                  ▀▉▄            :               |  ▄▉▉▉P▉▉▄               :                       |
//|                   ▀▉▄           :              ▄▉▉▉▉▀  : ▀▉▉▉▉▄           :                       |
//|                     ▀▉▄▄        :          ▄▉▉▉▉▀      :     ▀▉▉▉▉▄       :                       |
//|                       ▀▀▉▄▄     :      ▄▉▉▉▉▀   |      :         ▀▉▉▉▉▄   :                       |
//|                          ▀▀▉▄▄▄▄Q▄▄▄▉▉▉▉▀       |      :             ▀▉▉▉▄:                       |
//|                             ▀▀▀▀▀▀▀▀▀           |      :                ▀▉Q▉▄                     |
//|                                 :               |      :                  :▀▉▉▄                   |
//|                                 :               |      :                  :  ▀▉▉▄                 |
//|                                 :               |      :                  :    ▀▉▉▄               |
//|                                 :               |      :                  :      ▀▉▄              |
//|                                 :               |      :                  :       ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y
//
// When adding a point to itself, we have a similar problem in that there are multiple lines we could draw.
// However, this does not satisfy our group law. Additionally, Xp - Xq, qhere P = Q, is 0, and we cannot
// divide by zero.
//
// Instead, we can think of this as the addition of two points which approach one another, so the line is
// drawn as the tangent of the point on the curve; P and Q both equal P, and R is our third coordinate:
//_____________________________________________________________________________________________________
//|                                                 |                                 ▄▉▉▀            |
//|                                                 |                                ▄R▀              |
//|                                                 |                  _____-----¯¯▄▉▉▀               |
//|                                                 |   _____-----¯¯¯¯¯          ▄▉▉▀ :               |
//|                                      _____-----¯|¯¯¯                       ▄▉▉▀   :               |
//|                       _____-▄P▄▄¯¯¯¯¯           |                       ▄▉▉▉▀     :               |
//|        _____-----¯¯¯¯¯   ▄▄▉▀Q▀▀▀▀▀▀▉▉▉▉▄       |                    ▄▉▉▉▀        :               |
//|---¯¯¯¯¯               ▄▄▉▀▀            ▀▉▉▉▉▄   |                ▄▉▉▉▉▀           :               |
//|                     ▄▉▀▀                   ▀▉▉▉▉▄            ▄▉▉▉▉▀               :               |
//|                   ▄▉▀                          ▀▉▉▉▉▄    ▄▉▉▉▉▀                   :               |
//|                  ▄▉▀                            |  ▀▉▉▉▉▉▉▀                       :               |
//|                 ▄▉▀                             |                                 :               |
//|                ▄▉▀                              |                                 :               |
//|               ▄▉▀                               |                                 :               |
//|              ▄▉▀                                |                                 :               |
//|              ▉▉                                 |                                 :               |
//|             ▉▉▀                                 |                                 :               |
//|-------------▉▉----------------------------------+---------------------------------+---------------| X
//|             ▉▉▄                                 |                                 :               |
//|              ▉▉                                 |                                 :               |
//|              ▀▉▄                                |                                 :               |
//|               ▀▉▄                               |                                 :               |
//|                ▀▉▄                              |                                 :               |
//|                 ▀▉▄                             |                                 :               |
//|                  ▀▉▄                            |  ▄▉▉▉▉▉▉▄                       :               |
//|                   ▀▉▄                          ▄▉▉▉▉▀    ▀▉▉▉▉▄                   :               |
//|                     ▀▉▄▄                   ▄▉▉▉▉▀            ▀▉▉▉▉▄               :               |
//|                       ▀▀▉▄▄            ▄▉▉▉▉▀   |                ▀▉▉▉▉▄           :               |
//|                          ▀▀▉▄▄▄▄▄▄▄▄▉▉▉▉▀       |                    ▀▉▉▉▄        :               |
//|                             ▀▀▀▀▀▀▀▀▀           |                       ▀▉▉▉▄     :               |
//|                                                 |                          ▀▉▉▄   :               |
//|                                                 |                            ▀▉▉▄ :               |
//|                                                 |                              ▀▉▉▄               |
//|                                                 |                                ▀r▄              |
//|                                                 |                                 ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y
// This operation is referred to as 'point doubling'. We can calculate the slope of the tangent with:
// slope = ((3 * Xp^2) + a) / (2 * Yp)
// As P = Q, ((3 * Xq^2) + a) / (2 * Yq) yields the same result.
// We use the same formula to calculate the inverse of the third point as before; only the slope changes.
//
// Note that where Y = 0, the point is the inverse of itself, and the tangent is vertical, so the third
// point is infinity.
//             Inf
//______________R______________________________________________________________________________________
//|             :                                   |                                 ▄▉▉▀            |
//|             :                                   |                                ▄▉▀              |
//|             :                                   |                              ▄▉▉▀               |
//|             :                                   |                            ▄▉▉▀                 |
//|             :                                   |                          ▄▉▉▀                   |
//|             :               ▄▄▄▄▄▄▄▄▄           |                       ▄▉▉▉▀                     |
//|             :            ▄▄▉▀▀▀▀▀▀▀▀▉▉▉▉▄       |                    ▄▉▉▉▀                        |
//|             :         ▄▄▉▀▀            ▀▉▉▉▉▄   |                ▄▉▉▉▉▀                           |
//|             :       ▄▉▀▀                   ▀▉▉▉▉▄            ▄▉▉▉▉▀                               |
//|             :     ▄▉▀                          ▀▉▉▉▉▄    ▄▉▉▉▉▀                                   |
//|             :    ▄▉▀                            |  ▀▉▉▉▉▉▉▀                                       |
//|             :   ▄▉▀                             |                                                 |
//|             :  ▄▉▀                              |                                                 |
//|             : ▄▉▀                               |                                                 |
//|             :▄▉▀                                |                                                 |
//|             :▉▉                                 |                                                 |
//|             ▉▉▀                                 |                                                 |
//|------------PQ▉<-Y=0-----------------------------+-------------------------------------------------| X
//|             ▉▉▄                                 |                                                 |
//|             :▉▉                                 |                                                 |
//|             :▀▉▄                                |                                                 |
//|             : ▀▉▄                               |                                                 |
//|             :  ▀▉▄                              |                                                 |
//|             :   ▀▉▄                             |                                                 |
//|             :    ▀▉▄                            |  ▄▉▉▉▉▉▉▄                                       |
//|             :     ▀▉▄                          ▄▉▉▉▉▀    ▀▉▉▉▉▄                                   |
//|             :       ▀▉▄▄                   ▄▉▉▉▉▀            ▀▉▉▉▉▄                               |
//|             :         ▀▀▉▄▄            ▄▉▉▉▉▀   |                ▀▉▉▉▉▄                           |
//|             :            ▀▀▉▄▄▄▄▄▄▄▄▉▉▉▉▀       |                    ▀▉▉▉▄                        |
//|             :               ▀▀▀▀▀▀▀▀▀           |                       ▀▉▉▉▄                     |
//|             :                                   |                          ▀▉▉▄                   |
//|             :                                   |                            ▀▉▉▄                 |
//|             :                                   |                              ▀▉▉▄               |
//|             :                                   |                                ▀▉▄              |
//|             :                                   |                                 ▀▉▉▄            |
//¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
//                                                  Y
//
// When using an Elliptic Curve in cryptography, we need to work over a finite field (a range of values)
// within bound constraints. To achieve this, the equation:
// y^2 = x^3 + ax + b
// Simply becomes:
// y^2 = x^3 + ax + b (mod p)
// Where p is a prime number, and is the upper bound of the finite field.
// We apply the same modulus to all equations:
//
// Distinct point addition slope:
// slope = (Yp - Yq) / (Xp - Xq) (mod p)
//
// Point doubling slope:
// slope = ((3 * Xp^2) + a) / (2 * Yp) (mod p)
//
// Point addition/doubling sum from slope:
// Xr = slope^2 - Xp - Xq (mod p)
// Yr = Yp + (slope * (Xp - Xr)) (mod p)
//
// Note: (mod p) means that all arithmetic within the equation must be modular; we cannot just take
// the mod of the result.

use super::EllipticCurvePointAdditionContext;
use crate::integers::{BigSigned, BigUnsigned};

pub const COMPRESSED_Y_IS_EVEN_IDENTIFIER: u8 = 0x02;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EllipticCurvePoint {
    is_infinity: bool,
    x: BigSigned,
    y: BigSigned,
}

impl EllipticCurvePoint {
    pub fn infinity(integer_capacity: usize) -> Self {
        Self {
            x: BigSigned::with_capacity(integer_capacity),
            y: BigSigned::with_capacity(integer_capacity),
            is_infinity: true,
        }
    }

    pub fn try_serialize_compressed<const N: usize>(&self) -> Option<[u8; N]> {
        // We can compress a point on a prime finite field elliptic curve by representing it with only the X value,
        // and a single byte to indicate whether the Y value is odd or even, because there are two possible Y values
        // for any given X coordinate, and (mod p) results in one Y value always being even, and the other always being odd.
        if self.x.byte_count() + 1 > N {
            // We need to be able to fit X in the buffer, with one additional byte to spare. If we can't manage that, return None.
            return None;
        }

        // Create a buffer; the point will be serialized into it.
        let mut buffer = [0u8; N];

        // The first byte in the buffer is 2 if the Y coordinate is even, and 3 if the Y coordinate is odd.
        buffer[0] = if self.y.is_even() {
            COMPRESSED_Y_IS_EVEN_IDENTIFIER
        } else {
            0x03
        };

        // Copy the bytes from the X coordinate to the end of the buffer.
        self.x
            .copy_be_bytes_to(&mut buffer[N - self.x.byte_count()..]);

        Some(buffer)
    }

    #[cfg(test)]
    pub fn borrow_coordinates(&self) -> (&BigSigned, &BigSigned) {
        (&self.x, &self.y)
    }

    pub fn add(
        &mut self,
        addend: &EllipticCurvePoint,
        addition_context: &mut EllipticCurvePointAdditionContext,
    ) {
        if self.is_infinity {
            // Infinity + X = X
            self.set_equal_to(addend);
            return;
        }

        if addend.is_infinity {
            // X + Infinity = X
            return;
        }

        if self.x.eq(&addend.x) {
            // The X values are identical; there will be special-case logic for addition.
            if self.y.eq(&addend.y) {
                // The points are identical; we need to use the point doubling equation.
                self.double(addition_context);
            } else {
                // The points are not identical, but their X values are. The only possibility is that the Y values are inverse to one another
                // (as in Py = -Qy), in which case, the third point is infinity.
                self.set_infinity();
            }

            // Special case addition logic was applied; don't do anything more.
            return;
        }

        // Store the augend's original value for later. The X and Y values on the augend can now be used as working buffers.
        addition_context.store_augend(&self);

        // We need to calculate the slope of the line between points P and Q.
        // The formula is (Yp - Yq) / (Xp - Xq) (mod p)
        //
        // Using the modular inverse of the divisor simplifies things here:
        // a = Xq
        // a -= Xp
        // a mod inverse
        // b = Yq
        // b = Yp
        // a *= b

        // X = Xq
        self.x.set_equal_to(&addend.x);

        // X -= Xp
        self.x.subtract_big_signed(&addition_context.augend.x);

        // X mod inverse
        addition_context.mod_inverse(&mut self.x);

        // Y = Yq
        self.y.set_equal_to(&addend.y);

        // Y -= Yp
        self.y.subtract_big_signed(&addition_context.augend.y);

        // X *= Y
        self.x.multiply_big_signed(&self.y);

        addition_context.slope.set_equal_to(&self.x);

        // The sum-from-slope calculation is identical for distinct point addition and point doubling.
        // The slope is stored in the point addition context, along with the original augend value.
        // Calculate the sum point, passing in the addend.
        self.calculate_new_point_from_slope(Some(addend), addition_context)
    }

    pub fn double(&mut self, addition_context: &mut EllipticCurvePointAdditionContext) {
        if self.is_infinity {
            // Infinity + Infinity = Infinity
            return;
        }

        if self.y.is_zero() {
            // When Py = 0, the tangent is vertical, and the result is infinity.
            self.set_infinity();
            return;
        }

        // Store the point's original value for later. The X and Y values on the augend can now be used as working buffers.
        addition_context.store_augend(&self);

        // We need to calculate the tangent of P on the curve.
        // The formula is ((3 * Xp^2) + a) / (2 * Yp) (mod p)
        //
        // Using the modular inverse of the divisor simplifies things here:
        // a = Yp
        // a *= 2
        // a mod inverse
        // b = Xp
        // b *= Xp
        // b *= 3
        // b += a
        // a *= b

        // Y = Yp
        // Y *= 2
        self.y.multiply_unsigned(&[2]);

        // Y mod inverse
        addition_context.mod_inverse(&mut self.y);

        // X = Xp
        // X *= Xp
        self.x.multiply_big_signed(&addition_context.augend.x);

        // X *= 3
        self.x.multiply_unsigned(&[3]);

        // X += a
        self.x.add_big_unsigned(addition_context.a);

        // X *= Y
        self.x.multiply_big_signed(&self.y);

        addition_context.slope.set_equal_to(&self.x);

        // The sum-from-slope calculation is identical for distinct point addition and point doubling.
        // The slope is stored in the point addition context, along with the original point.
        // Calculate the sum point; the addend is the same as the augend.
        self.calculate_new_point_from_slope(None, addition_context)
    }

    pub fn borrow_coordinates_mut(&mut self) -> (&mut BigSigned, &mut BigSigned) {
        (&mut self.x, &mut self.y)
    }

    pub fn set_equal_to_unsigned(&mut self, x: &BigUnsigned, y: &BigUnsigned) {
        self.x.set_equal_to_unsigned(x, false);
        self.y.set_equal_to_unsigned(y, false);
        self.is_infinity = x.is_zero() && y.is_zero();
    }

    pub fn set_equal_to(&mut self, other: &EllipticCurvePoint) {
        self.is_infinity = other.is_infinity;
        self.x.set_equal_to(&other.x);
        self.y.set_equal_to(&other.y);
    }

    pub fn set_infinity(&mut self) {
        self.is_infinity = true;
        self.x.zero();
        self.y.zero();
    }

    fn calculate_new_point_from_slope(
        &mut self,
        addend: Option<&EllipticCurvePoint>,
        addition_context: &mut EllipticCurvePointAdditionContext,
    ) {
        // The slope is stored in the context's slope buffer, and the original augend (Xp, Yp) is stored in the context's augend buffer.
        // In point addition, the addend (Xq, Yq) is passed in. In point doubling, the addend is the same as the augend.
        //
        // We can calculate R with the following steps:
        //
        // Xr = slope^2 - Xp - Xq (mod p)
        // a = slope
        // a *= slope
        // a -= Xp
        // a -= Xq
        // a mod p
        //
        // Yr = (slope * (Xp - Xr)) - Yp (mod p)
        // a = Xp
        // a -= Xr
        // a *= slope
        // a -= Yp
        // a mod p

        // Y = slope
        self.y.set_equal_to(&addition_context.slope);

        // Y *= slope
        self.y.multiply_big_signed(&addition_context.slope);

        // Y -= Xp
        self.y.subtract_big_signed(&addition_context.augend.x);

        // Y -= Xq
        self.y.subtract_big_signed(match addend {
            Some(addend) => &addend.x,
            None => &addition_context.augend.x,
        });

        // X = Y mod p = Xr
        self.y
            .divide_big_unsigned_with_signed_modulus(addition_context.p, &mut self.x);

        // Y = Xp
        self.y.set_equal_to(&addition_context.augend.x);

        // Y -= Xr
        self.y.subtract_big_signed(&self.x);

        // slope *= Y
        addition_context.slope.multiply_big_signed(&self.y);

        // slope -= Yp
        addition_context
            .slope
            .subtract_big_signed(&addition_context.augend.y);

        // Y = slope mod p = Yr
        addition_context
            .slope
            .divide_big_unsigned_with_signed_modulus(addition_context.p, &mut self.y);
    }

    pub unsafe fn set_not_infinity(&mut self) {
        // Only to be used when the coordinates have been manually written to.
        self.is_infinity = false;
    }
}
