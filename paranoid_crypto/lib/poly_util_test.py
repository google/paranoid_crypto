# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from absl.testing import absltest
from paranoid_crypto.lib import poly_util
import sympy


def _mul_polys_lh(a: list[int], b: list[int]) -> list[int]:
  res = [0] * (len(a) + len(b) - 1)
  for i, ca in enumerate(a):
    for j, cb in enumerate(b):
      res[i + j] += ca * cb
  return res


class PolyUtilTest(absltest.TestCase):

  def test_eval_poly(self):
    self.assertEqual(poly_util.eval_poly([], 10), 0)
    self.assertEqual(poly_util.eval_poly([7], 10), 7)
    self.assertEqual(poly_util.eval_poly([-3, 2, 5], 10), -3 + 20 + 500)

  def test_constant_zero_and_monomial(self):
    self.assertEqual(poly_util.factor_zz_poly([0, 0, 0]), (0, []))
    self.assertEqual(poly_util.factor_zz_poly([-42, 0]), (-42, []))
    self.assertEqual(
        poly_util.factor_zz_poly([0, 0, 0, -6]), (-6, [([0, 1], 3)])
    )

  def test_content_multiplicities_and_large_leading_coeff(self):
    # -6 * x^2 * (x^2 + 1000*x + 1)^2 * (10^12 * x + 1)
    f1 = [1, 1000, 1]
    f2 = [1, 10**12]
    poly = _mul_polys_lh(_mul_polys_lh(f1, f1), f2)
    poly = [0, 0] + [-6 * c for c in poly]
    res = poly_util.factor_zz_poly(poly)
    self.assertEqual(
        res,
        (
            -6,
            [
                ([0, 1], 2),
                ([1, 10**12], 1),
                ([1, 1000, 1], 2),
            ],
        ),
    )

  def test_van_hoeij_recombines_many_modular_factors(self):
    # Product of 5 irreducible non-monic quadratics that split into >10 modular
    # factors over small primes, exercising van Hoeij LLL recombination.
    quads = [
        [1, 1, 2],
        [3, -2, 5],
        [-5, 3, 7],
        [7, -4, 11],
        [2, 5, 13],
    ]
    prod = [1]
    for q in quads:
      prod = _mul_polys_lh(prod, q)
    res = poly_util.factor_zz_poly(prod)
    self.assertEqual(res, (1, [(q, 1) for q in sorted(quads)]))

  def test_van_hoeij_detects_swinnerton_dyer_irreducible_in_poly_time(self):
    # Non-monic degree-16 Swinnerton-Dyer polynomial: irreducible over Z[x]
    # yet splits into >= 8 factors modulo every prime p.
    x = sympy.Symbol("x")
    sd16 = sympy.minimal_polynomial(
        sympy.sqrt(2) + sympy.sqrt(3) + sympy.sqrt(5) + sympy.sqrt(7), x
    )
    sd16_nonmonic = sympy.Poly(sd16.subs(x, 3 * x), x, domain="ZZ")
    coeffs_lh = [int(c) for c in reversed(sd16_nonmonic.all_coeffs())]
    res = poly_util.factor_zz_poly(coeffs_lh)
    self.assertEqual(res, (1, [(coeffs_lh, 1)]))

  def test_respects_max_modular_factors_bound(self):
    x = sympy.Symbol("x")
    sd16 = sympy.minimal_polynomial(
        sympy.sqrt(2) + sympy.sqrt(3) + sympy.sqrt(5) + sympy.sqrt(7), x
    )
    coeffs_lh = [int(c) for c in reversed(sympy.Poly(sd16, x).all_coeffs())]
    self.assertIsNone(
        poly_util.factor_zz_poly(coeffs_lh, max_modular_factors=4)
    )


if __name__ == "__main__":
  absltest.main()
