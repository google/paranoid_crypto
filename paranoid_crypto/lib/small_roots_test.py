# Copyright 2022 Google LLC
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
"""Tests for paranoid_crypto.lib.small_roots."""

import random
from absl.testing import absltest
from paranoid_crypto.lib import small_roots
import sympy

n = int(
    "be2dd762759138f349f97566d707d47ef9ac2e7246db455e4d11fa8d9f7ed9c52d35"
    "7d475d00689f407e700b05fe2025c92d59c23291b40e068c33825dee3329c6b7f864"
    "45bc04ed3099db4c3cd5646449c23e5b3b1ace207a558596d9b29cac2ad465532876"
    "7faf3eb594601ad9757863ac12d5f2fbcd50abba6924e6a987b210713ca92d9929dd"
    "f38e6021be2ed7a859dc623a78baf12663dd9df4fbcbce076e35134aad0fea87a2c1"
    "1307cad3d4ca110cb0b57907fc590e76c59f600fbc1e14368eea2e4f44d6fb7808dd"
    "a6b80c4c940e4283b45bad906b55249370836fcac366cba64741d1de7a2630412f08"
    "85bd5ba4877c5bea4de2378cdb0bb5a7b313", 16)
p = int(
    "e6b708bb5377977a4eac6c1bff544595e54bfbe732d28d16eafb7e700ea158cbe0b2"
    "7856a1405d4646de4a54021751c9ebb6870db48834fb8b5ac381fac10524d24e7018"
    "7a3750c859bb72519bcf7523ae97454000012695c3ce552cffc07f6d9a540f5dea97"
    "3b16a59ef22814dd0eca5405c05dd6767d4cba74c5031e5bc4a5", 16)


class SmallRootsTest(absltest.TestCase):

  def testUnivariateHighBits(self):
    x = sympy.Symbol("x")
    # Even using a small lattice (default k = 3), we are able to factorize when
    # about 624 (1024 - 400) bits of p are known:
    unknown_bits = 400
    b = 2**unknown_bits
    p0 = (p >> unknown_bits) << unknown_bits
    f = sympy.Poly(p0 + x, modulus=n)
    rx = small_roots.univariate_modp(f, b)
    self.assertEqual(p0 + rx, p)

    # With less known bits the factorization fails:
    unknown_bits = 480
    b = 2**unknown_bits
    p0 = (p >> unknown_bits) << unknown_bits
    f = sympy.Poly(p0 + x, modulus=n)
    rx = small_roots.univariate_modp(f, b)
    self.assertIsNone(rx)

    # By increasing the size of the lattice, we are still able to factor when up
    # to half of the bits are known:
    rx = small_roots.univariate_modp(f, b, k=9)
    self.assertEqual(p0 + rx, p)

  def testUnivariateNegativeRoot(self):
    x = sympy.Symbol("x")
    unknown_bits = 400
    b = 2**unknown_bits
    rx = random.randint(1, b)
    p0 = p + rx
    f = sympy.Poly(p0 - x, modulus=n)
    rx = small_roots.univariate_modp(f, b)
    self.assertEqual(p0 - rx, p)

  def testUnivariateLowBits(self):
    x = sympy.Symbol("x")
    unknown_bits = 400
    b = 2**unknown_bits
    l = p.bit_length() - unknown_bits
    p0 = p % 2**l
    f = sympy.Poly(x * 2**l + p0, modulus=n)
    rx = small_roots.univariate_modp(f, b)
    self.assertEqual(rx * 2**l + p0, p)

  def testUnivariateHigherDegree(self):
    x = sympy.Symbol("x")
    unknown_bits = 128
    b = 2**unknown_bits
    rx = random.randint(1, b)
    p0 = p - rx**3
    f = sympy.Poly(p0 + x**3, modulus=n)
    rx = small_roots.univariate_modp(f, b)
    self.assertEqual(p0 + rx**3, p)

  def testBivariateModp(self):
    x1, x2 = sympy.symbols("x1, x2")

    # p = x1||known||x2
    def bivariate_helper(unknown_bits, m=4):
      unknown_bits_x1, unknown_bits_x2 = unknown_bits
      b1, b2 = 2**unknown_bits_x1, 2**unknown_bits_x2
      known_bits = p.bit_length() - unknown_bits_x1 - unknown_bits_x2
      lx1 = known_bits + unknown_bits_x2
      lk = unknown_bits_x2
      lx2 = 0
      positions = [lx1, lk, lx2]
      p0 = ((p >> lk) % 2**known_bits) << lk
      f = sympy.Poly(p0 + x1 * 2**lx1 + x2, modulus=n)
      roots = small_roots.multivariate_modp(f, [b1, b2], m)
      return roots, positions, p0

    # Even using a small lattice (default m = 4), we are able to factorize when
    # 784 (1024 - 120 - 120) bits of p are known:
    roots, positions, p0 = bivariate_helper([120, 120])
    rx1, rx2 = roots
    lx1, _, _ = positions
    self.assertEqual(p0 + rx1 * 2**lx1 + rx2, p)
    # Testing with unbalanced bounds:
    roots, positions, p0 = bivariate_helper([232, 16])
    rx1, rx2 = roots
    lx1, _, _ = positions
    self.assertEqual(p0 + rx1 * 2**lx1 + rx2, p)
    # With less known bits, 768, the factorization fails:
    roots, positions, p0 = bivariate_helper([130, 130])
    self.assertIsNone(roots)
    # But we are still able to factorize it using a larger lattice:
    roots, positions, p0 = bivariate_helper([130, 130], m=5)
    rx1, rx2 = roots
    lx1, _, _ = positions
    self.assertEqual(p0 + rx1 * 2**lx1 + rx2, p)
    # Below is just a regression test, as the resulting lattice has some 0's
    # on its diagonal.
    roots, positions, p0 = bivariate_helper([128, 128], m=6)
    rx1, rx2 = roots
    lx1, _, _ = positions
    self.assertEqual(p0 + rx1 * 2**lx1 + rx2, p)

  def testTrivariateModp(self):
    x1, x2, x3 = sympy.symbols("x1, x2, x3")

    # p = x1||known1||x2||known2||x3
    def trivariate_helper(unknown_bits, m=4):
      unknown_bits_x1, unknown_bits_x2, unknown_bits_x3 = unknown_bits
      b1, b2, b3 = 2**unknown_bits_x1, 2**unknown_bits_x2, 2**unknown_bits_x3
      known_bits = p.bit_length(
      ) - unknown_bits_x1 - unknown_bits_x2 - unknown_bits_x3
      known_bits1 = known_bits // 2
      known_bits2 = known_bits // 2
      lx1 = known_bits1 + unknown_bits_x2 + known_bits2 + unknown_bits_x3
      lk1 = unknown_bits_x2 + known_bits2 + unknown_bits_x3
      lx2 = known_bits2 + unknown_bits_x3
      lk2 = unknown_bits_x3
      lx3 = 0
      positions = [lx1, lk1, lx2, lk2, lx3]
      p0 = ((p >> lk1) % 2**known_bits2) << lk1
      p0 += ((p >> lk2) % 2**known_bits1) << lk2
      f = sympy.Poly(p0 + x1 * 2**lx1 + x2 * 2**lx2 + x3, modulus=n)
      roots = small_roots.multivariate_modp(f, [b1, b2, b3], m)
      return roots, positions, p0

    # Testing with 880 (1024 - 48 - 48 -48) known bits:
    roots, positions, p0 = trivariate_helper([48, 48, 48])
    rx1, rx2, rx3 = roots
    lx1, _, lx2, _, _ = positions
    self.assertEqual(p0 + rx1 * 2**lx1 + rx2 * 2**lx2 + rx3, p)

    # Testing with unbalanced bounds:
    roots, positions, p0 = trivariate_helper([112, 16, 16])
    rx1, rx2, rx3 = roots
    lx1, _, lx2, _, _ = positions
    self.assertEqual(p0 + rx1 * 2**lx1 + rx2 * 2**lx2 + rx3, p)

  def testBivariateModn(self):
    x1, x2 = sympy.symbols("x1, x2")

    def bivariate_helper(unknown_bits, m=1):
      unknown_bits_x1, unknown_bits_x2 = unknown_bits
      b1, b2 = 2**unknown_bits_x1, 2**unknown_bits_x2
      p0 = (p >> unknown_bits_x1) << unknown_bits_x1
      q0 = (n // p >> unknown_bits_x2) << unknown_bits_x2
      f = sympy.Poly((p0 + x1) * (q0 + x2), modulus=n)
      roots = small_roots.multivariate_modn(f, [b1, b2], m)
      return roots, p0, q0

    # Even using a small lattice (default m = 1), we are able to factorize.
    roots, p0, q0 = bivariate_helper([340, 340])
    rx1, rx2 = roots
    self.assertEqual((p0 + rx1) * (q0 + rx2), n)
    # Testing with unbalanced bounds:
    roots, p0, q0 = bivariate_helper([820, 100])
    rx1, rx2 = roots
    self.assertEqual((p0 + rx1) * (q0 + rx2), n)
    # With less known bits the factorization fails:
    roots, _, _ = bivariate_helper([400, 400])
    self.assertIsNone(roots)
    # By increasing the size of the lattice, we are able to factor:
    roots, p0, q0 = bivariate_helper([400, 400], m=2)
    rx1, rx2 = roots
    self.assertEqual((p0 + rx1) * (q0 + rx2), n)

  def testBivariateModnHigherDegree(self):
    x1, x2 = sympy.symbols("x1, x2")
    unknown_bits_x1, unknown_bits_x2 = 128, 128
    b1, b2 = 2**unknown_bits_x1, 2**unknown_bits_x2
    rx1, rx2 = random.randint(1, b1), random.randint(1, b2)
    p0 = p - rx1**2
    q0 = n // p - rx2**3
    f = sympy.Poly((p0 + x1**2) * (q0 + x2**3), modulus=n)
    rx1, rx2 = small_roots.multivariate_modn(f, [b1, b2])
    self.assertEqual((p0 + rx1**2) * (q0 + rx2**3), n)


if __name__ == "__main__":
  absltest.main()
