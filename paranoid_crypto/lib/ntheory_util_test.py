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
"""Tests for paranoid_crypto.lib.ntheory_util.py."""

import random
from absl.testing import absltest
from paranoid_crypto.lib import ntheory_util


class NTheoryUtilTest(absltest.TestCase):

  def testInverse2exp(self):
    for i in range(1, 257):
      x = random.getrandbits(i) | 1
      a = ntheory_util.Inverse2exp(x, i)
      self.assertEqual(a * x % 2**i, 1)  # pyrefly: ignore[unsupported-operation]

  def testInverseSqrt2exp(self):
    for i in range(1, 257):
      x = random.getrandbits(i)
      # Ensures that x % 8 == 1, otherwise there is no inverse.
      x -= x % 8
      x += 1
      a = ntheory_util.InverseSqrt2exp(x, i)
      self.assertEqual(a * a * x % 2**i, 1)  # pyrefly: ignore[unsupported-operation]

  def testSqrt2exp(self):
    for i in range(1, 257):
      x = random.getrandbits(i)
      # Ensures that x % 8 == 1, otherwise there is no square root.
      x -= x % 8
      x += 1
      roots = ntheory_util.Sqrt2exp(x, i)
      if i >= 3:
        self.assertLen(set(roots), 4)
      for r in roots:
        self.assertEqual(x, r * r % 2**i)

  def testSieve(self):
    self.assertEmpty(ntheory_util.Sieve(0))
    self.assertEmpty(ntheory_util.Sieve(1))
    self.assertEmpty(ntheory_util.Sieve(2))
    self.assertEqual(ntheory_util.Sieve(3), [2])
    self.assertEqual(ntheory_util.Sieve(4), [2, 3])
    self.assertEqual(ntheory_util.Sieve(5), [2, 3])

  def testBalancedDigits(self):
    self.assertEqual(ntheory_util.BalancedDigits(0, 8), [])
    self.assertEqual(ntheory_util.BalancedDigits(1, 4), [1])
    self.assertEqual(ntheory_util.BalancedDigits(-1, 4), [-1])
    self.assertEqual(ntheory_util.BalancedDigits(8, 4), [-8, 1])
    self.assertEqual(ntheory_util.BalancedDigits(-8, 4), [-8])
    with self.assertRaises(ValueError):
      ntheory_util.BalancedDigits(5, 1)

    rng = random.Random(12345)
    for w in (2, 3, 8, 16, 32, 64, 128):
      half = 1 << (w - 1)
      for sign in (1, -1):
        val = sign * rng.getrandbits(512)
        digits = ntheory_util.BalancedDigits(val, w)
        if val != 0:
          self.assertNotEqual(digits[-1], 0)
        for d in digits:
          self.assertGreaterEqual(d, -half)
          self.assertLess(d, half)
        reconstructed = sum(d << (i * w) for i, d in enumerate(digits))
        self.assertEqual(reconstructed, val)


if __name__ == '__main__':
  absltest.main()
