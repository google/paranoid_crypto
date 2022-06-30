"""Tests for paranoid_crypto.lib.ntheory_util.py."""

import random
from absl.testing import absltest
from paranoid_crypto.lib import ntheory_util


class NTheoryUtilTest(absltest.TestCase):

  def testInverse2exp(self):
    for i in range(1, 257):
      x = random.getrandbits(i) | 1
      a = ntheory_util.Inverse2exp(x, i)
      self.assertEqual(a * x % 2**i, 1)

  def testInverseSqrt2exp(self):
    for i in range(1, 257):
      x = random.getrandbits(i)
      # Ensures that x % 8 == 1, otherwise there is no inverse.
      x -= x % 8
      x += 1
      a = ntheory_util.InverseSqrt2exp(x, i)
      self.assertEqual(a * a * x % 2**i, 1)

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


if __name__ == '__main__':
  absltest.main()
