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

from absl.testing import absltest
import numpy
from numpy import random as numpy_random
from paranoid_crypto.lib.randomness_tests import rng


class RngTest(absltest.TestCase):

  def testShake128(self):
    """Regression test."""
    self.assertEqual(0xc8f3374f0a636c707e324ddc0486f8a1cac5f01c,
                     rng.Shake128().RandomBits(160, seed=123456))
    self.assertEqual(0x6b3cca5933ce20,
                     rng.Shake128().RandomBits(55, seed=0xabcdef))

  def testMt19937(self):
    """Regression test.

    The sole purpose of this test is to detect changes in the python module
    random. random currently uses a Merseene twister with 19937 bits of state.
    There is of course no guarantee that python continues to use this
    pseudorandom number generator.
    """
    self.assertEqual(0xcb47d804530bce3d9460,
                     rng.Mt19937().RandomBits(80, seed=123456))

  def testGmp(self):
    """Regression test.

    The sole purpose of this test is to detect changes in gmpy.rand, so that
    other unit tests based on the weaknesses of gmpy.rand can be adjusted.
    """
    self.assertEqual(0x43eca180f7892ceb,
                     rng.GmpRand(16).RandomBits(63, seed=123456))
    self.assertEqual(0x7bd2b404e4b92216,
                     rng.GmpRand(20).RandomBits(63, seed=123456))
    self.assertEqual(0x1759df573d27d9be,
                     rng.GmpRand(28).RandomBits(63, seed=123456))
    self.assertEqual(0x2af9a4aca4686baf,
                     rng.GmpRand(32).RandomBits(63, seed=123456))
    self.assertEqual(0x2cf869f9ae314763,
                     rng.GmpRand(64).RandomBits(63, seed=123456))
    self.assertEqual(0x66af6d53fe71fa68,
                     rng.GmpRand(128).RandomBits(63, seed=123456))

  def testJavaRandom(self):
    """Compares the implementation with output from java.util.random."""
    expected = [
        0, 0xfffb, 0x4fffb5cf5, 0xcfffb5cf57358, 0x1cfffb5cf573588ff9,
        0x1cfffb5cf573588ff904b2, 0x1cfffb5cf573588ff904b225b2,
        0x1cfffb5cf573588ff904b225b2c3ab, 0xfffb5cf573588ff904b225b2c3ab76faa1,
        0xfffb5cf573588ff904b225b2c3ab76faa1dd3c,
        0x4fffb5cf573588ff904b225b2c3ab76faa1dd3c916e,
        0xcfffb5cf573588ff904b225b2c3ab76faa1dd3c916e80d5,
        0x1cfffb5cf573588ff904b225b2c3ab76faa1dd3c916e80d5dc77,
        0x1cfffb5cf573588ff904b225b2c3ab76faa1dd3c916e80d5dc770f55,
        0x1cfffb5cf573588ff904b225b2c3ab76faa1dd3c916e80d5dc770f555453
    ]

    for i, val in enumerate(expected):
      computed = rng.JavaRandom().RandomBits(i * 17 + 1, seed=0x123456789abd)
      self.assertEqual(val, computed)

  def testLcgNist(self):
    """Regression test."""

    self.assertEqual(0xe188f824e2f099626e91b7ff11b5fdfe1faf1422,
                     rng.LcgNist().RandomBits(160, seed=0x0123456))

  def testXorShift128plus(self):
    """Regression test."""

    self.assertEqual(
        0x333a495b2b503b50a3c8f042002468acf4d2a660,
        rng.XorShift128plus().RandomBits(160, seed=0x012345678abcdef))

  def testXorShiftStar(self):
    """Regression test."""

    self.assertEqual(0x12e8ff6895348ec343d28dade786d9e2b304bba0,
                     rng.XorShiftStar().RandomBits(160, seed=0x012345678abcdef))

  def testXorwow(self):
    """Regression test."""

    self.assertEqual(0xe149f7eeb555653ee50f1ba9d36baab4f217131f,
                     rng.Xorwow().RandomBits(160, seed=0x012345678abcdef))

  def testPcg64(self):
    """Regression test."""

    self.assertEqual(0xd6d4f1d8380b2c570c609a1321e50190f3b7b142,
                     rng.Pcg64().RandomBits(160, seed=0x012345678abcdef))

  def testPcg64ByteOrder(self):
    """Checks that the implementation uses the correct byte order.

    The implementation in the module rng uses the method
    numpy.random.BitGenerator.bytes() to generate random bits.
    This test ensures that the byte order is the same as if the method
    numpy.random.BitGenerator.integers() were used.
    """
    seed = 12345
    size = 4
    rand = numpy_random.Generator(numpy_random.PCG64(seed=seed))
    sample = rand.integers(low=0, high=2**64, dtype=numpy.uint64, size=size)
    expected = sum(int(x) << (64 * i) for i, x in enumerate(sample))
    computed = rng.Pcg64().RandomBits(64 * size, seed=seed)
    self.assertEqual(expected, computed)

  def testPhilox(self):
    """Regression test."""

    self.assertEqual(0xe87dba10d9f9d6ff35934f8c5bd85eeaeb4e1c12,
                     rng.Philox().RandomBits(160, seed=0x012345678abcdef))

  def testSfc64(self):
    """Regression test."""

    self.assertEqual(0x81e0f5fd864a75c6300282602ed9594f3bcef03d,
                     rng.Sfc64().RandomBits(160, seed=0x012345678abcdef))

  def testMwc(self):
    """Regression test."""

    self.assertEqual(
        0xc5c2dffcef49f52eaa40f50acb3c4d5e3e091d46,
        rng.GetRng('mwc64').RandomBits(160, seed=0x012345678abcdef))
    self.assertEqual(
        0xf46fdcec16c16c1406c197c16c16c16c16c197f0,
        rng.GetRng('mwc128').RandomBits(
            160, seed=0x012345678abcdef0123456789abcdef))
    self.assertEqual(
        int(
            '579c359b7071efead74320feb68989c854320feb'
            '68989cadd74320feb68989c854320feb68989cae', 16),
        rng.GetRng('mwc256').RandomBits(
            320, seed=0x012345678abcdef012345678abcdef * (1 + 2**128)))
    self.assertEqual(
        int(
            '0d2f517395b7d9fc1e40627f01d8c5fc'
            '620fedc935767b7320fedc935767b9a8'
            '97867564534231200efdecdbcabc1ccd'
            '620fedc935767b7320fedc935767b9a8'
            '97867564534231200efdecdbcabc1cd0', 16),
        rng.GetRng('mwc512').RandomBits(
            640,
            seed=0x012345678abcdef012345678abcdef00112233445566778899aabbccddeeff
            * (1 + 2**256)))


if __name__ == '__main__':
  absltest.main()
