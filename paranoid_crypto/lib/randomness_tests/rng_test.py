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
    self.assertEqual(
        0xC8F3374F0A636C707E324DDC0486F8A1CAC5F01C,
        rng.Shake128().RandomBits(160, seed=123456),
    )
    self.assertEqual(
        0x6B3CCA5933CE20, rng.Shake128().RandomBits(55, seed=0xABCDEF)
    )

  def testMt19937(self):
    """Regression test.

    The sole purpose of this test is to detect changes in the python module
    random. random currently uses a Merseene twister with 19937 bits of state.
    There is of course no guarantee that python continues to use this
    pseudorandom number generator.
    """
    self.assertEqual(
        0xCB47D804530BCE3D9460, rng.Mt19937().RandomBits(80, seed=123456)
    )

  def testTruncLcg(self):
    """Regression test."""

    self.assertEqual(
        0x61BD2B29909C8E52, rng.TruncLcgRand(16).RandomBits(63, seed=123456)
    )
    self.assertEqual(
        0xA3A607D44D04A862, rng.TruncLcgRand(20).RandomBits(63, seed=123456)
    )
    self.assertEqual(
        0xA5EC19808421926, rng.TruncLcgRand(28).RandomBits(63, seed=123456)
    )
    self.assertEqual(
        0xCB8975DC5D19C51C, rng.TruncLcgRand(32).RandomBits(63, seed=123456)
    )
    self.assertEqual(
        0x567EE71B6DE6B032, rng.TruncLcgRand(64).RandomBits(63, seed=123456)
    )
    self.assertEqual(
        0xCC314CF91CC12913, rng.TruncLcgRand(128).RandomBits(63, seed=123456)
    )

  def testJavaRandom(self):
    """Compares the implementation with output from java.util.random."""
    expected = [
        0,
        0xFFFB,
        0x4FFFB5CF5,
        0xCFFFB5CF57358,
        0x1CFFFB5CF573588FF9,
        0x1CFFFB5CF573588FF904B2,
        0x1CFFFB5CF573588FF904B225B2,
        0x1CFFFB5CF573588FF904B225B2C3AB,
        0xFFFB5CF573588FF904B225B2C3AB76FAA1,
        0xFFFB5CF573588FF904B225B2C3AB76FAA1DD3C,
        0x4FFFB5CF573588FF904B225B2C3AB76FAA1DD3C916E,
        0xCFFFB5CF573588FF904B225B2C3AB76FAA1DD3C916E80D5,
        0x1CFFFB5CF573588FF904B225B2C3AB76FAA1DD3C916E80D5DC77,
        0x1CFFFB5CF573588FF904B225B2C3AB76FAA1DD3C916E80D5DC770F55,
        0x1CFFFB5CF573588FF904B225B2C3AB76FAA1DD3C916E80D5DC770F555453,
    ]

    for i, val in enumerate(expected):
      computed = rng.JavaRandom().RandomBits(i * 17 + 1, seed=0x123456789ABD)
      self.assertEqual(val, computed)

  def testLcgNist(self):
    """Regression test."""

    self.assertEqual(
        0xE188F824E2F099626E91B7FF11B5FDFE1FAF1422,
        rng.LcgNist().RandomBits(160, seed=0x0123456),
    )

  def testXorShift128plus(self):
    """Regression test."""

    self.assertEqual(
        0x333A495B2B503B50A3C8F042002468ACF4D2A660,
        rng.XorShift128plus().RandomBits(160, seed=0x012345678ABCDEF),
    )

  def testXorShiftStar(self):
    """Regression test."""

    self.assertEqual(
        0x12E8FF6895348EC343D28DADE786D9E2B304BBA0,
        rng.XorShiftStar().RandomBits(160, seed=0x012345678ABCDEF),
    )

  def testXorwow(self):
    """Regression test."""

    self.assertEqual(
        0xE149F7EEB555653EE50F1BA9D36BAAB4F217131F,
        rng.Xorwow().RandomBits(160, seed=0x012345678ABCDEF),
    )

  def testPcg64(self):
    """Regression test."""

    self.assertEqual(
        0xD6D4F1D8380B2C570C609A1321E50190F3B7B142,
        rng.Pcg64().RandomBits(160, seed=0x012345678ABCDEF),
    )

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

    self.assertEqual(
        0xE87DBA10D9F9D6FF35934F8C5BD85EEAEB4E1C12,
        rng.Philox().RandomBits(160, seed=0x012345678ABCDEF),
    )

  def testSfc64(self):
    """Regression test."""

    self.assertEqual(
        0x81E0F5FD864A75C6300282602ED9594F3BCEF03D,
        rng.Sfc64().RandomBits(160, seed=0x012345678ABCDEF),
    )

  def testMwc(self):
    """Regression test."""

    self.assertEqual(
        0xC5C2DFFCEF49F52EAA40F50ACB3C4D5E3E091D46,
        rng.GetRng('mwc64').RandomBits(160, seed=0x012345678ABCDEF),
    )
    self.assertEqual(
        0xF46FDCEC16C16C1406C197C16C16C16C16C197F0,
        rng.GetRng('mwc128').RandomBits(
            160, seed=0x012345678ABCDEF0123456789ABCDEF
        ),
    )
    self.assertEqual(
        int(
            '579c359b7071efead74320feb68989c854320feb'
            '68989cadd74320feb68989c854320feb68989cae',
            16,
        ),
        rng.GetRng('mwc256').RandomBits(
            320, seed=0x012345678ABCDEF012345678ABCDEF * (1 + 2**128)
        ),
    )
    self.assertEqual(
        int(
            '0d2f517395b7d9fc1e40627f01d8c5fc'
            '620fedc935767b7320fedc935767b9a8'
            '97867564534231200efdecdbcabc1ccd'
            '620fedc935767b7320fedc935767b9a8'
            '97867564534231200efdecdbcabc1cd0',
            16,
        ),
        rng.GetRng('mwc512').RandomBits(
            640,
            seed=0x012345678ABCDEF012345678ABCDEF00112233445566778899AABBCCDDEEFF
            * (1 + 2**256),
        ),
    )


if __name__ == '__main__':
  absltest.main()
