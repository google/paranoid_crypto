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

import collections
import os
from absl.testing import absltest
from paranoid_crypto.lib.randomness_tests import exp1
from paranoid_crypto.lib.randomness_tests import util


class UtilTest(absltest.TestCase):

  def testBitCount(self):
    self.assertEqual(0, util.BitCount(0))
    self.assertEqual(1, util.BitCount(1))
    self.assertEqual(3, util.BitCount(25))
    self.assertEqual(1, util.BitCount(2**64))
    self.assertEqual(123, util.BitCount(2**123 - 1))
    self.assertEqual(1024, sum(util.BitCount(i) for i in range(256)))

  def testBitCountExp1(self):
    size = 1000000
    bits = exp1.bits(size)
    # NIST SP 800-22, section 2.11.8
    self.assertEqual(500029, util.BitCount(bits))

  def testReverseBits(self):
    bit_string = "10010100010100100010100011111111011010011111010101011000000"
    for size in range(1, len(bit_string) + 1):
      x = int(bit_string[:size], 2)
      x_reversed = int(bit_string[:size][::-1], 2)
      self.assertEqual(x_reversed, util.ReverseBits(x, size))

  def testBits(self):
    bits = 0b11010110000
    # Note, the lsb of bits is element 0 of the result.
    self.assertEqual([-1, -1, -1, -1, 1, 1, -1, 1, -1, 1, 1],
                     list(util.Bits(bits, 11)))
    # Same as above with leading 0 bits.
    self.assertEqual([-1, -1, -1, -1, 1, 1, -1, 1, -1, 1, 1, -1, -1, -1, -1],
                     list(util.Bits(bits, 15)))

  def testScatter(self):
    self.assertEqual([1, 1, 0, 0], util.Scatter(0b11, 4))
    self.assertEqual([0b10111, 0b0], util.Scatter(0b100010101, 2))
    self.assertEqual([0b11, 0b111111, 0b1111],
                     util.Scatter(0b010010110110111111, 3))
    self.assertEqual([0b11111, 0b1111, 0b111, 0b11, 0b1],
                     util.Scatter(0b100011001110111111111, 5))
    self.assertEqual([0b1, 0b11, 0b111, 0b1111, 0b11111],
                     util.Scatter(0b1000011000111001111011111, 5))

  def testNormalCdf(self):
    self.assertAlmostEqual(0.5, util.NormalCdf(1.0, 1.0, 1.0))
    self.assertAlmostEqual(0.841344746, util.NormalCdf(2.0, 1.0, 1.0))
    self.assertAlmostEqual(0.841344746, util.NormalCdf(20.0, 10.0, 100.0))
    self.assertAlmostEqual(0.158655, util.NormalCdf(-1.0, 0.0, 1.0), delta=1e-6)
    self.assertAlmostEqual(0.993790, util.NormalCdf(2.5, 0.0, 1.0), delta=1e-6)
    self.assertAlmostEqual(0.993790, util.NormalCdf(7.5, 2.5, 4.0), delta=1e-6)

  def testBinomialCdf(self):
    self.assertAlmostEqual(1.0, util.BinomialCdf(5, 5))
    self.assertAlmostEqual(1 / 32, util.BinomialCdf(0, 5))
    self.assertAlmostEqual(1 / 2, util.BinomialCdf(5, 11))
    self.assertAlmostEqual(1013 / 1024, util.BinomialCdf(8, 10))
    # Compares approximations against results computed with sums.
    self.assertAlmostEqual(0.698297, util.BinomialCdf(154, 300), delta=1e-3)
    self.assertAlmostEqual(0.984286, util.BinomialCdf(221, 400), delta=1e-4)
    self.assertAlmostEqual(0.265851, util.BinomialCdf(243, 501), delta=1e-4)

  def testUniformSumCdf(self):
    # The test results were obtained by using the formulo from
    # wikipedia and decimal.Decimal with 50 digits precision.
    self.assertAlmostEqual(0.0, util.UniformSumCdf(5, 0.0))
    self.assertAlmostEqual(1.0, util.UniformSumCdf(5, 5.0))
    self.assertAlmostEqual(0.765432, util.UniformSumCdf(1, 0.765432))
    self.assertAlmostEqual(0.5, util.UniformSumCdf(20, 10.0))
    self.assertAlmostEqual(0.079092, util.UniformSumCdf(24, 10.0), delta=1e-6)
    self.assertAlmostEqual(
        0.046647, util.UniformSumCdf(30, 12.3456), delta=1e-6)
    self.assertAlmostEqual(0.725947, util.UniformSumCdf(33, 17.5), delta=1e-6)
    self.assertAlmostEqual(0.094689, util.UniformSumCdf(40, 17.6), delta=1e-3)
    self.assertAlmostEqual(0.401590, util.UniformSumCdf(48, 23.5), delta=1e-3)
    self.assertAlmostEqual(0.5, util.UniformSumCdf(51, 25.5), delta=1e-3)
    self.assertAlmostEqual(0.242262, util.UniformSumCdf(55, 26), delta=1e-3)
    self.assertAlmostEqual(0.122883, util.UniformSumCdf(80, 37), delta=1e-3)
    self.assertAlmostEqual(0.5, util.UniformSumCdf(101, 50.5), delta=1e-3)

  def testCombinedPValue(self):
    x = 0.324523  # arbitrary value
    self.assertAlmostEqual(x, util.CombinedPValue([x]))
    self.assertAlmostEqual(0, util.CombinedPValue([0, x]))
    self.assertAlmostEqual(1.0, util.CombinedPValue([1.0, 1.0]), delta=1e-6)
    self.assertAlmostEqual(
        0.835315, util.CombinedPValue([0.782334, 0.618821]), delta=1e-6)
    self.assertAlmostEqual(
        0.051865,
        util.CombinedPValue([0.125421, 0.123541, 0.125134]),
        delta=1e-6)
    # Fisher's method is sentitive to low p-values and not very sentitive to
    # large p-values.
    self.assertAlmostEqual(
        4.25785e-07,
        util.CombinedPValue([0.000001, 0.0002, 0.9999, 1.0]),
        delta=1e-6)
    # A uniform distribution should not return a low p-value.
    self.assertAlmostEqual(
        0.603512,
        util.CombinedPValue([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]),
        delta=1e-6)
    # The implementation should be able to handle a large number of p-values.
    self.assertAlmostEqual(
        0.538353,
        util.CombinedPValue([0.001 * i for i in range(1, 1000)]),
        delta=1e-6)

  def testSubSequencesWrap(self):
    x = 0b11010110000
    a = list(util.SubSequences(x, 11, 4, wrap=True))
    self.assertCountEqual([
        0b1101, 0b1010, 0b0101, 0b1011, 0b0110, 0b1100, 0b1000, 0b0000, 0b0001,
        0b0011, 0b0110
    ], a)

  def testSubSequencesNoWrap(self):
    x1 = 0b11010110000
    a1 = list(util.SubSequences(x1, 11, 4, wrap=False))
    self.assertCountEqual(
        [0b1101, 0b1010, 0b0101, 0b1011, 0b0110, 0b1100, 0b1000, 0b0000], a1)
    x2 = 0b1011001111101111
    a2 = list(util.SubSequences(x2, 16, 8, wrap=False))
    self.assertCountEqual([
        0b10110011, 0b01100111, 0b11001111, 0b10011111, 0b00111110, 0b01111101,
        0b11111011, 0b11110111, 0b11101111
    ], a2)

  def testSubSequencesExp1(self):
    size = 1000000
    bits = exp1.bits(size)
    # NIST SP 800-22, section 2.11.8
    c_wrap = collections.Counter(util.SubSequences(bits, size, 2, wrap=True))
    c_nowrap = collections.Counter(util.SubSequences(bits, size, 2, wrap=False))
    expected_wrap = {0b00: 250116, 0b01: 249855, 0b10: 249855, 0b11: 250174}
    expected_nowrap = {0b00: 250116, 0b01: 249855, 0b10: 249854, 0b11: 250174}
    self.assertEqual(expected_wrap, c_wrap)
    self.assertEqual(expected_nowrap, c_nowrap)

  def testSubSequencesCount(self):
    for m in range(2, 10):
      sub_sequence = (1 << m) - 1
      for length in range(m, 30):
        bits = (1 << length) - 1
        c_wrap = list(util.SubSequences(bits, length, m))
        self.assertEqual([sub_sequence] * length, c_wrap)
        c_nowrap = list(util.SubSequences(bits, length, m, wrap=False))
        self.assertEqual([sub_sequence] * (length - m + 1), c_nowrap)

  def testFrequencyCount(self):
    bit_string = ("11110111010100100010100011111111011101111010101001010100011"
                  "10010100010111111110101010101111111111001111111111111111111"
                  "10101001000101010111010000001111010101010101001010001000111"
                  "01100101010100011101010101000100010101000000000111010101000"
                  "11010100101010000010010101010000100000000110000000011111111")
    for length in range(len(bit_string) - 15, len(bit_string) + 1):
      seq = int(bit_string[:length], 2)
      for size in range(2, 18):
        count0 = [0] * 2**size
        for x in util.SubSequences(seq, length, size):
          count0[x] += 1
        count1 = util.FrequencyCount(seq, length, size)
        self.assertEqual(count0, count1)

  def testFrequencyCountNoWrap(self):
    bit_string = ("11110111010100100010100011111111011101111010101001010100011"
                  "10010100010111111110101010101111111111001111111111111111111"
                  "10101001000101010111010000001111010101010101001010001000111"
                  "01100101010100011101010101000100010101000000000111010101000"
                  "11010100101010000010010101010000100000000110000000011111111")
    for length in range(len(bit_string) - 15, len(bit_string) + 1):
      seq = int(bit_string[:length], 2)
      for size in range(2, 18):
        count0 = [0] * 2**size
        for x in util.SubSequences(seq, length, size, wrap=False):
          count0[x] += 1
        count1 = util.FrequencyCount(seq, length, size, wrap=False)
        self.assertEqual(count0, count1)

  def testFrequencyCountExp1(self):
    size = 1000000
    bits = exp1.bits(size)
    count2 = util.FrequencyCount(bits, size, 2)
    # NIST SP 800-22, section 2.11.8
    expected2 = [250116, 249855, 249855, 250174]
    self.assertEqual(expected2, count2)
    count3 = util.FrequencyCount(bits, size, 3)
    expected3 = [124911, 125205, 124965, 124890, 125205, 124650, 124890, 125284]
    self.assertEqual(expected3, count3)

  def testSplitSequence(self):
    bit_string = ("11110111010100100010100011111111011101111010101001010100011"
                  "10010100010111111110101010101111111111001111111111111111111")
    seq = int(bit_string, 2)
    for size in range(3, 17):
      n = len(bit_string) // size
      expected = [(seq >> (i * size)) % 2**size for i in range(n)]
      res = util.SplitSequence(seq, len(bit_string), size)
      self.assertEqual(expected, res)

  def testRuns(self):
    self.assertEqual(1, util.Runs(0, 16))
    self.assertEqual(1, util.Runs(0xffff, 16))
    self.assertEqual(16, util.Runs(0x5555, 16))
    self.assertEqual(16, util.Runs(0xaaaa, 16))
    self.assertEqual(7, util.Runs(0b10110001011, 11))

  def testLongestRunOfOnes(self):
    self.assertEqual(0, util.LongestRunOfOnes(0))
    self.assertEqual(1, util.LongestRunOfOnes(0b1010101001010100))
    self.assertEqual(4, util.LongestRunOfOnes(0b0100111101011001))
    self.assertEqual(5, util.LongestRunOfOnes(0b0100111101011111))
    self.assertEqual(6, util.LongestRunOfOnes(0b1111110100111101))
    self.assertEqual(17, util.LongestRunOfOnes(0b11111111111111111))

  def testOverlappingRunsOfOnes(self):
    self.assertEqual(15, util.OverlappingRunsOfOnes(0b1011011101111011111, 1))
    self.assertEqual(10, util.OverlappingRunsOfOnes(0b1011011101111011111, 2))
    self.assertEqual(6, util.OverlappingRunsOfOnes(0b1011011101111011111, 3))
    self.assertEqual(3, util.OverlappingRunsOfOnes(0b1011011101111011111, 4))
    self.assertEqual(1, util.OverlappingRunsOfOnes(0b1011011101111011111, 5))
    self.assertEqual(0, util.OverlappingRunsOfOnes(0b1011011101111011111, 6))

  def testOverlappingRunsOfOnesExp1(self):
    size = 1000000
    bits = exp1.bits(size)
    self.assertEqual(500029, util.OverlappingRunsOfOnes(bits, 1))
    self.assertEqual(250174, util.OverlappingRunsOfOnes(bits, 2))
    self.assertEqual(125284, util.OverlappingRunsOfOnes(bits, 3))
    self.assertEqual(62752, util.OverlappingRunsOfOnes(bits, 4))
    self.assertEqual(31645, util.OverlappingRunsOfOnes(bits, 5))
    self.assertEqual(16019, util.OverlappingRunsOfOnes(bits, 6))
    self.assertEqual(8094, util.OverlappingRunsOfOnes(bits, 7))
    self.assertEqual(4095, util.OverlappingRunsOfOnes(bits, 8))
    self.assertEqual(2073, util.OverlappingRunsOfOnes(bits, 9))
    self.assertEqual(1032, util.OverlappingRunsOfOnes(bits, 10))

  def testBinaryMatrixRank(self):
    self.assertEqual(0, util.BinaryMatrixRank([0, 0, 0, 0]))
    self.assertEqual(1, util.BinaryMatrixRank([0, 0b1101, 0, 0b1101]))
    self.assertEqual(3, util.BinaryMatrixRank([0b011, 0b101, 0b111]))
    self.assertEqual(
        4, util.BinaryMatrixRank([0b01111, 0b10111, 0b11011, 0b11101, 0b11110]))
    self.assertEqual(4, util.BinaryMatrixRank(list(range(16))))
    self.assertEqual(
        2,
        util.BinaryMatrixRank(
            [0b1010101010101, 0b0101010101010, 0b1111111111111]))

  def testBinaryMatrixRankSmallExp1(self):
    size = 100000
    bits = exp1.bits(size)
    m = 32
    rows = util.SplitSequence(bits, size, m)
    count = collections.defaultdict(int)
    for i in range(len(rows) // m):
      rank = util.BinaryMatrixRank(rows[m * i:m * (i + 1)])
      count[rank] += 1
    # NIST SP 800-22, section 2.5.8
    expected = {30: 14, 31: 60, 32: 23}
    self.assertEqual(expected, count)

  def testBinaryMatrixRankLargeExp1(self):
    size = 100000
    bits = exp1.bits(size)
    m = 100
    rows = util.SplitSequence(bits, size, m)
    count = collections.defaultdict(int)
    for i in range(len(rows) // m):
      rank = util.BinaryMatrixRank(rows[m * i:m * (i + 1)])
      count[rank] += 1
    # Computed with _BinaryMatrixRankSmall
    expected = {99: 3, 100: 6, 98: 1}
    self.assertEqual(expected, count)

  def testBinaryMatrixRankCompare(self):
    for rows in range(100):
      m = []
      for _ in range(rows):
        m.append(int.from_bytes(os.urandom(rows // 8 + 1), "little"))
      rank1 = util._BinaryMatrixRankSmall(m)
      rank2 = util._BinaryMatrixRankLarge(m)
      self.assertEqual(rank1, rank2)

  def testIgamc(self):
    # Test vectors from NIST SP 800-22
    # Section 2.2.4
    self.assertAlmostEqual(util.Igamc(3 / 2, 1 / 2), 0.801252, delta=1e-6)
    # page 2-9
    self.assertAlmostEqual(
        util.Igamc(3 / 2, 4.882605 / 2), 0.180598, delta=1e-6)
    # page 2-11
    self.assertAlmostEqual(util.Igamc(1, 0.596953 / 2), 0.741948, delta=1e-6)
    # page 2-16
    self.assertAlmostEqual(util.Igamc(1, 2.133333 / 2), 0.344154, delta=1e-6)
    # page 2-37
    self.assertAlmostEqual(
        util.Igamc(5 / 2, 4.333033 / 2), 0.502529, delta=1e-6)

    # Below are possible mistakes in NIST SP 800-22
    # The test vectors below have been independently verified by implementing
    # the algorithm from Numerical Recipies.
    # page 2-19 claims 0.274932
    self.assertAlmostEqual(
        util.Igamc(5 / 2, 3.167729 / 2), 0.674145, delta=1e-6)
    # page 2-28 claims 0.9057
    self.assertAlmostEqual(util.Igamc(2, 1.6 / 2), 0.808792, delta=1e-6)
    # page 2-28 claims 0.8805
    self.assertAlmostEqual(util.Igamc(1, 0.8 / 2), 0.670320, delta=1e-6)
    # page 2-30 claims 0.261961
    self.assertAlmostEqual(util.Igamc(2**2, 0.502193 / 2), 0.999864, delta=1e-6)

    # Underflows
    self.assertAlmostEqual(util.Igamc(1, 1000), 0, delta=1e-20)
    self.assertAlmostEqual(util.Igamc(1.5, 1000), 0, delta=1e-20)

    # Section E-1 of NIST SP 800-22 contains some test vectors for large a
    # and x. The values below would lead to overflow errors if the formula
    # Q(a,x)/Q(x) were used.
    self.assertAlmostEqual(util.Igamc(600, 600), 0.4945710333)
    self.assertAlmostEqual(util.Igamc(800, 800), 0.4952983876)
    self.assertAlmostEqual(util.Igamc(1000, 1000), 0.4957947559)
    self.assertAlmostEqual(util.Igamc(10000, 10000), 0.4986701918)
    self.assertAlmostEqual(util.Igamc(100000, 100000), 0.4995794779)
    self.assertAlmostEqual(util.Igamc(1000000, 1000000), 0.4998670192)

    # The cumulative distribution function of the Erlang distribtuion with rate
    # 1 can be computed as 1 - Igamc(k, x). Hence Igamc(k, x) is equal to
    # the survival function of the Erlang distribution with rate 1.
    self.assertAlmostEqual(util.Igamc(2, 2.5), 0.287297, delta=1e-6)
    self.assertAlmostEqual(util.Igamc(3, 1.7), 0.757223, delta=1e-6)
    self.assertAlmostEqual(util.Igamc(20, 20), 0.470257, delta=1e-6)

  def testDft(self):
    # Example from NIST SP 800-22 Section 2.6.
    # Unfortunately, NIST does not include the result and the subsequent
    # result can not be reproduced.
    # I.e. NIST claims that 4 values of expected[:5] are smaller than 4.75.
    # However, scipy, wolfram alpha and a slow implementation of the definition
    # in Section 3.6 of NIST SP 800-22 give the same result below.
    x = [1, -1, -1, 1, -1, 1, -1, -1, 1, 1]
    expected = [
        0.0, 2.0, 4.472136, 2.0, 4.472136, 2.0, 4.472136, 2.0, 4.472136, 2.0
    ]
    v = util.Dft(x)
    self.assertSequenceAlmostEqual(expected, v, delta=1e-6)


if __name__ == "__main__":
  absltest.main()
