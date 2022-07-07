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
from paranoid_crypto.lib.randomness_tests import exp1
from paranoid_crypto.lib.randomness_tests import nist_suite
from paranoid_crypto.lib.randomness_tests import util


def BitString(bit_string: str) -> int:
  """Converts a bit string given as a string into an integer.

  The examples in NIST SP 800-22 use bit strings where
  bit 0 is printed first. Thus the bit order must be
  reversed when converting such bit strings to integers.

  Args:
    bit_string: the bit string (e.g. "1100101001"), where the left bit is bit 0.

  Returns:
    bit_string converted to an integer
  """
  return int(bit_string[::-1], 2)


def BitStrings(bit_strings: list[str]) -> list[int]:
  return [BitString(s) for s in bit_strings]


class NistSuite(absltest.TestCase):

  def testFrequency(self):
    bits = BitString("1011010101")
    self.assertAlmostEqual(0.527089, nist_suite.Frequency(bits, 10), delta=1e-6)

  def testFrequencyExp1(self):
    """Regression test with 1000000 bits of exp(1).

    NIST SP 800-22 doesn't contain a test with a long input.
    """
    size = 1000000
    bits = exp1.bits(size)
    self.assertAlmostEqual(
        0.953749, nist_suite.Frequency(bits, size), delta=1e-6)

  def testBlockFrequencyImpl(self):
    sample1 = BitStrings(["011", "001", "101"])
    self.assertAlmostEqual(
        0.801252, nist_suite.BlockFrequencyImpl(sample1, 3), delta=1e-6)

    sample2 = BitStrings([
        "1100100100", "0011111101", "1010101000", "1000100001", "0110100011",
        "0000100011", "0100110001", "0011000110", "0110001010", "0010111000"
    ])
    self.assertAlmostEqual(
        0.706438, nist_suite.BlockFrequencyImpl(sample2, 10), delta=1e-6)

  def testBlockFrequencyExp1(self):
    """Regression test with 1000000 bits of exp(1).

    NIST SP 800-22 doesn't contain a test with a long input.
    """
    m = 1024
    size = 1000000
    bits = exp1.bits(size)
    blocks = util.SplitSequence(bits, size, m)
    self.assertAlmostEqual(
        0.384850, nist_suite.BlockFrequencyImpl(blocks, m), delta=1e-6)

  def testRuns(self):
    # Examples from Section 2.3.4 and 2.3.8
    for bit_string, p_value in [
        ("1001101011", 0.147232),
        (("11001001000011111101101010100010001000010110100011"
          "00001000110100110001001100011001100010100010111000"), 0.500798)
    ]:
      bits = BitString(bit_string)
      self.assertAlmostEqual(
          p_value, nist_suite.Runs(bits, len(bit_string)), delta=1e-6)

  def testRunsExp1(self):
    """Regression test with 1000000 bits of exp(1).

    NIST SP 800-22 doesn't contain a test with a long input.
    """
    size = 1000000
    bits = exp1.bits(size)
    self.assertAlmostEqual(0.561916, nist_suite.Runs(bits, size), delta=1e-6)

  def testLongestRuns(self):
    # Example from Section 2.4.4
    # NIST uses only 4 digits of precision for the computation. Hence the
    # p-value given by NIST and the p-value given below differ slightly.
    bit_string = ("11001100000101010110110001001100111000000000001001"
                  "00110101010001000100111101011010000000110101111100"
                  "1100111001101101100010110010")
    bits = BitString(bit_string)
    self.assertAlmostEqual(
        0.180598, nist_suite.LongestRuns(bits, len(bit_string)), delta=1e-6)

  def testRankDistribution(self):
    computed = nist_suite.RankDistribution(32, 32, 3, allow_approximation=False)
    approximation = nist_suite.RankDistribution(
        32, 32, 3, allow_approximation=True)
    for x, y in zip(computed, approximation):
      self.assertAlmostEqual(x, y)
    # NIST SP 800-22 sometimes doesn't state clearly if exact values or
    # approximations are used in their computations. To get some additional
    # confirmation of the rank distribution we performed experiments on 10**8
    # or more random matrices.
    #
    # The following tuple contains values (rows, cols, k, experimental dist.)
    # Matrices of dimension 3*3 and 8*8 are used as examples by NIST, matrices
    # of dimension 6*8 are used by a test from diehard.
    experiments = [
        (3, 3, 2, [0.3281, 0.5742, 0.0977]),
        (6, 8, 3, [0.7731, 0.2175, 0.0093, 0.0001]),
        (8, 8, 3, [0.2899, 0.5775, 0.1274, 0.0052]),
    ]
    for rows, cols, k, measured in experiments:
      computed = nist_suite.RankDistribution(rows, cols, k)
      for x, y in zip(computed, measured):
        self.assertAlmostEqual(x, y, delta=1e-4)

  def testBinaryMatrixRank(self):
    # Example from Section 2.5.4
    # NIST uses values for the distribution of the rank that are correct for
    # large matrices. BinaryMatrixRank recomputes the distribution for matrices
    # with small dimension. Hence, the expected p-value below is different than
    # the value given by NIST.
    bit_string = "010110010010101011"
    bits = BitString(bit_string)
    self.assertAlmostEqual(
        0.820961,
        nist_suite.BinaryMatrixRank(
            bits, len(bit_string), 3, 3, 2, check_size=False),
        delta=1e-6)

  def testBinaryMatrixRankExp1(self):
    # Example from Section 2.5.8
    size = 100000
    bits = exp1.bits(size)
    self.assertAlmostEqual(
        0.532069,
        nist_suite.BinaryMatrixRank(bits, size, 32, 32, 2),
        delta=1e-6)

  def testNonOverlappingTemplateMatching(self):
    # Example from Section 2.7.4
    bit_string = "10100100101110010110"
    bits = BitString(bit_string)
    named_p_values = nist_suite.NonOverlappingTemplateMatching(
        bits, len(bit_string), blocks=2, m=3, templates=[BitString("001")])
    self.assertLen(named_p_values, 1)
    p_value = named_p_values[0][1]
    self.assertAlmostEqual(0.344154, p_value, delta=1e-6)

  def testOverlappingTemplateMatchingDistribution(self):
    # The distribution for the OverlappingTemplateMatching test described
    # by NIST are not very accurate. Our implementation uses a different
    # method to approximate these probabilities. The tests below compare
    # the compute probabilities with results obtained from 10^9 tests.
    # The format is (m, block_size, k, pi).
    # pyformat: disable
    experimental_results = [
        (2, 7, 5,
         [0.265605, 0.296880, 0.226569, 0.124999, 0.062502, 0.023444]),
        (2, 9, 5,
         [0.173810, 0.253906, 0.238288, 0.167985, 0.097647, 0.068365]),
        (2, 10, 5,
         [0.140639, 0.229499, 0.235349, 0.182621, 0.113270, 0.098622]),
        (3, 18, 5,
         [0.251821, 0.230820, 0.188961, 0.134695, 0.086656, 0.107046]),
        (4, 35, 5,
         [0.300125, 0.212536, 0.165604, 0.118438, 0.079562, 0.123733]),
        (5, 68, 5,
         [0.328983, 0.200776, 0.153220, 0.109931, 0.075357, 0.131734]),
        (6, 133, 5,
         [0.345821, 0.193634, 0.146409, 0.105333, 0.072948, 0.135856]),
        (7, 262, 5,
         [0.355497, 0.189442, 0.142646, 0.102771, 0.071611, 0.138031]),
        (8, 519, 5,
         [0.360977, 0.187058, 0.140558, 0.101353, 0.070845, 0.139207]),
        (9, 1032, 5,
         [0.364124, 0.185647, 0.139349, 0.100560, 0.070437, 0.139882]),
        (10, 2057, 5,
         [0.365796, 0.184898, 0.138723, 0.100150, 0.070206, 0.140227]),
        (8, 391, 5,
         [0.465524, 0.181114, 0.124346, 0.083009, 0.054211, 0.091797]),
    ]
    # pyformat: enable
    for m, block_size, k, pi_obs in experimental_results:
      pi = nist_suite.OverlappingTemplateMatchingDistribution(block_size, m, k)
      self.assertSequenceAlmostEqual(pi_obs, pi, delta=1e-4)

  def testOverlappingTemplateMatching(self):
    # Example from Section 2.8.4
    bit_string = ("1011101111"
                  "0010110100"
                  "0111001011"
                  "1011111000"
                  "0101101001")
    bits = BitString(bit_string)
    p_value = nist_suite.OverlappingTemplateMatching(
        bits, len(bit_string), m=2, block_size=10)
    # The expected result below differs from the claim in Section 2.8.4.
    # NIST uses probabilities based on asymptotic computations. I.e.,
    # pi = [0.324652, 0.182617, 0.142670, 0.106645, 0.077147, 0.166268]
    # An experiment with 10^9 random samples gives the following distribution:
    # pi_obs = [0.140639, 0.229499, 0.235349, 0.182621, 0.113270, 0.098622]
    # The probabilities computed by OverlappingTemplateMatchingDistribution are
    # pi = [0.140625, 0.229492, 0.235352, 0.182617, 0.113281, 0.098633]
    self.assertAlmostEqual(0.642474, p_value, delta=1e-6)

  def testOverlappingTemplateMatchingExp1(self):
    # TODO(bleichen): The example from Section 2.8.8 misses some information.
    #   Hence, it is not possible to reproduce the results given by NIST.
    #   In particular, it is not possible to get the same values for v.
    size = 1000000
    bits = exp1.bits(size)
    m = 9
    block_size = 1033
    p_value = nist_suite.OverlappingTemplateMatching(bits, size, m, block_size)
    self.assertAlmostEqual(0.049551, p_value, delta=1e-4)

  def testUniversalDistribution(self):
    """Compares the computed distribution agains experimental data.

    NIST SP 800-22 and "Handbook of applied Cryptography" by Menezes et. al.
    have slightly different formulas for c. The implementation follows NIST
    SP 800-22.
    The relative difference between the two formulas is about 0.1%.
    Hence, it does not influence the test significantly.
    """
    for block_size, k, experimental_mean, experimental_std in [
        (7, 128000, 6.19625, 0.002956), (8, 256000, 7.183661, 0.002167)
    ]:
      mean, std = nist_suite.UniversalDistribution(block_size, k)
      self.assertAlmostEqual(experimental_mean, mean, delta=1e-04)
      self.assertAlmostEqual(experimental_std, std, delta=1e-04)

  def testUniversalImplExp1(self):
    # TODO(bleichen): This is just a regression test.
    #   The example in section 2.9.4 from NIST SP 800-22 uses an incorrect
    #   constant and hence can only be partially verified. The example in
    #   section 2.9.8 does not define G-SHA1.
    size = 1000000
    bits = exp1.bits(size)
    self.assertAlmostEqual(
        0.986855,
        nist_suite.UniversalImpl(bits, size, 6, 10 * 2**6),
        delta=1e-6)
    self.assertAlmostEqual(
        0.282568,
        nist_suite.UniversalImpl(bits, size, 7, 10 * 2**7),
        delta=1e-6)

  def testUniversalExp1(self):
    # Regression test
    size = 500000
    bits = exp1.bits(size)
    self.assertAlmostEqual(
        0.791608, nist_suite.Universal(bits, size), delta=1e-6)

  def testLinearComplexity(self):
    # Example from 2.10.8
    size = 1000000
    m = 1000
    bits = exp1.bits(size)
    # TODO(bleichen): NIST claims that the result should be 0.845406.
    #   So far I can't explain why there is a deviation.
    #   The count for the linear complexities match, but the chi square
    #   value differs in the third digit.
    named_p_values = nist_suite.LinearComplexity(bits, size, m)
    p_values = [p_value[1] for p_value in named_p_values]
    self.assertAlmostEqual(0.844738, p_values[0], delta=1e-6)
    # This is a p-value for an additional test.
    self.assertAlmostEqual(0.491080, p_values[1], delta=1e-6)

  def testSerialExp1(self):
    # Example from 2.11.8
    size = 1000000
    m_max = 16
    p_values = dict(nist_suite.Serial(exp1.bits(size), size, m_max))
    # The values for m=2 and m=16 are included in NIST SP 800-22.
    # The other values are self generated.
    expected = {
        "m=2 p-value1": 0.843764,
        "m=2 p-value2": 0.561915,
        "m=3 p-value1": 0.695134,
        "m=3 p-value2": 0.390330,
        "m=4 p-value1": 0.779572,
        "m=4 p-value2": 0.632043,
        "m=5 p-value1": 0.225783,
        "m=5 p-value2": 0.057499,
        "m=6 p-value1": 0.361246,
        "m=6 p-value2": 0.572718,
        "m=7 p-value1": 0.103250,
        "m=7 p-value2": 0.071302,
        "m=8 p-value1": 0.004111,
        "m=8 p-value2": 0.006341,
        "m=9 p-value1": 0.092743,
        "m=9 p-value2": 0.839399,
        "m=10 p-value1": 0.491433,
        "m=10 p-value2": 0.914855,
        "m=11 p-value1": 0.701685,
        "m=11 p-value2": 0.775003,
        "m=12 p-value1": 0.739708,
        "m=12 p-value2": 0.642350,
        "m=13 p-value1": 0.292713,
        "m=13 p-value2": 0.080369,
        "m=14 p-value1": 0.392626,
        "m=14 p-value2": 0.561418,
        "m=15 p-value1": 0.868492,
        "m=15 p-value2": 0.968706,
        "m=16 p-value1": 0.766182,
        "m=16 p-value2": 0.462921,
    }
    self.assertSameElements(list(expected), list(p_values))
    for name in expected:
      self.assertAlmostEqual(
          expected[name], p_values[name], msg=name, delta=1e-6)

  def testApproximateEntropy(self):
    # Example from Section 2.12.8
    bit_string = ("11001001000011111101101010100010001000010110100011"
                  "00001000110100110001001100011001100010100010111000")
    bits = BitString(bit_string)
    p_values = nist_suite.ApproximateEntropy(bits, len(bit_string), 2)
    p_value = p_values[0][1]
    self.assertAlmostEqual(0.235301, p_value, delta=1e-6)

  def testApproximateEntropyExp1(self):
    size = 1000000
    bits = exp1.bits(size)
    m_max = 13
    p_values = dict(nist_suite.ApproximateEntropy(bits, size, m_max))
    # The value for m=10 is from Appendix 10 of NIST SP 900-22, the remaining
    # values are self generated.
    expected = {
        "m=2": 0.695109,
        "m=3": 0.779251,
        "m=4": 0.225756,
        "m=5": 0.361688,
        "m=6": 0.101718,
        "m=7": 0.003982,
        "m=8": 0.090301,
        "m=9": 0.488829,
        "m=10": 0.700073,
        "m=11": 0.745539,
        "m=12": 0.272461,
        "m=13": 0.294961,
    }
    self.assertSameElements(list(expected), list(p_values))
    for name in expected:
      self.assertAlmostEqual(
          expected[name], p_values[name], msg=name, delta=1e-6)

  def testSpectral(self):
    # NOTE(bleichen): NIST SP 800-22 has different values for both tests.
    #   The reason is that NIST gives different values for the variable n1.
    #   This is the number of elements in the DFT that are smaller than the
    #   bound n0. Since NIST does not give the result of the DFT it is not
    #   possible to determine the reason for the discrepancy. The values
    #   in the tests below have been confirmed with third party code.
    #   The values of the DFT have been compared among 3 different
    #   implementations.
    # Example from Section 2.6.4
    bit_string1 = "1100101001"
    bits1 = BitString(bit_string1)
    p_value1 = nist_suite.Spectral(bits1, len(bit_string1))
    self.assertAlmostEqual(0.468160, p_value1, delta=1e-6)

    # Example from Section 2.6.8
    bit_string2 = ("11001001000011111101101010100010001000010110100011"
                   "00001000110100110001001100011001100010100010111000")
    bits2 = BitString(bit_string2)
    p_value2 = nist_suite.Spectral(bits2, len(bit_string2))
    self.assertAlmostEqual(0.646355, p_value2, delta=1e-6)

  def testRandomExcursionsDistribution(self):
    # Examples are from Section 3.14
    # pyformat: disable
    self.assertSequenceAlmostEqual(
        [0.5000, 0.2500, 0.1250, 0.0625, 0.0312, 0.0312],
        nist_suite.RandomExcursionsDistribution(1, 5),
        delta=1e-4)
    self.assertSequenceAlmostEqual(
        [0.5000, 0.2500, 0.1250, 0.0625, 0.0625],
        nist_suite.RandomExcursionsDistribution(1, 4),
        delta=1e-4)
    self.assertSequenceAlmostEqual(
        [0.7500, 0.0625, 0.0469, 0.0352, 0.0264, 0.0791],
        nist_suite.RandomExcursionsDistribution(2, 5),
        delta=1e-4)
    self.assertSequenceAlmostEqual(
        [0.9286, 0.0051, 0.0047, 0.0044, 0.0041, 0.0531],
        nist_suite.RandomExcursionsDistribution(7, 5),
        delta=1e-4)
    # pyformat: enable

  def testRandomWalkExp1(self):
    # Example from Section 2.14.8.
    # Note(bleichen): The results for negative states match the ones given
    #   by NIST. The results for the positive states are different.
    #   To exclude that the implementation is wrong for positive states it
    #   is possible to flip all bits of the input and run the test again.
    #   This check is done in testRandomExcurionsNotExp1.
    size = 1000000
    bits = exp1.bits(size)
    computed = dict(
        nist_suite.RandomWalk(
            bits, size, max_state=4, max_cnt=5, max_state_variant=9))
    expected = {
        # Regression test.
        "cumulative sums forward": 0.669886,
        "cumulative sums reverse": 0.724265,

        # Example from Section 2.14.8.
        "random excursions -4": 0.573306,
        "random excursions -3": 0.197996,
        "random excursions -2": 0.164011,
        "random excursions -1": 0.007779,
        "random excursions 1": 0.786868,
        "random excursions 2": 0.440912,
        "random excursions 3": 0.797854,
        "random excursions 4": 0.778186,

        # Example from Section 2.15.8.
        "random excursions variant -9": 0.858946,
        "random excursions variant -8": 0.7947550,
        "random excursions variant -7": 0.5762486,
        "random excursions variant -6": 0.4934169,
        "random excursions variant -5": 0.6338727,
        "random excursions variant -4": 0.9172831,
        "random excursions variant -3": 0.9347078,
        "random excursions variant -2": 0.8160120,
        "random excursions variant -1": 0.8260090,
        "random excursions variant 1": 0.1378606,
        "random excursions variant 2": 0.2006419,
        "random excursions variant 3": 0.4412536,
        "random excursions variant 4": 0.9392906,
        "random excursions variant 5": 0.5056826,
        "random excursions variant 6": 0.4459347,
        "random excursions variant 7": 0.5122069,
        "random excursions variant 8": 0.5386347,
        "random excursions variant 9": 0.5939304,
    }
    self.assertSameElements(list(expected), list(computed))
    for name in expected:
      self.assertAlmostEqual(
          expected[name], computed[name], msg=name, delta=1e-6)

  def testRandomWalkNotExp1(self):
    # This is the same test as testRandomWalkExp, but with all bits flipped.
    # Flipping the bits result in a mirrored random walk.
    size = 1000000
    bits = exp1.bits(size) ^ ((1 << size) - 1)
    computed = dict(
        nist_suite.RandomWalk(
            bits, size, max_state=4, max_cnt=5, max_state_variant=9))
    expected = {
        # Regression test.
        "cumulative sums forward": 0.669886,
        "cumulative sums reverse": 0.724265,

        # Example from Section 2.14.8.
        "random excursions 4": 0.573306,
        "random excursions 3": 0.197996,
        "random excursions 2": 0.164011,
        "random excursions 1": 0.007779,
        "random excursions -1": 0.786868,
        "random excursions -2": 0.440912,
        "random excursions -3": 0.797854,
        "random excursions -4": 0.778186,

        # Example from Section 2.15.8.
        "random excursions variant 9": 0.858946,
        "random excursions variant 8": 0.7947550,
        "random excursions variant 7": 0.5762486,
        "random excursions variant 6": 0.4934169,
        "random excursions variant 5": 0.6338727,
        "random excursions variant 4": 0.9172831,
        "random excursions variant 3": 0.9347078,
        "random excursions variant 2": 0.8160120,
        "random excursions variant 1": 0.8260090,
        "random excursions variant -1": 0.1378606,
        "random excursions variant -2": 0.2006419,
        "random excursions variant -3": 0.4412536,
        "random excursions variant -4": 0.9392906,
        "random excursions variant -5": 0.5056826,
        "random excursions variant -6": 0.4459347,
        "random excursions variant -7": 0.5122069,
        "random excursions variant -8": 0.5386347,
        "random excursions variant -9": 0.5939304,
    }
    self.assertSameElements(list(expected), list(computed))
    for name in expected:
      self.assertAlmostEqual(
          expected[name], computed[name], msg=name, delta=1e-6)


if __name__ == "__main__":
  absltest.main()
