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

import os
from absl.testing import absltest
from absl.testing import parameterized
from paranoid_crypto.lib.randomness_tests import lattice_suite
from paranoid_crypto.lib.randomness_tests import rng


class LatticeSuiteTest(parameterized.TestCase):

  def testPseudoAverage(self):
    self.assertEqual(9, lattice_suite.PseudoAverage([7, 8, 9, 0, 1], 10))
    self.assertEqual(0, lattice_suite.PseudoAverage([8, 9, 0, 1, 2], 10))
    self.assertEqual(5, lattice_suite.PseudoAverage([1, 3, 5, 7, 9], 11))
    self.assertEqual(3, lattice_suite.PseudoAverage([3], 10))
    self.assertEqual(9, lattice_suite.PseudoAverage([0, 0, 9, 9, 9], 10))

  def testBias(self):
    sample = [0x012345678, 0xabcef1323, 0x2d3242142, 0x125345acd, 0x871726321]
    self.assertAlmostEqual(
        0.322337, lattice_suite.Bias(sample, 2**32, [(1, 0)]), delta=1e-6)
    self.assertAlmostEqual(
        0.471774,
        lattice_suite.Bias(sample, 2**32, [(0x12345679, 0x1298a123)]),
        delta=1e-6)

  # Output sizes for truncated LCG.
  trunclcg_parameters = [("TruncLcg16", 16), ("TruncLcg20", 20),
                         ("TruncLcg28", 28), ("TruncLcg32", 32),
                         ("TruncLcg64", 64), ("TruncLcg128", 128)]

  @parameterized.named_parameters(*trunclcg_parameters)
  def testFindBiasImpl(self, output_size: int):
    block_size = 3 * output_size
    test_size = 100
    sample = []
    for _ in range(test_size):
      block = rng.TruncLcgRand(output_size).RandomBits(block_size)
      sample.append(block)
    p_value = lattice_suite.FindBiasImpl(sample, 2**block_size)
    self.assertAlmostEqual(0.0, p_value)

  @parameterized.named_parameters(*trunclcg_parameters)
  def testFindBias(self, output_size):
    # For FindBias to work well it is helpful if block_size is a multiple
    # of the output_size of the random number generator, so that splitting
    # the bit string into blocks gives blocks that are equally aligned.
    block_size = 12 * output_size
    test_size = 100 * block_size
    bits = rng.TruncLcgRand(output_size).RandomBits(test_size)
    # NOTE(bleichen): The test here generates a long bit string of consecutive
    #   outputs from TruncLcg random number generator. The constants found by
    #   FindBias are aligned for this bit string. Using these constants it is
    #   possible to detect with very high confidence that bits is not random.
    #   The constants are however not able to generally detect a bias in
    #   TruncLcg. To do this one would have to reseed it after
    #   generating block_size bits (as done in testFindBiasImplTruncLcg).
    p_value = lattice_suite.FindBias(bits, test_size, block_size)
    self.assertAlmostEqual(0.0, p_value)


if __name__ == "__main__":
  absltest.main()
