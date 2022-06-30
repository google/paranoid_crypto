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
from paranoid_crypto.lib.randomness_tests import extended_nist_suite


class ExtendedNistSuite(absltest.TestCase):

  def testLargeBinaryMatrixRank(self):
    """Regression test."""
    size = 1000000
    bits = exp1.bits(size)
    test_result = extended_nist_suite.LargeBinaryMatrixRank(bits, size)
    p_values = [pv[1] for pv in test_result]
    expected = [
        0.133636,  # p-value for 64*64 matrix with rank 62
        0.711212,  # p-value for 128*128 matrix with rank 127
        0.711212,  # p-value for 256*256 matrix with rank 255
        1.0,  # p-value for 512*512 matrix with rank 512
    ]
    self.assertSequenceAlmostEqual(expected, p_values, delta=1e-06)


if __name__ == "__main__":
  absltest.main()
