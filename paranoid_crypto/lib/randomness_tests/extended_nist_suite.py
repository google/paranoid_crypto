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
"""This module implements extensions of the tests in NIST SP 800-22.

1 Binary Matrix Rank Test
    The binary matrix rank test in SP 800-22 uses matrices of size 32*32
    and checks the distribution of their ranks. The test requires at least
    38 matrices.
    The test in this module uses larger matrices. Only one matrix per
    size is tested. The test fails if the rank is significantly smaller
    than expected.
"""

from typing import Optional
from paranoid_crypto.lib.randomness_tests import berlekamp_massey
from paranoid_crypto.lib.randomness_tests import nist_suite
from paranoid_crypto.lib.randomness_tests import util

# ASYMPTOTIC_RANK_SF[k] is the asymptotic probability that a random quadratic
# binary matrix of size n has rank at most n - k. The probabilities are computed
# under the assumption that n goes to infinity. As a rule of thumb these values
# should only be used if n is at least 32.
ASYMPTOTIC_RANK_SF = [
    1.0, 0.711212, 0.133636, 0.00528545, 4.6664e-05, 9.69625e-08, 4.88413e-11,
    6.05577e-15, 1.86256e-19, 1.42658e-24, 2.7263e-30, 1.30127e-36, 1.55199e-43,
    4.62642e-51, 3.44738e-59, 6.42163e-68, 2.9904e-77, 3.48133e-87, 1.01321e-97,
    7.37209e-109, 1.34098e-120, 6.09807e-133, 6.9327e-146, 1.97039e-159,
    1.40005e-173, 2.48699e-188, 1.10444e-203, 1.22618e-219, 3.40333e-236,
    2.36153e-253, 4.09661e-271, 1.77662e-289, 1.92622e-308
]


def LargeBinaryMatrixRank(bits: int, n: int) -> nist_suite.NamedPValues:
  """Computes the rank of large binary matrices.

  Args:
    bits: the bit string to test
    n: the length of the bit string

  Returns:
    a list of p-values
  Raises:
    nist_suite.InsufficientDataError: if there is not enough data to compute
        at least one p-value.
  """
  p_values = []
  size = 64
  if n < size * size:
    raise nist_suite.InsufficientDataError(
        f"At least {size * size} bits required")
  while size * size <= n:
    truncated = bits & (((1 << (size * size)) - 1))
    matrix = util.SplitSequence(truncated, size * size, size)
    rank = util.BinaryMatrixRank(matrix)
    k = size - rank
    if k >= len(ASYMPTOTIC_RANK_SF):
      p_value = 0
    else:
      p_value = ASYMPTOTIC_RANK_SF[k]
    p_values.append((f"{size} * {size}", p_value))
    size *= 2
  return p_values


def LinearComplexityScatter(bits: int,
                            n: int,
                            step_size: int,
                            max_block_size: Optional[int] = None) -> float:
  """Computes the linear complexity of scattered bits.

  Some pseudorandom number generators have the property that certain
  bits (e.g. the least significant bit) of its output can be reproduced
  with an LFSR. This test tries to detect such cases.

  Args:
    bits: the bit string to test
    n: the length of the bit string
    step_size: the test constructs sequences to test where the distance between
      the bits selected is an element of this array.
    max_block_size: The maximal size of the blocks to test. Testing long
      sequences can therefore take a long time. Setting this value limits the
      size of the blocks tested.

  Returns:
    a p-value
  """
  if max_block_size is not None and step_size * max_block_size < n:
    n = step_size * max_block_size
    bits = bits & ((1 << n) - 1)
  sequences = util.Scatter(bits, step_size)
  log_prob = 0
  for i, sequence in enumerate(sequences):
    size = (n + step_size - 1 - i) // step_size
    c = berlekamp_massey.LinearComplexity(sequence, size)
    log_prob -= berlekamp_massey.LfsrLogProbability(size, c)
  p_value = util.BinomialCdf(len(sequences) - 1, log_prob - 1)
  return p_value
