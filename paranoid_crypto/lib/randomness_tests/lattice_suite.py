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
"""This module implements the tests based on lattice basis reduction."""

import math
from typing import Optional
from paranoid_crypto.lib import lll
from paranoid_crypto.lib.randomness_tests import util


def Bias(sample: list[int], n: int, transforms: list[tuple[int, int]]) -> float:
  """Determines whether a sample is biased.

  This function computes for each s in sample and each a, b in transforms the
  distance of s * a + b to the closest multiple of n. For random samples the
  result s expected to be almost uniformly distributed in the range 0 .. n/2.

  Args:
    sample: a list of values to check
    n: a modulus
    transforms: a list of value a, b

  Returns:
    a p-value
  """
  t = 0
  for s in sample:
    for a, b in transforms:
      v = (a * s + b) % n
      v = min(v, n - v)
      t += v
  normalized = 2 * t / n
  p_value = util.UniformSumCdf(len(sample) * len(transforms), normalized)
  return p_value


def PseudoAverage(a: list[int], n: int) -> int:
  """Finds a integer that is "closest" to a modulo n.

  The goal of this function is to define some sort of average
  for residues modulo n. For example if n = 10 and a =
  [0, 6, 7, 8, 9] then the result should be 8, since this one
  0 == 10 (mod 10) and the integers 6, 7, 8, 9, 10 are close to
  each other.

  This function does essentially the following:
  From each pair (a[i], a[i] + n) an element b[i] is selected,
  such that the variance of the elements b[i] is minimal.
  The result is then the mean of the elements b[i] modulo n.

  Args:
    a: a list of integers
    n: the modulus

  Returns:
    an integer close to all elements of a modulo n (as defined above).
  """
  a = sorted(a)
  sum_a = sum(a)
  m = len(a)
  best_j = 0
  best_diff = 0
  const_j = n * m - 2 * sum_a
  sx = 0
  for i in range(m):
    j = i + 1
    # sx = sum(a[k] for k in range(j))
    sx += a[i]
    # Let b = [a[0] + n, ... a[i] + n, a[i+1], ... a[m-1]],
    # i.e. b is the list a with the first j elements incremented by n.
    # Then diff = (Variance(b) - Variance(a)) * (m - 1) / n
    diff = 2 * sx * m + j * (const_j - j * n)
    if diff < best_diff:
      best_j, best_diff = j, diff
  pseudo_average = (sum_a + n * best_j + m // 2) // m % n
  return pseudo_average


def GetLattice(a: list[int], w: int, n: int) -> list[list[int]]:
  """Returns a lattice for finding a bias.

  The goal is to find integers c, d such that the elements of
  k = [(ai * c + d] are all close to some multiple of n.

  The lattice returned has the following form
  |1/w  a[0] a[1] a[2] .... a[k-1]|
  |0    1    1    1    .... 1     |
  |0    0    n    0    .... 0     | * w
  |0    0    0    n    .... 0     |
  |          .....                |
  |0    0    0    0    .... n     |

  Args:
    a: an integer array
    w: expected bias
    n: modulus

  Returns:
    an integer lattice
  """

  if len(a) <= 2:
    raise ValueError("not enough samples")
  size = len(a) + 1
  mat = [[0] * size for _ in range(size)]
  mat[0][0] = 1
  for i in range(1, size):
    mat[0][i] = a[i - 1] * w
    mat[1][i] = w
    if i > 1:
      mat[i][i] = n * w
  return mat


def FindBiasImpl(sample: list[int], n: int, w: Optional[int] = None) -> float:
  """Attempts to find a bias in a list of samples.

  This function works by dividing the given sample into a training sample
  and a test sample. The training sample is used to search for a non-random
  pattern. Concretely, it tries to find a multiplier c, such that the values
  [x * c % n for x in sample] are biased. Here, biased means that the values
  are close to each other, e.g. that they share the some of the most
  significant bits. For the best multiplier c found the function then
  uses the test sample to compute a p-value.

  Args:
    sample: a list of outputs to check.
    n: the range of the elements in sample is 0 .. n-1
    w: the expected bias (e.g. 2**32 is typically a good choice).

  Returns:
    a p-value
  """
  if w is None:
    w = 2**32
  # Step 1: Dividing the sample into a training sample to find a multiplier
  # c and a test sample that is used to check if the sample has a bias.
  training_size = min(72, len(sample) * 2 // 3)
  training_sample = sample[:training_size]
  test_sample = sample[training_size:]
  if len(training_sample) < 2 or len(test_sample) < 1:
    raise ValueError("not enough samples")
  # Step 2: Generating a lattice that has a short vector (c, ...) if the sample
  # is biased.
  mat = GetLattice(training_sample, w, n)
  red = lll.reduce(mat)
  c = 1
  # Searches for the smallest vector in the lattice where the first
  # element is not degenerate.
  for row in red:
    c0 = row[0] % n
    # If c0 and n share a large GCD then random data could look biased.
    # For example if c0 = n / 2. Then a small test sample consisting of
    # only even integers would be considered biased with a p-value that
    # largerly overestimates the confidence.
    # The cutoff for the maximal GCD below is arbitrary. It simply has
    # to allow typical values (small integers) and reject degenerate
    # values (anything close to n).
    if c0 != 0 and math.gcd(c0, n)**2 < n:
      c = c0
      break
  # Step 3: Compute a value d.
  biased = [x * c % n for x in training_sample]
  d = -PseudoAverage(biased, n) % n
  # Step 4: Compute a p-value from not yet used samples.
  p_value = Bias(test_sample, n, [(c, d)])
  return p_value


def FindBias(bits: int, length: int, block_size: int = 256) -> float:
  """Attempts to find a bias in a bit string.

  This function is mainly a wrapper for FindBiasImpl.

  The parameter choices for this function are important.
  Experiments with various weak random number generators are still
  necessary to make good recommendations.

  This function can detect most LCGs and truncated LCGs. For the function
  to work well it is important that block_size is a multiple of the output
  size of the LCG. block_size should typically be at least 2 times the
  state size of the LCG.

  A good input size is 100 to 200 blocks. Smaller inputs may also work
  it there is a large bias in the input sample.

  Args:
    bits: a bit string to check.
    length: the length of the bit string
    block_size: the size of the blocks in bits.

  Returns:
    a p-value

  """
  sample = util.SplitSequence(bits, length, block_size)
  return FindBiasImpl(sample, 2**block_size)
