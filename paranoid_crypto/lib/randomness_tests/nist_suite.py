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
"""This module implements the tests in NIST SP 800-22.

NIST is currently in the process of reviewing their test suite. The
implementation below is based on the "old version" of this test suite.
In some cases the document is ambiguous. In other cases the description
appears to be imprecise. In a few cases it is possible to add additional
checks with little computational overhead. A number of examples given
in NIST SP 800-22 appear to have typos. These test cases need to be
rechecked once a revision of the document is available.

The tests in NIST SP 800-22 and the current status of the implementation
is as follows:
2.1 Frequency (Monobits) Test ...........................
2.2 Frequency Test within a Block .......................
2.3 Runs Test ...........................................
2.4 Test for the Longest Run of Ones in a Block .........
2.5 Binary Matrix Rank Test .............................
    NIST uses asymptotic values for the distribution of the results, since
    the test uses sufficiently large matrices of size 32*32. Since other
    test suites use smaller matrices (e.g. diehard uses 6*8 in on test)
    the probability distribution is recomputed in our implementation. This
    can lead to small differences in the p-values.
2.6 Discrete Fourier Transform (Spectral) Test ..........
    This is currently the slowest test in the test suite. The test suite
    also performs below expectations.
2.7 Non-Overlapping Template Matching Test ..............
    The test can take a relatively large number of templates as
    input. Each template returns a p-value. A large number of p-values
    easily leads to some false positives. One plan is to extend the code,
    so that failing tests are repeated to avoid frequent false positives.
2.8 Overlapping Template Matching Test...................
    The computation of the expected distribution has been changed
    to a slower but more accurate method.
2.9 Maurer’s “Universal Statistical” Test ...............
2.10 Linear Complexity Test .............................
    The implementation computes an additional p-value that
    focuses on the occurrence of unlikely linear complexities.
    Ideally, the test should detect random number generators such as the
    Mersenne Twister. But the parameters proposed by NIST are too small
    to detect that random.getrandbits() is weak.
2.11 Serial Test.........................................
2.12 Approximate Entropy Test ...........................
2.13 Cumulative Sums (Cusum) Test........................
    Implemented in RandomWalk, which merges several tests.
2.14 Random Excursions Test..............................
    Implemented in RandomWalk, which merges several tests.
    In about 30% of all cases the random excursions test does not have
    enough cycles to give conclusive results, and hence no p-values are
    computed.
2.15 Random Excursions Variant Test .....................
    Implemented in RandomWalk, which merges several tests. Similar to the
    random excursions test there is a high chance that no p-values are
    computed, because of a lack of cycles.
"""

import collections
import math
from typing import Optional
import numpy
from paranoid_crypto.lib.randomness_tests import berlekamp_massey
from paranoid_crypto.lib.randomness_tests import util

# Type hints:
NamedPValues = list[tuple[str, float]]


class InsufficientDataError(ValueError):
  """Thrown when a test did not receive enouth data to run.

  The motivation for adding this error is that callers can
  catch them and notify the user that a test has been skipped.
  """


def ChiSquare(count: list[int],
              prob: list[float],
              k: Optional[int] = None) -> float:
  """Performs a Chi-Square test.

  Args:
    count: the number of results in each category
    prob: the expected distribution of the counts. The sum of prob should be
      1.0.
    k: the degrees of freedom

  Returns:
    the p-value. A small value indicates that the count does not follow
    a the given distribution.
  """
  # Performs some input validations, because typos are frequent.
  if len(count) != len(prob):
    raise ValueError("count and prob should have the same length")
  for p in prob:
    # All expected probabilities should be strictly larger than 0.0,
    # since otherwise the chi-square test is unreliable.
    if not 0.0 < p <= 1.0:
      raise ValueError("Invalid probability")
  # Tests in NIST SP 800-22 typically have a precision of 4 - 6 decimal digits.
  if abs(sum(prob) - 1.0) > 1e-04:
    raise ValueError("Probabilites should sum up to 1")

  if k is None:
    k = len(count) - 1
  n = sum(count)
  chi_square = sum((c - n * p)**2 / (n * p) for c, p in zip(count, prob))
  p_value = util.Igamc(k / 2, chi_square / 2)
  return p_value


def ChiSquareUniform(count: list[int]) -> float:
  """Performs a Chi-Square test with an expected uniform distribution.

  Args:
    count: the number of times each experiment occurred.

  Returns:
    the p-value.
  """
  n = len(count)
  return ChiSquare(count, [1. / n] * n, n - 1)


def Frequency(bits: int, n: int) -> float:
  """Frequency (Monobits) .

  This test checks whether the number of 0 and 1 bits deviates from
  random data. Described in Section 3.1 of NIST SP 800-22.

  Args:
    bits: a bit string
    n: the length of the bit string

  Returns:
    a p-value
  """
  s = 2 * util.BitCount(bits) - n
  s_obs = abs(s) / math.sqrt(n)
  p_value = math.erfc(s_obs / math.sqrt(2))
  return p_value


def BlockFrequencyImpl(blocks: list[int], m: int) -> float:
  """Block frequency test.

  This test checks whether the distribution of 0 and 1 bits in blocks
  deviates from random data. Described in Section 3.2 of NIST SP 800-22.

  Args:
    blocks: a list of bit strings.
    m: the size of the bit strings in blocks

  Returns:
    a p-value
  """
  pi = [util.BitCount(b) / m for b in blocks]
  chi_obs = 4 * m * sum((x - 1 / 2)**2 for x in pi)
  p_value = util.Igamc(len(blocks) / 2, chi_obs / 2)
  return p_value


def BlockFrequency(bits: int, n: int) -> float:
  """Block frequency test.

  This test checks whether the distribution of 0 and 1 bits in blocks
  deviates from random data. Described in Section 3.2 of NIST SP 800-22.

  Args:
    bits: the bit string to test.
    n: the length of the bit string

  Returns:
    a p-value
  Raises:
    InsufficientDataError: if the size of bits is smaller than the
        recommendation by NIST.
  """
  if n < 100:
    raise InsufficientDataError("Not enough input")
  # NIST does not exactly specify how to select m.
  # The documentation only recommends to use m >= 20 and m > n / 100.
  m = 16
  while n // m >= 100:
    m *= 2
  m = max(20, m)
  blocks = util.SplitSequence(bits, n, m)
  return BlockFrequencyImpl(blocks, m)


def Runs(bits: int, n: int) -> float:
  """Runs test.

  This test checks if the number of runs of 0 and 1 bits deviates from
  random data. Described in Section 3.3 of NIST SP 800-22.

  Args:
    bits: a bit string
    n: the length of the bit string

  Returns:
    a p-value
  """
  pi = util.BitCount(bits) / n
  v_obs = util.Runs(bits, n)
  pp = pi * (1 - pi)
  p_value = math.erfc(abs(v_obs - 2 * n * pp) / (2 * math.sqrt(2 * n) * pp))
  return p_value


def LongestRuns(bits: int, n: int) -> float:
  """Longest runs test.

  This test checks whether the longest runs in multiple blocks deviate
  from random data.
  Described in Section 3.4 of NIST SP 800-22.

  Args:
    bits: a bit string
    n: the length of the bit string

  Returns:
    a p-value
  Raises:
    InsufficientDataError: if the input is smaller than 128 bits.
  """
  # NIST SP 800-22 proposes to select parameters based on the size of the
  # input.
  # The list below contains tuples (min_n, m, v_lower, v_upper, pi) with:
  #    min_n: the minimal number of bits for the given parameter set.
  #       The values are given in section 2.4.2.
  #    m is: the block size for the parameter set
  #    v_lower: and v_upper are minimal an maximal values for the runs. Lower
  #       and higher values are lumped together with the v_lower rsp. v_upper.
  #       These values are described in section 2.4.4.
  #    pi: the probabilities to get runs in the range v_lower .. v_upper.
  #       These values are described in section 3.4.
  params = [[128, 8, 1, 4, [0.2148, 0.3672, 0.2305, 0.1875]],
            [6272, 128, 4, 9, [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]],
            [
                750000, 10000, 10, 16,
                [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
            ]]
  for p in params[::-1]:
    if n >= p[0]:
      _, m, v_lower, v_upper, pi = p
      k = v_upper - v_lower
      break
  else:
    raise InsufficientDataError("The test requires at least 128 bits of data")
  blocks = util.SplitSequence(bits, n, m)
  longest_runs = [util.LongestRunOfOnes(block) for block in blocks]
  v = [0] * (v_upper - v_lower + 1)
  for x in longest_runs:
    idx = max(0, min(v_upper, x) - v_lower)
    v[idx] += 1
  p_value = ChiSquare(v, pi, k)
  return p_value


def RankDistribution(r: int,
                     c: int,
                     k: int,
                     allow_approximation: bool = True) -> list[float]:
  """Returns the distribution of the rank of binary r*c matrices.

  Args:
    r: the number of rows of the matrix
    c: the number of columns of the matrix
    k: the last probability of the result is the sum of the probabilities of
      getting a rank 0 .. r - k
    allow_approximation: if True then approximations for large r and c might be
      returned.

  Returns:
    a list of probabilities [p_0 .. p_k], where
    p_k is the probability of getting a rank 0 .. r - k, otherwise p_i is
    the probability that a random row * cols matrix has rank m - i.
  """

  if allow_approximation:
    # NIST uses square matrices and k = 2 or 3. If the dimensions of the
    # matries are large enough then precomputed values can be used.
    if r == c and r >= 31 and k <= 5:
      precomputed = [
          0.28878809, 0.57757619, 0.12835026, 0.00523879, 0.00004657, 0.00000010
      ]
      return precomputed[:k] + [sum(precomputed[k:])]
  res = [0] * (r + 1)
  res[0] = 1.0
  for _ in range(c):
    for j in range(r - 1, -1, -1):
      prob_dependent = 2**(j - r)
      res[j + 1] += res[j] * (1 - prob_dependent)
      res[j] *= prob_dependent
  return res[-k:][::-1] + [sum(res[:-k])]


def BinaryMatrixRankImpl(rows: list[int], r: int, c: int, k: int) -> float:
  """Binary rank test.

  This test takes a list of bit string, divides this list into binary
  matrices and checks if the rank of the matrices deviate from random data.

  Args:
    rows: a list of bit strings of size c
    r: the number of rows of the matrix
    c: the number of columns of the matrix
    k: the last probability of the result is the sum of the probabilities of
      getting a rank 0 .. r - k

  Returns:
    a p-value
  Raises:
    InsufficientDataError: no matrices can be formed.
  """
  num_matrices = len(rows) // r
  if num_matrices < 1:
    raise InsufficientDataError("Can't create a matrix")
  v = [0] * (k + 1)
  for i in range(num_matrices):
    mat = rows[i * r:(i + 1) * r]
    rank = util.BinaryMatrixRank(mat)
    v[min(k, r - rank)] += 1
  pi = RankDistribution(r, c, k)
  p_value = ChiSquare(v, pi, k)
  return p_value


def BinaryMatrixRank(bits: int,
                     n: int,
                     r: int = 32,
                     c: int = 32,
                     k: int = 3,
                     check_size: bool = True) -> float:
  """Binary rank test.

  This test divides the bit string into binary matrices and checks if the
  rank of the matrices deviate from random data.
  Described in section 3.5 of NIST SP 800-22.
  Args:
    bits: the bit string to test
    n: the length of the bit string
    r: the number of rows of the matrix
    c: the number of columns of the matrix
    k: the last probability of the result is the sum of the probabilities of
      getting a rank 0 .. r - k
    check_size: if True then NIST recommendations for the minimal size of the
      input is checked.

  Returns:
    a p-value
  Raises:
    InsufficientDataError: if the size of the data is below NIST recommentation.
  """
  if min(r, c) < k:
    raise ValueError("k must not be larger than min(r, c)")
  if check_size:
    # Input size from Section 2.5.7 of NIST SP 800-22
    if n < 38 * r * c:
      raise InsufficientDataError("n should be at least 38 * r * c")
  rows = util.SplitSequence(bits, n, c)
  return BinaryMatrixRankImpl(rows, r, c, k)


def Spectral(bits: int, n: int) -> float:
  """Spectral test.

  Described in Section 2.6 of NIST SP 800-22

  Args:
    bits: the bit string to test
    n: the length of the bit string

  Returns:
    a p value
  """
  # TODO(bleichen): The spectral test is supposed to detect LCGs.
  #   So far it can only detect GMP's random number generator with
  #   32 and 40 bit state. This is of course disppointing.
  #   It is unclear if the test can be improved. One possibility might
  #   be to split the input into integers of size 32, 64 etc. instead of
  #   single bits.
  # NOTE(bleichen): The spectral test is currently the slowest test
  #   in the test suite. Some speedups may be possible: using rfft
  #   instead of fft. Single precision floating point could be
  #   sufficient. Truncating bits to a multiple of a power of two
  #   might allow a faster FFT.
  bits = list(util.Bits(bits, n))
  m = util.Dft(bits)
  m = m[:n // 2]
  # The bound t was proposed in Section 3 of the paper
  # https://eprint.iacr.org/2004/018.pdf.
  t = math.sqrt(math.log(1 / 0.05) * n)
  # expected number of values <= t in m
  n0 = 0.95 * len(m)
  # observed number of values <= t in m
  n1 = numpy.count_nonzero(m < t)
  # The paper "On Statistical Tests for Randomness Included in the NIST
  # SP800-22 Test Suite and Based on the Binomial Distribution" by
  # F. Pareschi, R. Rovatti, and  G. Setti
  # IEEE Transactions on Information Forensics and Security 2012, vol. 7, (2)
  # proposes to replace the value 4 by 3.8.
  d = (n0 - n1) / math.sqrt(n * 0.95 * 0.05 / 4)
  p_value = math.erfc(abs(d) / math.sqrt(2))
  return p_value


def IsNonOverlappingTemplate(template: int, m: int) -> bool:
  """Checks if a template is non-overlapping.

  A template is non-overlapping if it is not possible that two overlapping
  subsequences of a bit string are both equal to template.

  Args:
    template: the template to check
    m: the length of the template

  Returns:
    True if the template is non-overlapping
  """
  for i in range(1, m):
    if template >> (m - i) == template & ((1 << i) - 1):
      return False
  return True


def NonOverlappingTemplateMatchingImpl(blocks: list[int], n: int, m: int,
                                       templates: list[int]) -> NamedPValues:
  """Non-overlapping template matching test.

  Described in Section 2.7 of NIST SP 800-22

  Args:
    blocks: a list of bit sequences to test
    n: the length of the bit sequences in blocks
    m: the size of the templates to test
    templates: a list of templates to test.

  Returns:
    a list of tuples (template, p-value).
  Raises:
    ValueError: if templates contains a template that can overlap itself.
  """
  for b in templates:
    if not IsNonOverlappingTemplate(b, m):
      raise ValueError("TemplateMatching requires non-overlapping templates")

  # Since the templates are non-overlapping it is possible to count all the
  # subsequences of size m, once and use the result for all the templates.
  cnts = [util.FrequencyCount(block, n, m, False) for block in blocks]
  n0 = n - m + 1
  mean = n0 / 2**m
  variance = n * (1 / 2**m - (2 * m - 1) / 2**(2 * m))
  p_values = []
  for b in templates:
    v = [cnt[b] for cnt in cnts]
    obs = sum((w - mean)**2 / variance for w in v)
    p_value = util.Igamc(len(blocks) / 2, obs / 2)
    template_str = format(b, f"0{m}b")
    p_values.append((format(f"template '{template_str}'"), p_value))
  return p_values


def NonOverlappingTemplateMatching(
    bits: int,
    n: int,
    blocks: int = 8,
    m: Optional[int] = None,
    templates: Optional[list[int]] = None) -> NamedPValues:
  """Non-overlapping template matching test.

  Described in Section 2.7 of NIST SP 800-22

  Args:
    bits: the bit string to test
    n: the length of the bit string
    blocks: bits is divided into this number of blocks
    m: the size of the templates. If None then the test tries to find a size
      satisfying the conditions given by NIST.
    templates: a list of templates to test. Default is the list of all
      non-overlapping templates of size m.

  Returns:
    a list of tuples (template, p-value).
  Raises:
    ValueError: if templates contains a template that can overlap itself or if
        the input data is inconsistent
    InsufficientDataError: if there is not enough data to run the test.
  """

  # TODO(bleichen): NIST doesn't give a lot of guidance how to select
  #   the parameters for this test. Below are some best guesses.
  block_size = n // blocks

  if m is None:
    if templates is not None:
      raise ValueError("m is required when templates is not None.")
    # NOTE(bleichen): the values for m are arbitrary. NIST SP 800-22 does not
    #   seem to give any guidance here.
    if block_size < 4:
      raise InsufficientDataError("small block_size")
    elif block_size < 64:
      m = 2
    elif block_size < 256:
      m = 3
    elif block_size < 1024:
      m = 4
    elif block_size < 2048:
      m = 5
    elif block_size < 4096:
      m = 6
    elif block_size < 8192:
      m = 7
    elif block_size < 16384:
      m = 8
    elif block_size < 32768:
      m = 9
    else:
      m = 10

  if templates is None:
    templates = []
    for b in range(2**m):
      if IsNonOverlappingTemplate(b, m):
        templates.append(b)
  blocks = util.SplitSequence(bits, n, block_size)
  return NonOverlappingTemplateMatchingImpl(blocks, block_size, m, templates)


def OverlappingTemplateMatchingMatrix(m: int, k: int) -> list[list[float]]:
  """Returns a transition probability matrix for the overlapping template test.

  The overlapping template test counts the number of runs of 1s of size m in a
  bit sequence. To compute the distribution of the number of runs of 1s we use
  a Markov chain with k * m + 1 states. A bit string with i runs of 1s ending
  with j 1s corresponds to state min(k * m, i * m + min(k - 1, j)).
  The Markov chain described here stops counting after seeing k runs of size m.
  I.e., state k*m is used for any case where k or more runs have occurred.
  The matrix M returned describes the transition probability of adding a random
  bit to a bit string. That is M[i][j] is the probability that appending a bit
  to a bit string in state i gives a bit string in state j.

  Args:
    m: the length of the runs of 1s.
    k: the upper bound on the number of runs of 1s of length m.

  Returns:
    the transition probability matrix.
  """
  size = k * m + 1
  mat = [[0] * size for _ in range(size)]
  for occurrences in range(k):
    for run in range(m):
      i = occurrences * m + run
      # Getting a 0
      mat[i][occurrences * m] += 0.5
      # Getting a 1
      if run < m - 1:
        mat[i][i + 1] += 0.5
      elif occurrences < k - 1:
        mat[i][i + m] += 0.5
      else:
        mat[i][k * m] += 0.5
  mat[k * m][k * m] = 1.0
  return mat


def OverlappingTemplateMatchingDistribution(n: int, m: int,
                                            k: int) -> list[float]:
  """The expected probability distribution of an overlapping matching test.

  Args:
    n: the size of the bit string
    m: the length of the template
    k: the maximal number of occurrences

  Returns:
    a list of size k+1. If i < k then the i-th element is the probability that
    a random bit string of size n contains k runs of 1s of size m. These runs
    may overlap. The k-th element is the probability that a random bit string
    of size n has k or more runs of 1s of size m.
  """
  mat = OverlappingTemplateMatchingMatrix(m, k)
  matn = numpy.linalg.matrix_power(mat, n)
  row_0 = matn[0]
  pi = [sum(row_0[i * m:(i + 1) * m]) for i in range(k + 1)]
  return pi


def OverlappingTemplateMatchingImpl(blocks: list[int], n: int, m: int) -> float:
  """Overlapping template matching test.

  Described in Section 2.8 of NIST SP 800-22.

  The test counts the number of occurrences of runs of 1s of length m in
  each block and checks if the result deviates from random data.

  Args:
    blocks: a list of bit strings to test
    n: the length of the bit strings in block
    m: the size of the runs.

  Returns:
    a p-value.
  """

  k = 5
  v = [0] * (k + 1)
  for block in blocks:
    cnt = util.OverlappingRunsOfOnes(block, m)
    v[min(k, cnt)] += 1
  pi = OverlappingTemplateMatchingDistribution(n, m, k)
  return ChiSquare(v, pi, k)


def OverlappingTemplateMatching(bits: int,
                                n: int,
                                m: Optional[int] = None,
                                block_size: Optional[int] = None) -> float:
  """Overlapping template matching test.

  Described in Section 2.8 of NIST SP 800-22.

  The test counts the number of occurrences of runs of 1s of length m in
  each block and checks if the result deviates from random data.

  Args:
    bits: a bit strings to test
    n: the length of the bit string
    m: the size of the runs.
    block_size: the size of the blocks to evaluate.

  Returns:
    a p-value.
  """
  # Some recommendations for the parameter selection are in Section 2.8.7
  if m is None:
    m = 9
  if block_size is None:
    block_size = 2**(m + 1) + m - 1
  blocks = util.SplitSequence(bits, n, block_size)
  return OverlappingTemplateMatchingImpl(blocks, block_size, m)


def UniversalDistribution(block_size: int, k: int) -> tuple[float, float]:
  """Returns expected value and standard deviation of a universal test.

  Args:
    block_size: the size of the blocks in bits
    k: the number of blocks used in the test

  Returns:
    A tuple (expected, std) containing the expected value for f and
    its standard deviation, where f is the value computed by the universal
    test with k blocks of size block_size.
  """

  # A table with entries block_size: (mean, variance).
  # Values below 6 are taken from Maurer's paper, since NIST
  # does not recommend such sizes.
  distribution_table = {
      1: (0.7326495, 0.690),
      2: (1.5374383, 1.338),
      3: (2.4016068, 1.901),
      4: (3.3112247, 2.358),
      5: (4.2534266, 2.705),
      6: (5.2177052, 2.954),
      7: (6.1962507, 3.125),
      8: (7.1836656, 3.238),
      9: (8.1764248, 3.311),
      10: (9.1723243, 3.356),
      11: (10.170032, 3.384),
      12: (11.168765, 3.401),
      13: (12.168070, 3.410),
      14: (13.167693, 3.416),
      15: (14.167488, 3.419),
      16: (15.167379, 3.421)
  }
  if block_size not in distribution_table:
    raise ValueError("block_size not supported")
  mean, variance = distribution_table[block_size]
  # NIST SP 800-22 and "Handbook of applied Cryptography" by Menezes et. al.
  # have slightly different formulas for c. The implementation below follows
  # NIST SP 800-22.
  # To confirm that these values are reasonable, we performed a large series
  # of tests.
  c = (0.7 - 0.8 / block_size + (4 + 32 / block_size) *
       (k**(-3 / block_size) / 15))
  std = c * math.sqrt(variance / k)
  return mean, std


def UniversalImpl(bits: int, n: int, block_size: int, q: int) -> float:
  """Implementation of Maurer's universal test.

  The test is described in Section 2.9 of NIST SP 800-22.

  Args:
    bits: the bit string to test
    n: the length of the bit string
    block_size: the size of blocks
    q: the number of leading blocks used for the initialization.

  Returns:
    a p-value
  """
  blocks = util.SplitSequence(bits, n, block_size)
  k = len(blocks) - q
  mean, std = UniversalDistribution(block_size, k)

  # Initialization: after this step tab[b] contains the position
  # of the last occurrence of b or -1 if b did not occur.
  tab = [-1] * 2**block_size
  for i in range(q):
    tab[blocks[i]] = i

  sumb = 0.0
  for j in range(q, q + k):
    b = blocks[j]
    sumb += math.log(j - tab[b], 2)
    tab[b] = j
  f = sumb / k
  p_value = math.erfc(abs(f - mean) / std / math.sqrt(2))
  return p_value


def Universal(bits: int, n: int) -> float:
  """Maurer's universal test.

  The test is described in Section 2.9 of NIST SP 800-22.

  Args:
    bits: the bit string to test
    n: the length of the bit string

  Returns:
    a p-value

  Raises:
    InsufficientDataError: if n < 387840. Smaller inputs can be tested
        with UniversalImpl, but the caller has to choose the parameters k and
        q and has to expect that the results become unreliable.
  """
  # NIST SP 800-22 recommends the following parameters for Maurer's
  # universtal test:
  # n should satisfy n >= min_n[block_size]
  # q = 10 * 2**block_size
  min_n = {
      6: 387840,
      7: 904960,
      8: 2068480,
      9: 4654080,
      10: 10342400,
      11: 22753280,
      12: 49643520,
      13: 107560960,
      14: 231669760,
      15: 496435200,
      16: 1059061760,
  }
  if n < min_n[6]:
    raise InsufficientDataError("Not enough data for Universal")
  block_size = min(size for (size, bound) in min_n.items() if bound <= n)
  q = 10 * 2**block_size
  return UniversalImpl(bits, n, block_size, q)


def LinearComplexityImpl(blocks: list[int], m: int) -> NamedPValues:
  # pyformat: disable
  """Performs the linear complexity test.

  This test computes the linear complexity of all the blocks then
  checks if the distribution of the results deviates from random data.
  Described in section 3.11 of NIST SP 800-22.

  The test proposed by NIST essentially ignores single extreme results
  from Berlekamp-Massey. E.g. getting a linear complexity that differs from
  the median by more than 16 has a probability < 2^-32. To catch such cases
  we compute another p-value.
  This test uses that the probilities for linear complexities are all
  powers of two and that the distribution can be simulated with coin tosses.
  I.e., if m is sufficiently large (e.g. m > 25) then the distribution of
  the linear complexities and the distribution of throwing a coin until head
  comes up are almost equal. E.g., assuming m is even then:

    prob(LFSR-length = m/2)     = prob(head after one toss)     = 1/2,
    prob(LFSR-length = m/2 + 1) = prob(head after two tosses)   = 1/4,
    prob(LFSR-length = m/2 - 1) = prob(head after three tosses) = 1/8,
    prob(LFSR-length = m/2 + k) = prob(head after 2*k tosses)   = 1/2**(2*k),
    prob(LFSR-length = m/2 - k) = prob(head after 2*k+1 tosses) = 1/2**(2*k+1).

  The equivalence breaks down for LFSR-length = 0. The assumption is that m
  is large enough, so that this event is negligible.

  Hence, if a random bit string has linear complexity c, and
  LfsrLogProbability(m, c) = 2^(-x) then we may compare this getting
  a first head after x coin tosses. Similarly an experiment with an array
  lfsr_length as result corresponds to getting len(lfsr_length) heads after
  tossing a coin q times, where

    q = -sum(LfsrLogProbability(m, c) for c in lfsr_length)

  Thus the second p-value is defined as the probability of needing q or more
  coin tosses to get len(lfsr_length) times head.

  Example: Assume that 3 bit strings of length 100 are tested and that the
  shortest LFSRs for these strings have length 50, 51 and 48 respectively.
  The probabilites that random bit string have LFSRs of length 50, 51 and 48
  are 1/2, 1/4 and 1/32. Hence, the combined probability to get the result
  (50, 51, 48) is 1/256. The test asks for the total probability of all
  outcomes where the probability of an individual outcome is <= 1/256.
  In this case the probability of all such outcomes is 29/128. Hence, the
  p-value for this experiment would be 29/128.
  One way to derive this probability is to equate the linear complexities with
  coin tosses. Here the outcome (50, 51, 48) corresponds to HTHTTTTH.
  The p-value is equal to the probability of getting the third head after 8 or
  more tosses. This is equal to the probability of getting head at most twice
  in 7 tosses. I.e., the p-value is

    (binomial(7, 0) + binomial(7, 1) + binomial(7,2)) / 128 = 29/128

  Args:
    blocks: a list of bit strings of size m
    m: the size of the bit strings in blocks.

  Returns:
    a list of tuples (description, p-value).
  """
  # pyformat: enable
  lfsr_length = [berlekamp_massey.LinearComplexity(b, m) for b in blocks]
  median = (m + 1) // 2
  # A random sequence has linear complexity equal to median with probability
  # 1/2. pi contains the following probabilities for the linear complexity of
  # a random bit string:
  # pi[0] = prob(size <= median - 3)
  # pi[j] = prob(size == median - 3 + j) for 1 <= j <= 5
  # pi[6] = prob(size >= median + 3)
  if m % 2 == 0:
    pi = [1 / 96, 1 / 32, 1 / 8, 1 / 2, 1 / 4, 1 / 16, 1 / 48]
  else:
    pi = [1 / 48, 1 / 16, 1 / 4, 1 / 2, 1 / 8, 1 / 32, 1 / 96]
  k = 6
  v = [0] * (k + 1)
  for length in lfsr_length:
    if length <= median - 3:
      v[0] += 1
    elif length >= median + 3:
      v[6] += 1
    else:
      v[length - median + 3] += 1
  p_value1 = ChiSquare(v, pi, k)

  # Computes an additional p-value that was not proposed by NIST.
  q = -sum(berlekamp_massey.LfsrLogProbability(m, c) for c in lfsr_length)
  p_value2 = util.BinomialCdf(len(lfsr_length) - 1, q - 1)
  return [("distribution", p_value1), ("extreme values", p_value2)]


def LinearComplexity(bits: int, n: int, block_size: int) -> NamedPValues:
  """Performs the linear complexity test.

  Described in section 3.11 of NIST SP 800-22.

  Args:
    bits: a bit string
    n: the length of the bit string
    block_size: the size of the blocks. Nist recommends sizes in the range 500
      .. 5000.

  Returns:
    a pair of p-values. The first p-value is the one described
    by NIST, the second p-value is an additional value that tries
    to catch cases with extreme outliers.
  Raises:
    InsufficientDataError: if the size of the input is too small.
  """
  # Sections 2.10.7 and 3.10 discuss limitiations of the test.
  # The distribution for the LFSR lengths are exact even for small values of
  # bits. Hence the test can be performed with small values. NIST is too
  # conservative here.
  # For example https://smartfacts.cr.yp.to/smartfacts-20130916.pdf contains
  # a list of weak primes. Some these primes have patterns that can be easily
  # recognized even with small block sizes. Thus running the LinearComplexity
  # test on samples of smaller blocks would be reasonable.
  if block_size < 10:
    raise InsufficientDataError("Small block size")
  # NIST recommends to use at least 200 blocks. The reason for this
  # recommendation is unclear.
  if block_size * 200 > n:
    raise InsufficientDataError("Not enough blocks")
  blocks = util.SplitSequence(bits, n, block_size)
  return LinearComplexityImpl(blocks, block_size)


def Serial(bits: int, n: int, m_max: Optional[int] = None) -> NamedPValues:
  """Serial test.

  Described in section 3.11 of NIST SP 800-22.

  This test divides a bit string into small overlapping subsequences of size m,
  where m ranges from 2 to m_max. The test checks whether the number
  of occurrences of each m-bit subsequence deviates from random data.

  Args:
    bits: the bit string to test
    n: the length of the bit string
    m_max: the maximal size of the subsequences. If m_max is None then the bound
      given by NIST SP 800-22 in Section 2.11.7 is used.

  Returns:
    a list of tuples (description, p-value).
  """
  # TODO(bleichen): lcgnist consistently returns p-values close to 1.0. Hence,
  #   the test is able to distinguish lcgnist from random input. An additional
  #   p-value for such occurrences would make sense.
  # Section 2.11.7 recommends an upper bound for m.
  # If this bound is not applicable then just m=2 is tested.
  if m_max is None:
    m_max = max(2, min(22, n.bit_length() - 4))

  v = [0] * (m_max + 1)
  count = util.FrequencyCount(bits, n, m_max)
  for m in range(m_max, 0, -1):
    sumc = sum(x**2 for x in count)
    v[m] = sumc * 2**m / n - n
    count = [count[i] + count[i + 1] for i in range(0, len(count), 2)]
  p_values = []
  for m in range(2, m_max + 1):
    d_psi = v[m] - v[m - 1]
    d2_psi = v[m] - 2 * v[m - 1] + v[m - 2]
    p_value1 = util.Igamc(2**(m - 2), d_psi / 2)
    p_value2 = util.Igamc(2**(m - 3), d2_psi / 2)
    p_values.append((f"m={m} p-value1", p_value1))
    p_values.append((f"m={m} p-value2", p_value2))
  return p_values


def ComputeApproximateEntropy(frequencies: list[int]) -> float:
  """Computes the approximate entropy given a list of frequencies.

  Args:
    frequencies: a list of frequencies

  Returns:
    an approximate entropy
  """
  n = sum(frequencies)
  entropy = 0.0
  for c in frequencies:
    if c:
      p = c / n
      entropy += p * math.log(p)
  return entropy


def ApproximateEntropy(bits: int,
                       n: int,
                       m_max: Optional[int] = None) -> NamedPValues:
  """Approximate entropy test.

  Described in section 3.12 of NIST SP 800-22. The test is based on the paper
  "Approximate Entropy for Testing Randomness" by A. L. Rukhin.
  This paper proves an asymptotic distribution for the approximate entropy.

  Args:
    bits: the bit string to test
    n: the length of the bit string
    m_max: the test uses the values 2 upto and including m_max for the block
      size m. If m_max is None then the bound recommended in Section 2.12.7 is
      used. In some cases the bound recommended by NIST is too large. Then m_max
      is reduced further.

  Returns:
    a list of tuples (name, p_value). The test returns one p-value for each
    block size m that was tested.
  """
  # TODO(bleichen): lcgnist could be detected with this test.
  #   lcgnist returns a p-value very close to 1.0 for large m.
  #   Hence an additional p-value for detecting such cases might
  #   make sense.
  if m_max is None:
    # TODO(bleichen): n.bit_length() - 7 is proposed by NIST as the upper
    #   bound for m_max. Section 4.3 note (f), points out that the
    #   approximate entropy test may not work for large m.
    #   Testing has shown that the bound proposed by NIST is too optimisitic.
    #   The bounds below are based on experiments only. They simply try to
    #   exclude cases where tests with urandom gave p-values that are
    #   significanly lower then expected.
    #   A more accurate computation of the p-value would be preferable.
    if n < 2**16:
      m_max = max(2, n.bit_length() - 7)
    elif n < 2**20:
      m_max = n.bit_length() - 8
    elif n < 2**24:
      m_max = n.bit_length() - 9
    else:
      m_max = min(22, n.bit_length() - 10)
  phi = {}
  count = util.FrequencyCount(bits, n, m_max + 1)
  for m in range(m_max + 1, 1, -1):
    phi[m] = ComputeApproximateEntropy(count)
    count = [count[i] + count[i + 1] for i in range(0, len(count), 2)]
  p_values = []
  for m in range(2, m_max + 1):
    ap_em = phi[m] - phi[m + 1]
    chi_square = 2 * n * (math.log(2) - ap_em)
    p_value = util.Igamc(2**(m - 1), chi_square / 2)
    p_values.append((f"m={m}", p_value))
  return p_values


def CumulativeSumsPValue(n: int, z: int) -> float:
  """Computes the p-value for the Cumulative sum test.

  This is based on NIST SP 800-22, as well as
  https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc323.htm
  https://www.itl.nist.gov/div898/software/dataplot/refman1/auxillar/cusumtes.htm

  Args:
    n: the size of the bit string
    z: The maximal absolute value of the cumulative sum.

  Returns:
    a p-value
  """
  t = z / math.sqrt(2 * n)
  # The bounds mink and maxk determine the accuracy of the result.
  mink = (-n / z + 1) / 4
  maxk = (n / z - 1) / 4
  k = math.ceil(mink)
  res = 0.0
  while k <= maxk:
    res += math.erf((4 * k - 1) * t)
    res -= math.erf((4 * k + 1) * t)
    k += 1
  # The bounds mink and maxk determine the accuracy of the result.
  mink = (-n / z - 3) / 4
  maxk = (n / z - 1) / 4
  k = math.ceil(mink)
  while k <= maxk:
    res -= math.erf((4 * k + 1) * t)
    res += math.erf((4 * k + 3) * t)
    k += 1
  return 1.0 + res / 2


def RandomExcursionsDistribution(x: int, max_cnt: int = 5) -> list[float]:
  """Returns the probability distribution for the random excursions test.

  The probability distribution is described in Section 3.14 of NIST SP 800-22.

  Args:
    x: the state
    max_cnt: maximal number of visits of a state used in the test.

  Returns:
    a list of max_cnt + 1 probabilities. The last element of this
    list is the sum of all probabilities for k >= max_cnt.
  """
  pi = [0] * (max_cnt + 1)
  t = 1 / (2 * abs(x))
  pi[0] = 1 - t
  for k in range(1, max_cnt):
    pi[k] = t**2 * (1 - t)**(k - 1)
  pi[max_cnt] = t * (1 - t)**(max_cnt - 1)
  return pi


def RandomWalk(bits: int,
               n: int,
               max_state: int = 4,
               max_cnt: int = 5,
               max_state_variant: int = 9) -> NamedPValues:
  """Random walk.

  Performs the test described in Section 2.13, 2.14, 2.15 of NIST SP 800-22.

  The tests perform a random walk based on the cumulative sums of the bits
  in the bit string to test and determine if the results deviate from random
  input.

  The cumulative sum test described in Section 2.13 analyzes the maximal
  distance of the random walk from the origin.

  The random excursions test described in Section 2.14 divides the random
  walk into cycles, where each cycle starts at the origin. The test analyzes
  the number of times states close to 0 are visited in each cycle.

  The random excursions variant test described in Section 2.15 analyzes the
  number of times states x close to 0 are visited overall. The number of times
  a state in the range -max_state_variant ... max_state_variant is visited
  is expected to be close to the number of times the state 0 is visited.

  Args:
    bits: the bit string to test
    n: the length of the bit string to test
    max_state: the maximal distance from 0 to use in the test. The default is 4,
      which is the number that NIST uses.
    max_cnt: the maximal count for the number of occurrences of a state. The
      default is 5, which is the number that NIST uses.
    max_state_variant: the maximal state for the variant test.

  Returns:
    a list of tuples (test, p-value). The cumulative sums test from Section 2.13
    results in 2 values, both for forward and backward direction. The random
    excursions test from Section 2.14 results in either 2 * max_state values or
    none at all depending on whether there are enough cycles for the evaluation.
    The random excursions variant test from Section 2.15 results in an other
    2 * max_state_variant values if there are enough cycles for evaluation.
  """
  s = 0
  cnts = []
  cnt = collections.defaultdict(int)
  max_state2 = max(max_state, max_state_variant)
  maxs = 0
  mins = 0
  for b in util.Bits(bits, n):
    s += b
    if s > max_state2:
      if s > maxs:
        maxs = s
    elif s < -max_state2:
      if s < mins:
        mins = s
    elif s != 0:
      cnt[s] += 1
    else:
      cnts.append(cnt)
      cnt = collections.defaultdict(int)
  cnts.append(cnt)
  total_cnt = collections.defaultdict(int)
  for cnt in cnts:
    for x, c in cnt.items():
      total_cnt[x] += c
  # mins and maxs are only computed over the states outside the range
  # -max_state2 .. max_state2. In the case that s never reaches these bounds
  # it is possible to determine these values from total_cnt
  if maxs == 0:
    maxs = max(total_cnt)
  if mins == 0:
    mins = min(total_cnt)
  excursions = len(cnts)

  p_values = []
  # Cumulative sums test from Section 3.13
  #
  # This test analyzes the maximal distance of the random walk both in forward
  # and backward direction.
  max_dist_forward = max(maxs, -mins)
  max_dist_backward = max(maxs - s, s - mins)
  p_value_forward = CumulativeSumsPValue(n, max_dist_forward)
  p_value_backward = CumulativeSumsPValue(n, max_dist_backward)
  p_values.append(("cumulative sums forward", p_value_forward))
  p_values.append(("cumulative sums reverse", p_value_backward))

  # Random excursions test from Section 3.14
  #
  # Section 3.14.4 estimates the probability of the total number of excursions.
  # It appears that the equation given in this section underestimates the
  # probability of getting only a small number of cycles.
  # For example the probability of getting a single cycle with 1000000 bits of
  # input is about 0.0008. Hence extreme cases can happen in practice.
  # Thus, at the moment the test does not give a reliable result and hence
  # cannot run. Equation (12) suggests that the following p-value can be used:
  #   p_value_j = 1 - util.Igamc(1 / 2, excursions**2 / (2 * n))
  # But experiments with os.urandom gave p-values smaller than 10^(-12).

  # An alternative check is described in step 4 of Section 2.14.4. Here NIST
  # simply recommends to abandon the test if the number of excursions is too
  # small. This happens quite frequently. In experiments with 1000000 bits
  # about 1/3 or all checks are abandoned.
  if excursions >= 500:
    for x in range(-max_state, max_state + 1):
      if x != 0:
        v = [0] * (max_cnt + 1)
        for cnt in cnts:
          c = min(max_cnt, cnt[x])
          v[c] += 1
        pi = RandomExcursionsDistribution(x, max_cnt)
        obs = sum((v[k] - excursions * pi[k])**2 / (excursions * pi[k])
                  for k in range(max_cnt + 1))
        p_values.append(
            (f"random excursions {x}", util.Igamc(max_cnt / 2, obs / 2)))

  # Random excursions variant test from Section 3.15.
  if excursions >= 500:
    for x in range(-max_state_variant, max_state_variant + 1):
      if x != 0:
        obs = abs(excursions - total_cnt[x]) / math.sqrt(2 * excursions *
                                                         (4 * abs(x) - 2))
        p_values.append((f"random excursions variant {x}", math.erfc(obs)))

  return p_values
