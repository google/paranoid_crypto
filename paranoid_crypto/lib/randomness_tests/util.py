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
"""Implements common functions used by NIST SP-800 22."""

import array
from collections.abc import Iterator
import math
import gmpy
import numpy
from scipy import fftpack as scipy_fft
from scipy import special as scipy_special
from scipy import stats as scipy_stats


def BitCount(s: int) -> int:
  """Counts the number of bits in an integer.

  Python 3.10 will allow to use s.bit_count().

  Args:
    s: a non-negative integer

  Returns:
    the number of 1 bits in s.
  """
  return gmpy.popcount(s)


def Igamc(a: float, x: float) -> float:
  """Computes the regularized upper incomplete gamma function.

  NIST defines the function in section 5.5.3 of NIST SP-800 22 and calls
  it igmac. Wikipedia denotes the function as Q(a, x).

  The function is mainly used to compute p-values for statistical tests.
  The result does not have to be very precise (e.g. 6 digits of precision are
  more than enough). However, the implementation is expected to handle
  floating point underflows and return 0 in such cases.

  Args:
    a: a positive floating point number
    x: floating point number that is 0 or positive

  Returns:
    a p-value
  """
  return scipy_special.gammaincc(a, x)


def NormalCdf(x: float, mean: float, variance: float) -> float:
  """Cumulative distribution function of the normal distribution.

  See en.wikipedia.org/wiki/Normal_distribution
  NIST SP 800-22a defines in Section 5.5.3 a function Cdf. This is
  the same as NormalCdf with mean 0.0 and variance 1.0.

  Args:
    x: a value in the range -infinity .. infinity
    mean: the mean value of the distribution
    variance: the variance of the distribtuion

  Returns:
    a p-value
  """
  return (1 + math.erf((x - mean) / math.sqrt(2 * variance))) / 2


def BinomialCdf(n: int, m: int) -> float:
  """Returns the probability to get at most n heads when throwing m coins.

  Args:
    n: the maximal number of heads in m coin tosses.
    m: the number of coin tosses

  Returns:
    the probability to get at most n heads when throwing m coins.
  """
  return scipy_stats.binom.cdf(n, m, 0.5)


def UniformSumCdf(n: int, x: float) -> float:
  """Cumulative distribution function of the Irwing-Hall distribution.

  Args:
    n: the number of random variables
    x: the bound

  Returns:
    the probability that the sum of n uniform variables in the range 0..1
    is smaller than x.
  """
  # Source: en.wikipedia.org/wiki/Irwin-Hall_distribution
  # The forumla given there contains very large terms when n is large.
  # Hence it loses precision fast.
  # There may be a better way to compute this distribution.
  # Scipy might add this function github.com/scipy/scipy/issues/14806
  if x <= 0:
    return 0.0
  elif 2 * x > n:
    return 1.0 - UniformSumCdf(n, n - x)
  # For large n it is faster and more accurate to approximate
  # the distribution with a normal distribution. The bound 36 below is just
  # based on experimentation.
  elif n > 36:
    return NormalCdf(x, n / 2, n / 12)
  else:
    p_value = 0.0
    sign = 1  # (-1)**k
    binom = 1  # Binomial(n, k)
    f = math.factorial(n)
    for k in range(math.floor(x) + 1):
      t = sign * binom / f * (x - k)**n
      p_value += t
      sign = -sign
      binom = binom * (n - k) // (k + 1)
    return p_value


def CombinedPValue(pvalues: list[float]) -> float:
  """Computes a combined p-value for a list of p-values.

  When tests are repeated then the result of these tests is a list of p-values.
  Thus we have to decide whether contains sufficiently small p-values to reject
  the null hypothesis (i.e. reject the assumption that the pseudo random numbers
  are indistinguishable from random data).
  The method here computes s = -sum(math.log(p) for p in pvalues) and returns
  the probability that a list of uniformly distributed p-values results in a
  larger sum. This method was proposed by Fisher in 1934.

  If the p-values are uniformly distributed (as they ideally should)
  then the value s = -sum(math.log(p) for p in pvalues) has an Erlang
  distribution. https://en.wikipedia.org/wiki/Erlang_distribution.
  The survival function of the Erlang distribution with rate 1 is a special
  case of Igamc.

  Different proposals to combine p-values are compared in the paper
  "Choosing Between Methods of Combining p-values" by N. A. Heard and
  P. Rubin-Delanchy, https://arxiv.org/pdf/1707.06897.pdf .

  A criterion used here is that the method should be sensitive to small
  p-values. A pseudo random number generator that sometimes generates weak
  output and sometimes does not is still a weak random number generator.

  Args:
    pvalues: a list of p-values from independent test runs.

  Returns:
    a combined p-value
  """
  if not pvalues:
    raise ValueError("empty sample")
  elif len(pvalues) == 1:
    return pvalues[0]
  elif min(pvalues) == 0:
    return 0
  else:
    s = sum(-math.log(p) for p in pvalues)
    return Igamc(len(pvalues), s)


def _ReversedBytes() -> bytes:
  """Returns a table to reverse bits in a byte array.

  The result of this function can be used to reverse the bits in each byte by
  using bytes.translate() or bytearray.translate().

  Returns:
    the translation table
  """
  res = bytearray(256)
  for j in range(1, 256):
    res[j] = (res[j >> 1] >> 1) ^ ((j & 1) << 7)
  return bytes(res)


_REVERSE_BITS = _ReversedBytes()


def ReverseBits(seq: int, length: int) -> int:
  """Reverses the bits in a bit string.

  Args:
    seq: the bit string
    length: the length of the bit string

  Returns:
    the integer with the bits in reverse order
  """
  # Reverses the bits in each byte of the sequence
  a = seq.to_bytes((length + 7) // 8, "little").translate(_REVERSE_BITS)
  # Reverses the byte order
  b = int.from_bytes(a, "big")
  # Removes extra bits
  c = b >> (-length % 8)
  return c


def Bits(seq: int, length: int) -> array.array:
  """Converts a bit string into an array with elements 1, -1.

  Some tests such a Spectral use a balanced representation of the bits
  in a sequence, i.e. use -1 for each 0 and 1 for each 1 in the bit
  string.

  Args:
    seq: The bit string
    length: the length of the bit string

  Returns:
    an array containing -1 and 1s.
  """
  b = bytes(format(seq, "b"), "ascii")
  tab = bytes.maketrans(b"01", b"\xff\x01")
  res = array.array("b", [-1]) * (length - len(b))
  res.frombytes(b.translate(tab))
  res.reverse()
  return res


def SubSequences(seq: int,
                 length: int,
                 m: int,
                 wrap: bool = True) -> Iterator[int]:
  """Yields all m-bit subsequences of seq.

  The order of the subsequences is not defined. The same subsequence
  is returned multiple times if it occurs multiple times in seq.

  Args:
    seq: a bit-sequence represented as an integer
    length: the length of seq
    m: the length of the subsequence
    wrap: if True allows bit sequences consisting of k least significant bits
      followed by m-k most significant bits

  Yields:
    subsequences of size m
  """
  if m <= 0:
    raise ValueError("m must be positive")
  if length < 0:
    raise ValueError("length must not be negative")
  if seq.bit_length() > length:
    raise ValueError("seq has too many bits")
  if m > length:
    raise ValueError("m must not be larger than length")
  ba = seq.to_bytes((length + 7) // 8, "little")
  mask = (1 << m) - 1
  if wrap:
    start = 0
    s = (seq >> (length - m)) & mask
  else:
    start = m
    s = int.from_bytes(ba[:(start + 7) // 8], "little")
    yield s & mask
  for i in range(start, length):
    if i & 7 == 0:
      s ^= ba[i // 8] << m
    s >>= 1
    yield s & mask


def FrequencyCount(seq: int,
                   length: int,
                   m: int,
                   wrap: bool = True) -> list[int]:
  """Counts the number of occurrences of m-bit subsequences of seq.

  The bit string seq is assumed to be a loop. Hence subsequences
  can consist of j least significant bits followed by m - j most
  significant bits of seq.

  Args:
    seq: the bit string
    length: the length of seq
    m: the length of the subsequences
    wrap: if True then subsequences consisting of k lsbs followed by m - k msbs
      are included in the count.

  Returns:
    a list of size 2**m, where element i contains the number of times the
    m-bit string i occurred in seq.
  """
  if m > length:
    raise ValueError("m must not be larger than length")
  ba = seq.to_bytes((length + 7) // 8, "little")
  if 50 * 2**m < length and m < 24:
    # If 2**m is significantly smaller than length then the following speedup
    # is possible:
    # seq is split into subsequences of length m + 3 using a step size of 4.
    # These subsequences are counted. Each subsequence of length m + 3 contains
    # 4 subsequences of length m. Once the subsequcnes of length m + 3 have
    # been counted it is then possible to also compute the tally of the smaller
    # subsequences of length m.
    m3 = m + 3
    count = [0] * 2**m3
    s = seq >> (length - m3)
    mask3 = (1 << (m3)) - 1
    for j in range(length // 8):
      s ^= ba[j] << m3
      count[s & mask3] += 1
      count[(s >> 4) & mask3] += 1
      s >>= 8
    mask = (1 << m) - 1
    res = [0] * 2**m
    for i, v in enumerate(count):
      res[i & mask] += v
      res[(i >> 1) & mask] += v
      res[(i >> 2) & mask] += v
      res[(i >> 3) & mask] += v
    if length % 8 != 0:
      s ^= ba[-1] << m3
      for j in range(length % 8):
        res[s & mask] += 1
        s >>= 1
  else:
    mask = (1 << m) - 1
    res = [0] * 2**m
    s = seq >> (length - m)
    for j in range(length // 8):
      s ^= ba[j] << m
      res[s & mask] += 1
      res[(s >> 1) & mask] += 1
      res[(s >> 2) & mask] += 1
      res[(s >> 3) & mask] += 1
      res[(s >> 4) & mask] += 1
      res[(s >> 5) & mask] += 1
      res[(s >> 6) & mask] += 1
      res[(s >> 7) & mask] += 1
      s >>= 8
    if length % 8 != 0:
      s ^= ba[-1] << m
      for j in range(length % 8):
        res[s & mask] += 1
        s >>= 1
  # The code above counts the number of subsequences with wrap = True.
  # The simplest way to handle the case wrap=False is to simply remove
  # the subsequences that were overcounted.
  if not wrap:
    mask = (1 << m) - 1
    w = (seq >> (length - m)) | ((seq & mask) << m)
    for i in range(1, m):
      x = (w >> i) & mask
      res[x] -= 1
  return res


def SplitSequence(seq: int, length: int, m: int) -> list[int]:
  """Splits a bit sequence into non-overlapping blocks of size m.

  The splitting starts with the least significant bits. If the length
  of the bit-sequence is not divisible by m then the last block will be
  ignored.


  Args:
    seq: the bit-sequence to split
    length: the length of the bit-sequence
    m: the size of blocks in bits

  Returns:
    a list of blocks
  """
  n = length // m
  res = [0] * n
  size = max((seq.bit_length() + 7) // 8, m * n // 8)
  ba = seq.to_bytes(size, "little")
  if m % 8 == 0:
    # If m is divisible by 8 then it is possible to use byte arrays to speed
    # up the splitting. Using structs for m=8, 16, 32 or 64 is even faster.
    for i in range(n):
      res[i] = int.from_bytes(ba[i * m // 8:(i + 1) * m // 8], "little")
  else:
    mask = (1 << m) - 1
    for i in range(n):
      val = int.from_bytes(ba[i * m // 8:(i + 1) * m // 8 + 1], "little")
      val >>= ((i * m) & 7)
      res[i] = val & mask
  return res


def Scatter(seq: int, m: int) -> list[int]:
  """Divides the bits of seq into m interleaved bit strings.

  Args:
    seq: the bit string
    m: the number of interleaved bit strings

  Returns:
    a list of bit strings, where the i-th value of the result contains the bits
    i, i+m, i+2*m, ... of the input seq.

  """
  # Special case to avoid calling int('', 2)
  if seq.bit_length() < m:
    return [(seq >> i) & 1 for i in range(m)]
  bits = format(seq, "b")
  res = []
  offset = (len(bits) - 1) % m
  for i in range(m):
    start = (offset - i) % m
    res.append(int(bits[start::m], 2))
  return res


def Runs(s: int, length: int) -> int:
  """Computes the number of runs of a bit-sequence.

  A run is a continuous sequence of 0's or a a continuous sequence
  of 1's.

  Args:
    s: the bit-sequence
    length: the length of the bit-sequence

  Returns:
    the number of runs.
  """
  # The i-th bit of s ^ (s >> 1) is 1 iff bit i and i + 1 of s are different.
  # Hence, the bitcount of s ^ (s >> 1) is equal to the number runs, except
  # when the bit-sequence starts with a 0-bit.
  runs = BitCount(s ^ (s >> 1))
  if length and s >> (length - 1) == 0:
    runs += 1
  return runs


def LongestRunOfOnes(seq: int) -> int:
  """Returns the longest run of 1's in a bit sequence.

  Args:
    seq: the bit-sequence

  Returns:
    the largest number of consecutive 1-bits.
  """
  if seq == 0:
    return 0
  # The code below uses the following invariants:
  #   s = seq & (seq >> 1) & (seq >> 2) & ... & (seq >> (longest_run - 1)
  #   LongestRunOfOnes(seq) = LongestRunOfOnes(s) + longest_run - 1
  #   all runs of ones in s are separated by at least longest_run zeros.
  # The code uses the following property:
  # if all runs of ones in s are separated by at least m >= n zeros and
  # s2 = s & (s >> n), then all runs in s2 are shortened by n or disappear
  # if the run was shorter than n. Additionally all runs in s2 are
  # separated by at least m + n zeros.
  # E.g., if   s = 0b1111100011001001111 and n = 2. Then
  # s >> 2       =   0b11111000110010011
  # s & (s >> 2) =   0b11100000000000011
  # The runs of length 5 and 4 are reduced to runs of length 3 and 2. All
  # other runs disappear.
  # The algorithm used here has complexity O(n log(r)), where r is the length
  # of the longest run of ones, but it still is significantly faster than
  # unpacking all the bits of seq.
  s = seq
  longest_run = 1
  while True:
    s2 = s & (s >> longest_run)
    if s2 == 0:
      break
    s = s2
    longest_run *= 2
  n = longest_run // 2
  while n:
    s2 = s & (s >> n)
    if s2:
      s = s2
      longest_run += n
    n //= 2
  return longest_run


def OverlappingRunsOfOnes(seq: int, m: int) -> int:
  """Returns the number of possibly overlapping runs of 1's of length m.

  Example: if seq = 011101111100 and m = 3. Then this function returns
  the number of subsequences of seq that are equal to 111. Since there are
  such subsequences starting at positions 1, 5, 6, and 7 the result would be 4.

  Args:
    seq: the bit string to search
    m: the length of the runs of 1s to search.

  Returns:
    the number of runs of 1's of length m in seq.
  """
  k = 1
  m -= 1
  while m:
    t = min(k, m)
    seq = seq & (seq >> t)
    m -= t
    k *= 2
  return BitCount(seq)


def BinaryMatrixRank(matrix: list[int]) -> int:
  """Computes the rank of a binary matrix.

  The rank of a matrix is the number of linearly independent rows.

  Args:
    matrix: the binary matrix represented as a list of rows.

  Returns:
    the rank of the matrix
  """
  # TODO(bleichen): This function performs a Gauss elimination.
  #   If binary matrices are useful for other purposes then this function
  #   should be refactored, and maybe put into a class for binary matrices.
  for r in matrix:
    if r < 0:
      raise ValueError("rows cannot be negative")
  if len(matrix) < 50:
    return _BinaryMatrixRankSmall(matrix)
  else:
    return _BinaryMatrixRankLarge(matrix)


def _BinaryMatrixRankSmall(matrix: list[int]) -> int:
  """Computes the rank of a binary matrix.

  This implementation is used for small matrices.

  Args:
    matrix: the binary matrix represented as a list of rows.

  Returns:
    the rank of the matrix
  """
  m = matrix[:]
  rank = 0
  for i in range(len(m)):
    if m[i]:
      rank += 1
      msb = 1 << (m[i].bit_length() - 1)
      for j in range(i + 1, len(m)):
        if m[j] & msb:
          m[j] ^= m[i]
  return rank


def _BinaryMatrixRankLarge(matrix: list[int]) -> int:
  """Computes the rank of a binary matrix.

  This implementation is fast for large matrices. The implementation
  selects multiple pivots at once, computes tables with sums of the
  corresponding rows and uses these tables to eliminate all the columns
  of the selected pivots at the same time.

  Args:
    matrix: the binary matrix represented as a list of rows.

  Returns:
    the rank of the matrix
  """
  if not matrix:
    return 0
  m = matrix[:]
  rows = len(m)
  cols = max(r.bit_length() for r in m)
  # Determines the number of columns that are eliminated in one step.
  # This number is based on experiments.
  if rows < 32:
    step = max(1, rows.bit_length() - 2)
  elif rows < 256:
    step = rows.bit_length() - 3
  elif rows < 8192:
    step = rows.bit_length() - 4
  else:
    step = rows.bit_length() - 5
  c_upper = cols
  rank = 0
  while c_upper > 0:
    tab_size = min(c_upper, step)
    # In this step the columns c_lower .. c_upper - 1 are eliminated.
    c_lower = c_upper - tab_size
    # If the i-th bit in mask is set then a pivot for column c_lower + i
    # has been found.
    mask = 0
    # tab[j] is None if j & ~mask != 0.
    # Otherwise tab[j] contains the xor-sum s of rows with the property
    # that (tab[j] >> c_lower) & mask == j.
    # Thus if r is a row of the matrix then the columns c_lower + i
    # for all bits i set in mask can be eliminated by
    # r ^= tab[(r >> c_lower) & mask]
    tab = [None] * 2**tab_size
    tab[0] = 0
    for i in range(rank, rows):
      row_i = m[i]
      row_i ^= tab[(row_i >> c_lower) & mask]
      m[i] = row_i
      msbs = row_i >> c_lower
      if msbs:
        # Not all columns in the range c_lower .. c_upper - 1 have been
        # eliminated. Hence row_i contains a new pivot.
        if i != rank:
          # Switches m[i] and m[rank], so that m[0:rank] contains the rows
          # that have been used for elimination.
          m[i] = m[rank]
          m[rank] = row_i
        rank += 1

        # The new pivot is at column c_lower + pivot_pos.
        # tab is updated, such that tab[j] != None for all j & ~new_mask == 0.
        pivot_pos = msbs.bit_length() - 1
        bit = 1 << pivot_pos
        new_mask = mask ^ bit
        tab[bit] = row_i
        t = mask  # t iterates over all subsets of the bits of mask
        while t:
          a = tab[t]
          b = a ^ row_i
          tab[(a >> c_lower) & new_mask] = a
          tab[(b >> c_lower) & new_mask] = b
          t = (t - 1) & mask
        mask = new_mask
    c_upper = c_lower
  return rank


def Dft(x: list[float]) -> numpy.ndarray:
  """Returns the absolute values of the FFT of x.

  This is described in Section 3.6 of NIST SP 800-22.

  Args:
    x: the input for the FFT. Preferably this should be a power of two, so that
      the FFT can be performed efficiently.

  Returns:
    the ablsolute values of the results of the FFT.
    This function returns an array of the same size as x,
    even though the spectral test only uses the first half.
  """
  return numpy.abs(scipy_fft.fft(x))
