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
"""Implements the Berlekamp-Massey algorithm."""

# pybind version
from paranoid_crypto.lib.randomness_tests.cc_util.pybind import berlekamp_massey


def LinearComplexity(s: int, length: int) -> int:
  """Computes the linear complexity of a sequence with Berlekamp-Massey.

  The Berlekamp-Massey algorithm finds the shortest LFSR that produces the bits
  of a sequence s. This implementation is specialized for binary sequences.
  The implementation here only returns the length of the shortest LFSR, but
  not the feedback polynomial itself. This is the only result needed to
  determine the linear complexity of a sequence.

  Args:
    s: the bit-sequence s_0, s_1, ... s_length-1 represented as s = sum(2 ** i *
      s_i for i = 0 .. length-1).
    length: the length of the bit sequence.

  Returns:
    the length of the shortest LFSR generating the bit sequence
  """
  size = (length + 7) // 8
  if not 0 <= size < 2**31:
    raise ValueError("Size out of range")
  ba = s.to_bytes(size, "little")
  return berlekamp_massey.LfsrLength(ba, length)


def LinearComplexityNative(s: int, length: int) -> int:
  """Native implementation of Berlekamp-Massey.

  LinearComplexityNative and LinearComplexity are identical functions.
  The algorithm used here is described in the paper "Algorithm 970: Optimizing
  the NIST Statistical Test Suite and the Berlekamp-Massey Algorithm",
  ACM Transactions on Mathematical Software, vol. 43, num. 3, Sep. 2017.

  A straight forward implementation of the Berlekamp-Massey algorithm keeps
  two polynomials B and C, which are short LFSR's for subsequences of s.
  The Berlekamp-Massey algorithm iteratively computes new polynomials from
  B and C by computing a discrepancy derived from the product s * C.
  Computing the discrepancy typically is the most time consuming loop in a
  Berlekamp-Massey implementation. This loop can be avoided by computing
  the products s * B and s * C incrementally. The complexity of the algorithm
  remains the same: O(length^2). However, incrementally updating s * B and
  s * C can be done by using logical operations over integers. Especially
  in Python it is much faster to perform single logical operations than to
  loop over each bit of the same integer, thus leading to a significant
  constant factor speedup.

  There exist faster algorithms with a time complexity smaller than O(length^2).
  For example it is possible to use Karatsuba multiplication to compute
  parts of s * B and s * C. Such implementations are much more complex and may
  not give a lot of improvement for typical sequences of a few thousand bits.

  Args:
    s: the bit-sequence s_0, s_1, ... s_length-1 represented as s = sum(2 ** i *
      s_i for i = 0 .. length-1).
    length: the length of the bit sequence.

  Returns:
    the length of the shortest LFSR generating the bit sequence
  """
  if length < 0:
    raise ValueError("Bit sequence cannot have negative length")
  sb, sc = s, s
  deg_c = 0
  m = 0
  for n in range(length):
    disc = sc & (1 << m)
    m += 1
    if disc:
      sc >>= m
      m = 0
      if 2 * deg_c <= n:
        sb, sc = sc, sb
        deg_c = n + 1 - deg_c
      sc ^= sb
  return deg_c


def LfsrCount(n: int, m: int) -> int:
  """Returns the number of n-bit sequences where the shortest LFSR has length m.

  The probability that a random n-bit sequence has an LFSR of length m is
  LfsrCount(n, m) / 2 ** n.

  This distribution is used in the LinearComplexity test of NIST SP 800-22.
  Args:
    n: the length of the bit sequences
    m: the size of the shortest LFSR

  Returns:
    The number of n-bit sequences having a shortest LFSR of size m.
  """
  if m < 0 or n <= 0 or m > n:
    return 0
  elif m == 0:
    return 1
  elif m <= n // 2:
    # Result is always an int since m >= 1
    return int(2 * 4**(m - 1))
  else:
    # Result is always an int since n >= m
    return int(4**(n - m))


def LfsrLogProbability(n: int, m: int) -> int:
  """Returns log_2 of the prob.

  that an n-bit sequence has an LFSR of length m.

  This value can be used for an entropy test. Such a test is complementary
  to the NIST test. It give a large weight to unlikely outliers. These are
  cases that NIST's test ignore.

  Args:
    n: the length of a bit sequence
    m: the length of the shortest LFSR.

  Returns:
    an integer x, such that 2^(-x) is the probability that a random bit string
    of length n has an LFSR of size m.
  """
  if n <= 0:
    raise ValueError("n must be positive")
  if m < 0 or m > n:
    raise ValueError("m must be in range 0 .. n")
  if m == 0:
    return -n
  elif m <= n // 2:
    return 2 * m - n - 1
  else:
    return n - 2 * m
