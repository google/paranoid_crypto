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
from paranoid_crypto.lib.randomness_tests import berlekamp_massey
from paranoid_crypto.lib.randomness_tests import exp1
from paranoid_crypto.lib.randomness_tests import util

# A sequence s = (s_0, s_1, s_2, ...) of bits is represented as an integer
# with value sum(v << i for i,v in enumerate(s)).
BitSequence = int

# Binary polynomials p(x) = c_0 + c_i x + c_2 x^2 + ... are represented as
# an integer with value p(2) computed over Z.
BinPoly = int


def BinMult(x: BinPoly, y: BinPoly) -> BinPoly:
  """Multiplies two binary polynomials.

  Args:
    x: a polynomial
    y: another polynomials

  Returns:
    the product of x and y.
  """
  res = 0
  while x:
    if x & 1:
      res ^= y
    x >>= 1
    y <<= 1
  return res


def RandomBits(n: int) -> int:
  """Generates a random bit sequence.

  Args:
    n: the number of random bits

  Returns:
    a random value in the range(0, 2**n)
  """
  bits = int.from_bytes(os.urandom((n + 7) // 8), "little")
  if n % 8:
    bits >>= -n % 8
  return bits


def ShortestLfsrWithInvariants(s: BitSequence,
                               length: int,
                               check: bool = True) -> tuple[int, BinPoly]:
  """An full implementation of Berlekamp-Massey for binary sequences.

  This function differs from LinearComplexity as follows:
  (1) the feedback polynomial is also computed
  (2) loop invariants are added to the function. The loop invariants
      are tested if check == True.
  (3) the main purpos of this function is to document the function
      LinearComplexity. Without the computation of the feedback pllynomials
      it may be difficult to explain the function.

  Args:
    s: the bit sequence.
    length: the length of the sequence
    check: if True then all loop invariants are checked during computation

  Returns:
    a tuple (length, c), where length is the length of the shortest LFSR for
    sequence s and c is the corresponding feedback polynomial.
  """
  b, c = 1, 1
  sb, sc = s, s
  # The maximal degree of B and C.
  deg_b, deg_c = 0, 0
  m = 0
  for n in range(length):
    # Checks the loop invariants
    if check:
      assert deg_b + deg_c == n
      # c has degree deg_c or smaller
      assert c.bit_length() <= deg_c + 1
      # b has degree deg_b or smaller
      assert b.bit_length() <= deg_b + 1
      # Bit 0 of c is always set. This condition asserts that the discrepancy is
      # the same as sc & 1.
      assert c % 2 == 1
      # sb and sc are incrementally updated so that the following properties
      # hold:
      sbn = BinMult(s, b)
      scn = BinMult(s, c)
      assert sbn >> n == sb
      assert scn >> n == sc >> m
      if n >= 1:
        assert (sbn % (1 << (n - 1))).bit_length() <= deg_b + 1
        assert (scn % (1 << n)).bit_length() <= deg_c + 1
    disc = sc & (1 << m)
    m += 1
    b <<= 1
    deg_b += 1
    if disc:
      sc >>= m
      m = 0
      if deg_c < deg_b:  # Same as L <= n/2
        b, c = c, b
        sb, sc = sc, sb
        deg_b, deg_c = deg_c, deg_b
      c ^= b
      sc ^= sb
  return deg_c, c


def BerlekampMasseyWikipedia(seq: BitSequence,
                             length: int) -> tuple[int, BinPoly]:
  """Berlekamp-Massey implementation based on wikipedia.

  This implementation is a typical way to implement Berlekamp-Massey.
  It follows the algorithm for binary fields described here:
  https://en.wikipedia.org/w/index.php?title=Berlekamp%E2%80%93Massey_algorithm&oldid=956482144

  Args:
    seq: the bit sequence
    length: the length of S

  Returns:
    a tuple (deg_c, c), where deg_c is the length of the shortest LFSR for s
    and c is the feedback polynomial.
  """
  s = [(seq >> i) & 1 for i in range(length)]
  # NOTE(bleichen): I'm adding a minor bug fix at this point.
  #   The code on wikipedia only used arrays of size length.
  #   As a result b and c could only represent polynomials of degree length-1.
  #   Degenerated sequences such as 0, 0, 0, 1 require LFSR of size length,
  #   hence requiring arrays of size length + 1.
  #   The algorithm from Wikipedia would return the correct length of the LFSR,
  #   but return an incorrect feedback polynomial.
  b = [0] * (length + 1)
  c = [0] * (length + 1)
  b[0] = 1
  c[0] = 1
  deg_c = 0
  m = -1
  for n in range(length):
    d = (s[n] + sum(c[i] * s[n - i] for i in range(1, deg_c + 1))) % 2
    if d:
      t = c[:]
      for i in range(length + 1 - n + m):
        c[n - m + i] = c[n - m + i] ^ b[i]
      if 2 * deg_c <= n:
        deg_c = n + 1 - deg_c
        m = n
        b = t
  feedback_poly = sum(ci << i for i, ci in enumerate(c))
  return deg_c, feedback_poly


class BerlekampMasseyTest(absltest.TestCase):

  def CompareImplementations(self,
                             seq: BitSequence,
                             length: int,
                             check_invariants: bool = True):
    """Compares multiple implementations with each other.

    Args:
      seq: the bit sequence to test
      length: the length of the bit sequence
      check_invariants: determines whether ShortestLfsrWithInvariants should
        check the loop invariants during the computation.
    """
    len_a = berlekamp_massey.LinearComplexity(seq, length)
    len_b = berlekamp_massey.LinearComplexityNative(seq, length)
    len_c, poly_c = ShortestLfsrWithInvariants(seq, length, check_invariants)
    len_d, poly_d = BerlekampMasseyWikipedia(seq, length)
    self.assertEqual(len_a, len_b)
    self.assertEqual(len_a, len_c)
    self.assertEqual(len_a, len_d)
    self.assertEqual(poly_c, poly_d)

  def testShortSequences(self):
    for seq in range(1, 1100):
      self.CompareImplementations(seq, seq.bit_length())

  def testLongSequence(self):
    for length in (255, 256, 257):
      seq = RandomBits(length)
      self.CompareImplementations(seq, length)

  def testLeadingZeros(self):
    """Sequences with leading zeros are degenerate cases.

    Especially the sequence 0, 0, 0, ..., 1 leads to a feedback polynomial
    of maximal degree.
    """
    for seq in range(1, 130):
      for zeroes in (1, seq.bit_length(), 2 * seq.bit_length()):
        self.CompareImplementations(seq, seq.bit_length() + zeroes)

  def testTrailingZeros(self):
    """Tests sequences with trailing zeroes."""
    for seq in range(1, 130):
      for zeroes in (seq.bit_length(), 2 * seq.bit_length(),
                     3 * seq.bit_length()):
        self.CompareImplementations(seq << zeroes, seq.bit_length() + zeroes)

  def testLeadingAndTrailingZeros(self):
    """Tests sequences with leading and trailing zeroes."""
    for seq in range(1, 130):
      for zeroes in (seq.bit_length(), 2 * seq.bit_length()):
        self.CompareImplementations(seq << zeroes,
                                    seq.bit_length() + 2 * zeroes)

  def testZeroesInTheMiddle(self):
    """Tests sequences of the form 1, 0, 0, ..., 0, 0, 1."""
    for length in (30, 31, 32, 33):
      seq = 2**(length - 1) ^ 1
      self.CompareImplementations(seq, length)

  def testLongRandom(self):
    size = 8 * 100000  # should take about 1s
    seq = RandomBits(size)
    lfsr_len = berlekamp_massey.LinearComplexity(seq, size)
    # The probability of this test failing is about 2^-40
    self.assertBetween(lfsr_len, size // 2 - 20, size // 2 + 20)

  def testLfsrCount(self):
    for length in (9, 10):
      count = [0] * (length + 1)
      for seq in range(2**length):
        linear_complexity = berlekamp_massey.LinearComplexity(seq, length)
        count[linear_complexity] += 1
      for i in range(length + 1):
        self.assertEqual(berlekamp_massey.LfsrCount(length, i), count[i])

  def testLfsrCountExp1(self):
    size = 1000000
    m = 1000
    bits = exp1.bits(size)
    count = collections.defaultdict(int)
    for seq in util.SplitSequence(bits, size, m):
      linear_complexity = berlekamp_massey.LinearComplexity(seq, m)
      count[linear_complexity] += 1
    # Matches NIST SP 800-22, section 2.10.8, since v_0 = 11 is the number of
    # sequences with lin. compl. <= 497 and v_6 = 26 is the number of sequences
    # with lin. compl. >= 503.
    expected = {
        495: 2,
        497: 9,
        498: 31,
        499: 116,
        500: 501,
        501: 258,
        502: 57,
        503: 21,
        504: 4,
        505: 1
    }
    self.assertEqual(expected, count)

  def testLfsrLogProbability(self):
    self.assertAlmostEqual(-1, berlekamp_massey.LfsrLogProbability(8, 4))
    self.assertAlmostEqual(-1, berlekamp_massey.LfsrLogProbability(9, 5))
    self.assertAlmostEqual(-2, berlekamp_massey.LfsrLogProbability(8, 5))
    self.assertAlmostEqual(-2, berlekamp_massey.LfsrLogProbability(9, 4))
    self.assertAlmostEqual(
        1.0,
        sum(2**berlekamp_massey.LfsrLogProbability(8, i) for i in range(9)))
    self.assertAlmostEqual(
        1.0,
        sum(2**berlekamp_massey.LfsrLogProbability(9, i) for i in range(10)))


if __name__ == "__main__":
  absltest.main()
