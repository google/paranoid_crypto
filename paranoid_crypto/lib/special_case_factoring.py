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
"""Implements special case factoring algorithms.

The motivaton behind these algorithm is that RSA moduli can often be factored
if partial information about the prime numbers is known.
"""

from typing import Optional
import gmpy
from paranoid_crypto.lib import ntheory_util


def FactorWithGuess(n: int, p_0: int) -> Optional[list[int]]:
  """Tries to factor an RSA modulus n given an approximation p_0 of p.

  The method finds a factorization if p_0 is close enough to a factor p
  of n. It is somewhat tricky to define when an approximation is close enough.
  Typically when the guess p_0 has about the same size as the square root of n
  then a difference abs(p - p_0) up to about 1 / 6 of the bit size of n is
  sufficiently close. If p / q can be approximated by a fraction with small
  numerator and denominator then a difference up to about 1 / 4 of the bit
  size of n is sufficient.

  This implementation is based on a method by Lehman proposed in the paper
  "Factoring large integers", Math. Comp. 28:637-646. (See also
  Section 5.1.2 of "Prime numbers, a computational perspective" 2nd ed.,
  by Crandall and Pomerance.)

  The motivation for this implementation is the paper
  "Factoring RSA keys from certified smart cards: Coppersmith in the wild"
  https://smartfacts.cr.yp.to/smartfacts-20130916.pdf
  Appendix A of this paper contains a list of prime factors of weak RSA
  moduli found in the wild. A number of these prime factors have a pattern
  that is easy to guess, except for the last few bits.

  Coppersmith has proposed an algorithm that can factor RSA keys with weaker
  guesses, (i.e. for an 2048-bit RSA key it could recover up to 512 bits of
  a factor p, given the 512 most significant bits of p.)
  https://en.wikipedia.org/wiki/Coppersmith_method
  This method, however requires much more CPU time and it is unclear if it
  would give much better results. Coppersmith's method requires an
  implementation of the Lenstra-Lenstra-Lovasz lattice basis reduction
  algorithm. This is somewhat tricky to implement efficiently. Hence this is
  something that might be attempted using sagemath.

  Args:
    n: an RSA modulus
    p_0: a guess for a factor p

  Returns:
    A factorization [p, q] of n or None if no factor could be found.

  """
  q_0 = n // p_0

  # Finds an approximation bound = n ** (1 / 3)
  # Converting a large integer to float can overflow.
  # To avoid this the cube root of n // 2**(3*shift) is computed instead.
  bits = n.bit_length()
  shift = max(0, (bits // 3) - 52)
  bound = int((n >> (3 * shift))**(1 / 3)) << shift

  for _, u, v in ntheory_util.ContinuedFraction(p_0, q_0):
    # An approximation u / v of p_0 / q_0 is good enough for this factoring
    # method abs(u * q_0 - v * p_0) < bound.
    # Lehman proves that such a pair (u, v) exists with u * v <= n^(1/3).
    # The main idea is that in this case u * q is close to v * p.
    # Therefore, applying Fermat's method to 4 * u * v * n = (2 * u * q) *
    # (2 * v * p) finds the factorization if p_0 is a close approximation of p.
    # Multiplying by 4 is done, because u*q or v*p can be even. Fermat's
    # method does not work if one of the factors is even and the other one is
    # odd.
    if abs(u * q_0 - v * p_0) < bound:
      d = 4 * u * v * n
      a = gmpy.sqrt(d)
      if a * a < d:
        a += 1
      if gmpy.is_square(a * a - d):
        b = gmpy.sqrt(a * a - d)
        g = gmpy.gcd(a + b, n)
        if 1 < g < n:
          return [g, n // g]
      return None
  return None
