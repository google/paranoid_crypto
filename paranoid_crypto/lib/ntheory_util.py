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
"""Set of useful number theory functions."""

import itertools
from typing import Optional
import gmpy


def FastProduct(values: list[int]) -> int:
  """Returns a product computed using a product tree.

  Args:
    values: List of values to calculate the product.
  """
  if not values:
    return 1
  while len(values) > 1:
    pairwise = itertools.zip_longest(values[::2], values[1::2], fillvalue=1)
    values = [a * b for a, b in pairwise]
  return values[0]


def ExtendedProductTree(values: list[int]) -> tuple[list[list[int]], int]:
  """Returns a product tree and a value T.

  The value T is defined as T = sum(P//v for v in values), where P is the
  product of values. T has the property that T % v == P // v % v for all
  values v. This allows to do the BatchGCD without using squared moduli, so is
  faster than the one presented in http://facthacks.cr.yp.to/batchgcd.html.

  Args:
    values: List of values to calculate the product.
  """
  prod_tree = [values]
  t = [1] * len(values)
  while len(values) > 1:
    last_t = t[-1]
    quadruplewise = zip(t[::2], t[1::2], values[::2], values[1::2])
    t = [a * d + b * c for a, b, c, d in quadruplewise]
    if len(values) % 2 == 1:
      t.append(last_t)
    pairwise = itertools.zip_longest(values[::2], values[1::2], fillvalue=1)
    values = [a * b for a, b in pairwise]
    prod_tree.append(values)

  return prod_tree, t[0]


def Inverse2exp(n: int, k: int) -> Optional[int]:
  """Computes the inverse of n modulo 2**k.

  Args:
    n: an odd value that is inverted
    k: the exponent of the modulus 2**k

  Returns:
    a, such that 1 == a * n % 2**k or None if no inverse extists.
  """
  if n % 2 == 0:
    return None
  a = n % 4
  t = 2
  while t < k:
    # This loop invariant is a*n % 2**t == 1.
    # Assuming that the loop invariant holds at the beginning of the loop,
    # it can be shown that it also must hold at the end of the loop:
    # a*n % 2**t == 1 implies that 2**t divides (a*n - 1).
    # Hence 2**(2*t) divides (a * n - 1)**2 = a * n * (a * n - 2) + 1,
    # and hence a * n * (2 - a * n) % 2**(2*t) == 1.
    t = min(k, 2 * t)
    a = gmpy.lowbits(a * (2 - a * n), t)
  return a


def InverseSqrt2exp(n: int, k: int) -> Optional[int]:
  """Returns a, such that 1 == a * a * n % 2**k or None if no solution exists.

  Args:
    n: the value for which the inverse square root is computed
    k: the bit-size of the result.
  """
  # Special case for k < 3, since the code below only works for k >= 3.
  if k < 3:
    for a in range(2**k):
      if a * a * n % 2**k == 1:
        return a
    return None
  if n % 8 != 1:
    return None
  a = 1
  t = 3
  while t < k:
    # The loop invariant is a**2 * n % 2**t == 1.
    #
    # Assuming that the loop invariant holds at the beginning of the loop, it
    # can be shown that the loop invariant holds again at the end of the loop.
    # Let m = (3 - a**2 * n) / 2 = 1 + (1 - a**2 * n) / 2.
    # Then the claim that the loop invariant holds at the end of the loop is the
    # equivalent to claiming that 2**(2 * t - 2) divides a**2 * m**2 * n - 1.
    #
    # m**2 = (1 + (1 - a**2 * n) / 2)
    #      = 1 + (1 - a**2 * n) + ((1 - a**2 * n) / 2)**2.
    # By assumption (1 - a * a * n) is divisible by 2**t.
    # Hence, (1 - a**2 * n)**2 / 4 is divisible by 2**(2 * t - 2).
    # Thus, m**2 is congruent to 2 - a**2 * n modulo 2**(2 * t - 2).
    # From the loop invariant follows 2**t divides a**2 * n - 1 and thus
    # 2**(2 * t - 2) divides (a**2 * n - 1)**2 = a**2 * n * (a**2 * n - 2) + 1.
    # Since m**2 is congruent to 2 - a**2 * n modulo 2**(2 * t-2), it follows
    # that 2**(2*t-2) divides a**2 * m**2 * n - 1.
    # This is equivalant to the claim that the loop invariant holds after the
    # loop.
    t = min(k, 2 * t - 2)
    a = gmpy.lowbits(a * (3 - a * a * n) // 2, t)
  return a


def Sqrt2exp(n: int, k: int) -> list[int]:
  """Returns all square roots of n modulo 2**k, where n is odd.

  This function is restricted to odd inputs n, since only this case
  is needed and since otherwise the number of solutions can be large.
  E.g. the equation x**2 = 0 (mod 2**256) has 2**128 solutions, since
  any multiple of 2**128 is a solution.

  Args:
    n: an odd integer
    k: exponent of the modulus

  Returns:
    all x mod 2**k with x * x % 2**k == n % 2**k
  """
  if n % 2 == 0 or k < 0:
    raise ValueError("Not implemented for even inputs or negative k")
  # Speical case for k < 3, since the code below assumes k >= 3.
  if k < 3:
    return [x for x in range(2**k) if (x * x - n) % 2**k == 0]
  s = InverseSqrt2exp(n, k)
  if s is None:
    return []
  r = Inverse2exp(s, k)
  # Besides r there are three other roots modulo 2**k.
  roots = [
      r,
      int(2**k - r),
      gmpy.lowbits((2**(k - 1) - r), k),
      gmpy.lowbits((2**(k - 1) + r), k)
  ]
  return roots


def ContinuedFraction(a: int, b: int) -> list[tuple[int, int, int]]:
  """Computes a continued fraction expansion and partial convergents.

  Args:
      a: the numerator
      b: the denominator

  Returns:
      A list of triples (q, r, t), where q is the coefficient of the
      continued fraction expansion and r/t is the corresponding
      partial convergent.
  """
  res = []
  r, s, t, u = 1, 0, 0, 1
  # loop invariant: fraction = r*x + s / t*x + u
  # where x is the remainder of the continued fraction
  while b:
    q, rem = divmod(a, b)
    a, b = b, rem
    r, s = r * q + s, r
    t, u = t * q + u, t
    res.append((q, r, t))
  return res


def DivmodRounded(a: int, b: int) -> tuple[int, int]:
  """Performs a rounded division.

  Args:
      a: dividend
      b: divisor

  Returns:
      A tuple q, r, where q = round(a/b) and r = a - q*b
  """
  d = (b + 1) // 2
  x, y = divmod(a + d, b)
  return x, y - d


def Sieve(n: int) -> list[int]:
  """Using Sieve of Eratosthenes, returns all primes lower than n."""
  table = [True] * n
  for i in range(2, gmpy.sqrt(n) + 1):
    if table[i]:
      for j in range(i * i, n, i):
        table[j] = False
  return [i for i, v in enumerate(table) if v][2:]
