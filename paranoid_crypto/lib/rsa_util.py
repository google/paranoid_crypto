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
"""Set of math functions that are useful when checking RSA."""

from typing import Optional
import gmpy2 as gmpy
from paranoid_crypto.lib import lll
from paranoid_crypto.lib import ntheory_util
from paranoid_crypto.lib import special_case_factoring


def BatchGCD(
    values: list[int], other_values_prod: Optional[int] = None
) -> list[int]:
  """Returns a list with the GCD for each number with all the other values.

  Args:
    values: List of mpz numbers to calculate the pairwise GCDs.
    other_values_prod: Product of additional integers, used in the GCD
      computation. This can be a product of prime factors or keys that have
      already been tested.

  Returns:
    a list of GCDs. The i-th element of the result is the GCD of values[i]
    with the product of all values[j] with i!=j and other_values_prod.
  """
  unique_values = list(set(values))
  prod_tree, t = ntheory_util.ExtendedProductTree(unique_values)
  if other_values_prod:
    t *= other_values_prod

  # For efficiency, we want to create a remainder tree to explore the property
  # GCD(a, foo % a) = GCD(a, foo).
  # https://proofwiki.org/wiki/GCD_from_Congruence_Modulo_m

  remainders = [t]
  while prod_tree:
    unique_values = prod_tree.pop()
    prev = remainders
    remainders = [None] * len(unique_values)
    for i in range(len(unique_values)):
      if i + 1 == len(unique_values) and i % 2 == 0:
        remainders[i] = prev[i // 2]  # pyrefly: ignore[unsupported-operation]
      else:
        remainders[i] = prev[i // 2] % unique_values[i]  # pyrefly: ignore[unsupported-operation]
  gcds_dict = {v: gmpy.gcd(v, r) for v, r in zip(unique_values, remainders)}
  return [gcds_dict[v] for v in values]


def FermatFactor(n: int, max_steps: int) -> Optional[tuple[int, int]]:
  """Returns p and q such as n = p*q.

  Fermat's factorization method is based on the representation of an odd
  integer as the difference of two squares:
    n = a**2 - b**2.
  That difference is algebraically factorable as n = pq = (a + b)(a - b).
  See https://en.wikipedia.org/wiki/Fermat%27s_factorization_method.

  Args:
    n: Value to factorize;
    max_steps: Max of steps to try to find the square number.
  """
  if n % 2 == 0:
    return 2, n // 2

  n = gmpy.mpz(n)
  a = gmpy.isqrt(n)
  if a * a == n:
    return a, a

  a += 1  # ceil(sqrt(n))
  if max_steps <= 0:
    return None
  a_end = a + max_steps

  # Modulo 16 / modulo 8 analysis of a^2 - n = b^2:
  # - If n % 16 in (1, 13): b is even (b^2 % 16 in (0, 4)), so a^2 % 16 == 1
  #   -> a % 8 in (1, 7).
  # - If n % 16 in (5, 9): b is even (b^2 % 16 in (0, 4)), so a^2 % 16 == 9
  #   -> a % 8 in (3, 5).
  # - If n % 8 == 3: b is odd (b^2 % 8 == 1), so a^2 % 8 == 4
  #   -> a % 8 in (2, 6).
  # - If n % 8 == 7: b is odd (b^2 % 8 == 1), so a^2 % 8 == 0
  #   -> a % 8 in (0, 4).
  n_mod16 = int(n & 15)
  if n_mod16 in (1, 13):
    r1, r2 = 1, 7
  elif n_mod16 in (5, 9):
    r1, r2 = 3, 5
  elif (n_mod16 & 7) == 3:
    r1, r2 = 2, 6
  else:
    r1, r2 = 0, 4

  a_mod8 = int(a & 7)
  dist1 = (r1 - a_mod8) & 7
  dist2 = (r2 - a_mod8) & 7
  if dist1 < dist2:
    a += dist1
    d1 = (r2 - r1) & 7
  else:
    a += dist2
    d1 = (r1 - r2) & 7
  d2 = 8 - d1

  b2 = a * a - n
  two_a = 2 * a
  two_a_end = 2 * a_end
  d1_sq = d1 * d1
  d2_sq = d2 * d2
  two_d1 = 2 * d1
  two_d2 = 2 * d2
  is_square = gmpy.is_square

  while two_a < two_a_end:
    if is_square(b2):
      cur_a = two_a >> 1
      b = gmpy.isqrt(b2)
      return cur_a + b, cur_a - b
    b2 += d1 * two_a + d1_sq
    two_a += two_d1
    if two_a >= two_a_end:
      break
    if is_square(b2):
      cur_a = two_a >> 1
      b = gmpy.isqrt(b2)
      return cur_a + b, cur_a - b
    b2 += d2 * two_a + d2_sq
    two_a += two_d2

  return None


def FactorHighAndLowBitsEqual(
    n: int, middle_bits: int = 3
) -> Optional[list[int]]:
  """Factors n = p*q if p and q share sufficiently many high and low bits.

  This function factors n if about n.bit_length() / 4 of the high bits and
  low bits of p and q are equal.

  The function uses a variant of Fermats factorization. The method here uses
  that some of the bits of (p+q)/2 can be computed if p and q are partially
  equal. If r of the most significant bits of p and q are equal then
  approximately 2r of the most significant bits of n^(1/2) and (p+q)/2 are
  equal. E.g. Fermat's factorization uses this property.

  On the other hand, assuming
     p == q (mod 2^m)
  implies
     0 == ((p - q) / 2)^2 (mod 2^(2m-2))
  And hence because of
     n + ((p - q) / 2)^2 == ((p + q) / 2)^2
  it follows that
     n == ((p + q) / 2)^2 (mod 2^(2m - 2))

  If some of the most significant and some of the least significant bits of p
  and q are the same then the two methods can be combined: the integer square
  root is used to compute the most significant bits of (p+q)/2 and the moduluar
  square root is used to find the least significant bits of (p+q)/2.

  Example:
    p = 0xcb557401230321b723a2342377a28249
    q = 0xcb557401a315c42e24cc6aaa77a28249
    n = 0xa180a2807092c6564a2387ed849efb482e5117417ccc5c39d4d1debe04b238d1

    (p+q)/2         = 0xcb557401630c72f2a4374f66f7a28249
    floor(n^0.5)    = 0xcb557401630c72f29a21eac2e0ddad4b
    n^(1/2) % 2^128 = 0xdd2c6b82f42784bd84374f66f7a28249 or
                      0x22d3947d0bd87b427bc8b099085d7db7

    Here, p and q have the property that the 32 most significant bits and
    the 32 least significant bits are the same. The example shows that
    (p + q) / 2 can be found by taking the 64 most significant bits from
    floor(n^(1/2)) and 61 of the least significant bits of one of the modular
    square roots of n^(1/2) modulo 2^128.

  Args:
    n: the integer to factor
    middle_bits: determines the number of bits in the middle that neither come
      from floor(n^0.5) nor from (p + q) / 2. The default has been chosen so
      that the factorization succeeds if exactly n.bit_length() // 4 of the most
      and least significant bits of p and q are the same.

  Returns:
    a list of factors of n if factorization was successful or None if no
    factor was found.

  Raises:
    ArithmeticError:
      to indicate a programming error
  """

  # Not implemented for small integers.
  if n.bit_length() < 6:
    return None
  # If n % 8 is not 1 then the least significant 3 bits of p and
  # q are different. Hence, this function cannot find factorizations that
  # Fermat would not find. Skipping these cases assures that the modular
  # square root below can be computed.
  if n % 8 != 1:
    return None
  # Computes a square root r0 modulo 2**k
  k = (n.bit_length() + 1) // 2
  r0 = ntheory_util.Inverse2exp(ntheory_util.InverseSqrt2exp(n, k + 1), k + 1)  # pyrefly: ignore[bad-argument-type]
  # Fighting with broken lint rules here and below.
  if r0 is None:
    raise ArithmeticError("expecting that square root exists")

  # approximation of (p+q)/2 if p is close to q.
  a = gmpy.isqrt(n - 1) + 1
  for r in [r0, 2**k - r0]:
    s = a
    for i in range(k):
      if ((s ^ r) >> i) & 1:
        # At this point s is the smallest integer >= a such that the
        # i-1 least significant bits of s and r are the same, but the
        # i-th least significant bit of s and r is different.
        # To find the smallest integer s >= a where the i lsbs are the same
        # one could simply add 2**i to s. However, the loop below increments
        # s in 2**m steps of 2**(i-m). This finds factorizations where all
        # but a few (middle_bits) bits of (p+q)/2 are either determined by
        # a or r respectively.
        m = min(middle_bits, i)
        for _ in range(2**m):
          s += 2 ** (i - m)
          d = s**2 - n
          if gmpy.is_square(d):
            d_sqrt = gmpy.isqrt(d)
            return [s - d_sqrt, s + d_sqrt]
      # Loop invariants:
      # assert (s - r) % 2**i == 0
      # assert a <= s < a + 2**i
  return None


def CheckContinuedFraction(n: int, bound: int) -> tuple[bool, list[int]]:
  """Checks an RSA modulus for large coefficients in a continued fraction.

  Motivation:
  This test computes the continued fraction of each RSA modulus with a
  power of two. The test fails if an unusually large coefficient is found.
  "Factoring RSA keys from certified smart cards: Coppersmith in the wild"
  https://smartfacts.cr.yp.to/smartfacts-20130916.pdf
  Many of the weak primes in Appendix A have a repetitive pattern.
  Such primes have the property that they are close to a/b * 2^m,
  where a/b is a small fraction and m is the size of the prime.
  If the both prime factors have this form then their product n
  also has this form if the fractions are small enough.
  Computing a continued fraction can detect such forms: a modulus n
  is close to some a/b * 2^m if one of the coefficients of the continued
  fraction is unusually large.

  Factorization:
  The implementation here tries to factor n, based on the assumption
  that both factors contain a repeated bit pattern. For example, let:

  p = 0xfa157ca157ca157ca157ca157ca1647
  q = 0xc1acb1acb1acb1acb1acb1acb1342bb

  The continued fraction determines that a close approximation of n=p*q is
  u/v * 2^248 for u = 0x25d6d2c9c77 and v = 0x3332fcccd00.
  The value for n*v is
  0x25d6d2c9c76fffffffffffffffe875d1a5b4e1547ffffffffffffffecf2057d45ca83f900,
  which can be represented as
  a * z^2 + b * z + c
  for a = 0x25d6d2c9c77, b = -0x178a2e5a4b1eab80, c = -0x130dfa82ba357c0700
  and z = 2^124.
  If the roots x_1, x_2 of the polynomial a * x^2 + b * x + c are rational
  then one has a factorization n*v = a * (z - x1) * (z - x2). While this
  factorization could be trivial, typically one finds that the numerator
  of z - x1 or z - x2 have a non-trivial gcd with n.

  When factorization fails:
  The method used for factoring the modulus above is rather primitive and
  hence can fail. If the continued fraction contains a large coefficient,
  but the factorization attempt above fails then this may still imply that
  the modulus is weak and that the attempt above just didn't try hard enough
  to factor the modulus.

  The minimum bound for the coefficient for which this test fails must be
  chosen large enough, so that correctly generated RSA moduli fail with
  a negligible probability.
  The asymptotic distribution of the coefficients of a continued fraction
  expansion is given by the Gauss-Kyzmin theorem:
  https://en.wikipedia.org/wiki/Gauss%E2%80%93Kuzmin_distribution
  This theorem claims that the probability of a coefficient <= k is
  asymptotically $1 - log_2((k+2) / (k+1))$, hence the probility to
  get a coefficient >= k is asymptotically $log_2((k+1) / k)$. For a
  large k this is about $1/ln(2)k$.
  To get a negligible number of false positives, the value of bound
  should be chosen significantly larger than number of tested keys
  times the average length of the continued fraction expansion.
  The average length of the continued fraction expansion is the
  bit-size of the modulus times some small constant. (Not sure what
  that constant is).

  Comparison with other methods:
  The author of the paper above give an overview of the methods used
  in Section 1 of their paper: they used a batch gcd to find a number of
  common primes, analyzed these primes, generalized the patterns found and
  then tried to find more factorizations with these generalized patterns.
  This method works when sufficiently many bits of the prime factors can be
  guessed. Hence one weak prime factor is enough.
  The method here requires that both prime factors are weak. However, the
  test is fast and does not require to guess a pattern first.

  Args:
      n: An RSA modulus to check.
      bound: A bound, such that the test fails if a coefficent equal or larger
        than this bound is found in the continued fraction.

  Returns:
      A tuple (ok, factors), where the value ok is False if the modulus
      is (probably) weak, and a list of factors that were found.
      The test can fail even if no factors were found, but the continued
      fraction has a large coefficient.
  """
  n = gmpy.mpz(n)
  bits = n.bit_length()
  m = gmpy.mpz(1) << bits
  half_bits = bits // 2
  x = gmpy.mpz(1) << half_bits
  d = (x + 1) >> 1
  mask = x - 1
  is_square = gmpy.is_square

  a_cf, b_cf = n, m
  u0, u1 = gmpy.mpz(0), gmpy.mpz(1)
  neg_rem = True
  while b_cf:
    quot, rem = divmod(a_cf, b_cf)
    a_cf, b_cf = b_cf, rem
    u0, u1 = u1, quot * u1 + u0
    # By the continued fraction identity, u1 * m - v1 * n = (-1)^k * rem,
    # so n * v1 == (u1 << bits) + rem when k is odd (neg_rem=True), and
    # (u1 << bits) - rem when k is even (neg_rem=False).
    nv = (u1 << bits) + rem if neg_rem else (u1 << bits) - rem
    neg_rem = not neg_rem
    if half_bits:
      nv_d = nv + d
      r = nv_d >> half_bits
      c = (nv_d & mask) - d
      r_d = r + d
      a = r_d >> half_bits
      b = (r_d & mask) - d
    else:
      r, c = ntheory_util.DivmodRounded(nv, x)
      a, b = ntheory_util.DivmodRounded(r, x)
    if a and c:
      disc = b * b - 4 * a * c
      if is_square(disc):
        t = gmpy.isqrt(disc)
        two_a_x_b = (a << (half_bits + 1)) + b
        for rt in (t, -t):
          p = gmpy.gcd(n, two_a_x_b + rt)
          if 1 < p < n:
            return False, [p, n // p]
    if quot >= bound:
      # There is a large coefficient in the continued fraction of n and m,
      # but no factorization was found.
      return False, []
  return True, []


def CheckFraction(n: int, d0: int = 1) -> list[int]:
  """Attempts to factor an RSA moduli where one factor is close to a fraction.

  The method here attempts to find a factorization of n assuming that the
  factors p and q of n are of the same size and that one of the factors can
  be represented as p = (a*B + c) / d, where a, c are small.

  Let w be 2**(n.bit_length() // 2), and assume that p < B and q < B.
  If n = p*q = u*B + v, then d*n = d*p*q, thus
  d*u*w + d*v = a*q*w + c*q.

  Hence, d*v == c*q (mod w), and abs(d*u - a*q) < h,
  where h = max(abs(c) + abs(d)).

  Hence a*d*v == a*c*q (mod w) and abs(c*d*u - a*c*q) < c*h.
  Therefore abs((c*d*u - a*d*v) % w) < c*h.

  Assume that d is known and define a lattice as follows:
     L = ((x, 0, d*u),
          (0, x, d*v),
          (0, 0, w))
  Here w is an arbitrary integer of about the same size as d to balance
  the lattice.

  Then this lattice contains the vector (c*x, -a*x, (c*d*u - a*d*v) % w).

  The volume of the lattice is x**2*w. Hence a vector with norm smaller than
  (x**2*w) ^ (1/3) is likely in the reduced basis.

  If this vector can be found with a lattice basis reduction,
  then gcd(n, a*x*w + c*x) should return p, since
  a*x*w + c*x is a multiple of p.

  Remark: Simple prime factors of n (i.e. a,c and d small) can also be
  found just by setting d0 = 1. In this case the lattice L defined above is
       L = ((1, 0, u),
            (0, 1, v),
            (0, 0, w))
  and thus contains the vector (c*d, -a*d, (c*d*u - a*d*v) % w).
  Hence if a, c and d are small then this vector can be found. The drawback
  is that only small values can be found. E.g. by setting d0 it is possible
  to find prime factors p of a 2048-bit modulus if p has a 240-bit pattern.
  Without setting d only patterns of lengths up to about 104-bits can be
  discovered.

  Example: let
    p = 0xeab851eab851eab851eab851eab851eab851ead1
    q = 0xf1e8e75e0a2f461b934d190d4a6ee2f53f2b0c39
  Thus n = p*q =
  0xddcd104abf2b9407b93919a4c59db479ff86d3305aff3bf29bc7c097c33b7d67742a9877c15a1489

  Here p has a 24 bit pattern "eab851" and q is random.
  Because of the 24-bit pattern, we get
  (2**24-1) * p = 0xeab8510000000000000000000000000000000018ae152f

  The lattice contains the vector
  v = [0x18ae152f * x, -0xeab851 * x, 0x236ce2624c94189]
  Hence -v[1] * 2**160 + v[0] =
  0xeab8510000000000000000000000000000000018ae152f000000,
  which is a multiple of p

  Args:
    n: the RSA modulus to check
    d0: a guess for the denominator d

  Returns:
    non-trivial factors of n if this method was able to factor n or
    an empty list if the attempt was unsuccessful.
  """
  w = 2 ** (n.bit_length() // 2)
  u, v = divmod(n, w)
  x = 2 ** d0.bit_length()
  lat = [[x, 0, u * d0 % w], [0, x, v * d0 % w], [0, 0, w]]
  for v in lll.reduce(lat):
    cx, ax = v[0], -v[1]
    p = gmpy.gcd(ax * w + cx, n)
    if 1 < p < n:
      return [p, n // p]
  return []


def CheckSmallUpperDifferences(n: int) -> Optional[list[int]]:
  """Checks if abs(p - q) has some special form.

  FIPS 186-4 requires that p and q are chosen such that
  abs(p - q) > 2 ** (n.bit_length() // 2 - 100). Some implementors might
  misunderstand this recommendation and choose e.g.
    q = next_prime(p + 2 ** (n.bit_length() // 2 - 100)).
  Hence this is one of the differences tested.

  Args:
    n: the modulus to factor

  Returns:
    A list of factors of n, if the factorization was successful or
    None otherwise.
  """
  prime_size = n.bit_length() // 2
  # This implementation assumes that primes are at least 384-bit integers.
  # Smaller values are already rejected by other tests.
  if prime_size < 384:
    return None

  # Approximation of the differences that are tested. The value
  # 2 ** (prime_size - 100) checks for misunderstanding the bound required
  # by NIST. The other values check for similar bugs.
  differences = [
      2 ** (prime_size - 100),
      2 ** (prime_size - 128),
      2 ** (prime_size - 160),
      2 ** (prime_size - 256),
      2 ** (prime_size - 2),
      2 ** (prime_size - 3),
  ]
  for diff in differences:
    # find an approximation p0 for p such that p - n // q is approx. diff.
    p0 = gmpy.isqrt(n + (diff // 2) ** 2) + diff // 2
    factors = special_case_factoring.FactorWithGuess(n, p0)
    if factors:
      return factors
  return None


def Pollardpm1(
    n: int, m: Optional[int] = None, gcd_bound: int = 2**60
) -> tuple[bool, list[int]]:
  """Checks if an RSA modulus is factorable by pollard p-1 method.

  Pollard's p-1 algorithm finds factors when the number preceding the factor,
  p - 1, is powersmooth. A number X is called B-powersmooth if all prime powers
  r^v dividing X satisfy: r ^ v <= B. For example, 720 (2^4 * 3^2 *5) is
  5-smooth (largest prime is 5) and 16-powersmooth (greatest prime factor power
  is 2^4 = 16).

  The algorithm works due Fermat's little theorem. Let N = p*q. For all
  integers a, coprime to p and for all positive integers K, if b = a ^ (K*(p-1))
  is congruent to 1 mod p, then the factor p is gcd(b - 1, N).

  Motivation:
  For high speed, some key generators may use much smaller numbers to compose
  the key. For example, https://www.umopit.ru/CompLab/primes32eng.htm contains
  a list of all 32-bit prime numbers and it states that this list "can be used
  for manual picking of a prime number (e.g. as a base for effective
  cryptography)".

  When factorization fails:
  The factorization fails when p-1 is not enough powersmooth (for the given m
  value). m with more and larger factors can be chosen, but this function takes
  much longer to return.
  Args:
      n: An RSA modulus to check.
      m: A pre-calculated guess for K*(p-1).
      gcd_bound: For efficiency, the test runs only when gcd(n-1, m) >
        gcd_bound. This is based on the assumption that when both p-1 and q-1
        are smooth, so is their gcd. Rough experiments suggest that gcd_bound =
        2**60 is a reasonable value to skip possible true random keys. A
        drawback is that it can also skip the test when only p-1 (but not q-1)
        is smooth enough.

  Returns:
      A tuple (weak, factors), where the value weak is True if the modulus
      is weak, and a list of factors that were found. When both p-1 and q-1 are
      smooth enough, the function returns True but an empty list of factors.
      In that case, divisors of m can be tried instead.
  """
  # Using a = 2^(n-1) instead of a = 2 extends the test to cases where
  # p = b*m + 1 and q = c*m + 1, and where either b or c is smooth.
  if gmpy.gcd(n - 1, m) >= gcd_bound:
    a = pow(2, n - 1, n)
    p = gmpy.gcd(pow(a, m, n) - 1, n)  # pyrefly: ignore[no-matching-overload]
    if 1 < p < n:
      return True, [p, n // p]
    if p == n:
      return True, []
  return False, []


def CheckLowHammingWeight(
    n: int, cutoff: int = 2500, maxsteps: int = 10**6
) -> tuple[bool, list[int]]:
  """Tries to factor n assuming that the factors have a low Hamming weight.

  This algorithm is loosly based on crackpot claims that the bit
  patterns for the prime factors can be derived from the bit pattern
  of the product. This doesn't work for general integers, but may
  work if n is the product of two factors with a small Hamming weight.

  Args:
      n: the modulus to test
      cutoff: the number or steps after which the search is abandoned if no
        promissing branch has been found. The default of 2500 means that the
        function takes about 100 ms when n is not a product of factors with a
        low Hamming weight.
      maxsteps: an upper bound on the maximal number of steps. The default value
        10**6 means that the search spends about 20 seconds before giving up. A
        value of 10**7 is the largest value tested with 64 GB of memory.

  Returns:
      A tuple (weak, factors), where the value weak is True if the modulus
      is (probably) weak, and a list of factors that were found.
      The test can fail even if no factors were found. This happens when
      the search finds a partial factorization with unusually low
      Hamming weight. E.g., the following cases can be detected without
      finding a factorization:
         * the Hamming weight of the factors is close to the bound that
           can be factored. E.g. products of two 1024-bit primes with
           Hamming weight 96 often require 10**7 or more steps to factor.
         * only the most significant bits of the factors have a small
           Hamming weight. The key may still be weak because other methods
           such as Coppersmith may be used to find the least significant bits.
         * the primes are not of equal size. The search will still find
           partial factorizations with low Hamming weight, but fail to factor n.
         * the search spends a lot of time with false positives. The product
           of two factors of very low Hamming weight often has other partial
           factorizations with low Hamming weight.
  """

  def Heuristic(hamming_weight: int, rem_size: int) -> int:
    """The heuristic used for the search.

    The heuristc (in particular the factor 5) has been determined
    experimentally. Using a factor 5 in this heuristic allows to factor
    some 2048 bit products where each of the 1024-bit factors has a Hamming
    weight 96. The factor 5 has the property that the heuristic of correct
    guesses are expected to slowly decrease with more bits of the factors
    guessed, while the heuristic of incorrect guesses are slowly increasing.

    Args:
      hamming_weight: the Hamming weight of the partial factors p0 and q0
      rem_size: (n - (p0 << bit) * (q0 << bit)).bit_length()

    Returns:
      the heuristic. Smaller is better.
    """
    return rem_size + 5 * hamming_weight

  # Bucket priority queue (Dial's algorithm) indexed by heuristic value v.
  # Elements in buckets[v] are 5-tuples (hw, bit, p0, q0, rem0) where:
  #   hw: is the sum of the Hamming weights of p0 and q0.
  #   bit: is the number of missing bits in p0 and q0.
  #   p0: a guess for the msbs of p, i.e., the value p >> bit.
  #   q0: a guess for the msbs of q, i.e., the value q >> bit.
  #   rem0: the remainder (n >> (2 * bit)) - p0 * q0.
  n = int(n)

  # There are two thresholds for the heurisitic.
  # If no value of the heuristic smaller than threshold_cutoff is found then
  # the search is stopped after cutoff steps. This value has been selected
  # experimentally. A collection of about 28'000 real RSA keys has no value for
  # minv that is smaller than n.bit_length(). Hence checking a correctly
  # generated RSA key will very likely stop after cutoff steps.
  # If a small value or the heuristic is found then search will continue until
  # a factorization is found or maxsteps steps were made. If at this point
  # the minimal value for the heuristic is smaller or equal to threshold_weak
  # (and no factorzation was found) then the RSA key is considered to be
  # potentially weak. Such keys may need to be analyzed further.
  threshold_cutoff = n.bit_length()
  threshold_weak = n.bit_length() - 12

  psize = (n.bit_length() + 1) // 2
  n_limbs = [(n >> (2 * b)) & 3 for b in range(psize)]
  steps = 0
  remainder = n - (1 << (2 * (psize - 1)))
  minv = Heuristic(2, remainder.bit_length())
  cur_v = minv
  buckets: list[Optional[list[tuple[int, int, int, int, int]]]] = [None] * (
      12 * psize + 25
  )
  buckets[cur_v] = [(2, psize - 1, 1, 1, remainder >> (2 * (psize - 1)))]
  queued = 1

  while steps < maxsteps and queued:
    steps += 1
    if steps == cutoff:
      if minv >= threshold_cutoff:
        break

    bucket = buckets[cur_v]
    while not bucket:
      cur_v += 1
      bucket = buckets[cur_v]
    hw, bit, p, q, rem = bucket.pop()
    queued -= 1

    # Doing computations on the msbs only saves 40% CPU time.
    while bit >= 1:
      p <<= 1
      q <<= 1
      bit -= 1
      rem = (rem << 2) | n_limbs[bit]
      if rem < p:
        continue
      bound = p + q + 1
      base_v = 2 * bit + 5 * hw + 5
      # dp=0, dq=1: p0 = p, q0 = q + 1, p0 * q0 = p * q + p (always p <= q + 1)
      rem0 = rem - p
      if bit:
        if rem0 <= bound:
          v_new = rem0.bit_length() + base_v
          target = buckets[v_new]
          if target is None:
            buckets[v_new] = [(hw + 1, bit, p, q + 1, rem0)]
          else:
            target.append((hw + 1, bit, p, q + 1, rem0))
          queued += 1
          if v_new < cur_v:
            cur_v = v_new
            if v_new < minv:
              minv = v_new
      elif rem0 == 0:
        return True, [p, q + 1]

      # dp=1, dq=0: p0 = p + 1, q0 = q, p0 * q0 = p * q + q (p0 <= q0 iff p < q)
      rem0 = rem - q
      if rem0 < 0:
        continue
      if bit:
        if rem0 <= bound and p < q:
          v_new = rem0.bit_length() + base_v
          target = buckets[v_new]
          if target is None:
            buckets[v_new] = [(hw + 1, bit, p + 1, q, rem0)]
          else:
            target.append((hw + 1, bit, p + 1, q, rem0))
          queued += 1
          if v_new < cur_v:
            cur_v = v_new
            if v_new < minv:
              minv = v_new
      elif rem0 == 0 and p < q:
        return True, [p + 1, q]

      # dp=1, dq=1: p0 = p + 1, q0 = q + 1, p0 * q0 = p * q + p + q + 1
      rem0 = rem0 - p - 1
      if rem0 < 0:
        continue
      if bit:
        if rem0 <= bound + 1:
          v_new = rem0.bit_length() + base_v + 5
          target = buckets[v_new]
          if target is None:
            buckets[v_new] = [(hw + 2, bit, p + 1, q + 1, rem0)]
          else:
            target.append((hw + 2, bit, p + 1, q + 1, rem0))
          queued += 1
          if v_new < cur_v:
            cur_v = v_new
            if v_new < minv:
              minv = v_new
      elif rem0 == 0:
        return True, [p + 1, q + 1]
      if rem0 > 0:
        break
  potentially_weak = minv <= threshold_weak
  return potentially_weak, []
