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
"""Module containing Paranoid single checks for RSA keys."""

import hashlib
import math
from typing import Optional
from absl import logging
import gmpy
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import base_check
from paranoid_crypto.lib import consts
from paranoid_crypto.lib import keypair_generator
from paranoid_crypto.lib import ntheory_util
from paranoid_crypto.lib import roca
from paranoid_crypto.lib import rsa_util
from paranoid_crypto.lib import special_case_factoring
from paranoid_crypto.lib import util
from paranoid_crypto.lib.data import default_storage
from paranoid_crypto.lib.data import storage


class CheckSizes(base_check.RSAKeyCheck):
  """Runs modulus size checks on the input RSA keys (artifacts)."""

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_MEDIUM)

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      weak = gmpy.bit_length(n) < 2048
      if weak:
        logging.warning("Key size check failed! Size: %d\n%s",
                        gmpy.bit_length(n), key.rsa_info)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckExponents(base_check.RSAKeyCheck):
  """Runs exponent checks on the input RSA keys (artifacts)."""

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_MEDIUM)

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      e = gmpy.mpz(util.Bytes2Int(key.rsa_info.e))
      if e != 65537:
        logging.warning("Exponent check failed! Exponent: %d\n%s", e,
                        key.rsa_info)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckROCA(base_check.RSAKeyCheck):
  """Runs ROCA check on the input RSA keys (artifacts).

  Attributes:
    _fc: Private attribute. ROCAKeyDetector instance to detect ROCA keys.
  """

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_HIGH)
    self._fc = roca.ROCAKeyDetector()

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      if self._fc.IsWeak(n):
        logging.warning("ROCA check failed!\n%s", key.rsa_info)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckROCAVariant(base_check.RSAKeyCheck):
  """Runs check for ROCA variants on the input RSA keys (artifacts).

  Attributes:
    _fcv: Private attribute. ROCAKeyVariantDetector instance to detect ROCA
      variant keys.
  """

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_MEDIUM)
    self._fcv = roca.ROCAKeyVariantDetector()

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      if self._fcv.IsWeak(n):
        logging.warning("Check for ROCA variant failed!\n%s", key.rsa_info)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckFermat(base_check.RSAKeyCheck):
  """Runs quick Fermat checks on the input RSA keys (artifacts)."""

  def __init__(self, max_steps: Optional[int] = 100000):
    """CheckFermat check constructor.

    Args:
      max_steps: Max steps to try to find the square number.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    self._max_steps = max_steps

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      factors = rsa_util.FermatFactor(n, self._max_steps)
      if factors:
        logging.warning("Key factored! Factors: %s\n%s", factors, key.rsa_info)
        util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, factors)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckHighAndLowBitsEqual(base_check.RSAKeyCheck):
  """Runs a check that factors key if enough bits of p and q are equal.

  This test is similar to Fermat, but with the difference that it tries
  to factor an RSA modulus under the assumption that the some of the high and
  some of the lower bits of p and q are equal. The check factors the keys
  when the r least significant bits of p and q are equal, the s most
  significant bits of p and q are equal and r + s is at least half of the
  bit length of n.
  """

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      factors = rsa_util.FactorHighAndLowBitsEqual(n)
      if factors:
        logging.warning("Key factored! Factors: %s\n%s", factors, key.rsa_info)
        util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, factors)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckOpensslDenylist(base_check.RSAKeyCheck):
  """Checks Debian OpenSSL Predictable Pseudo Random Number Generator."""

  def __init__(self, paranoid_storage: Optional[storage.Storage] = None):
    """CheckOpensslDenylist check constructor.

    Args:
      paranoid_storage: Instance of storage.Storage, containing
        GetOpensslDenylist method.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    self._storage = paranoid_storage or default_storage.DefaultStorage()
    self._weak_keylist = self._storage.GetOpensslDenylist()

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      keytype = "RSA-%d" % gmpy.bit_length(n)
      n_str = "Modulus=%X\n" % n
      n_hash = hashlib.sha1(n_str.encode("utf-8")).hexdigest()[20:]
      keystr = "%s:%s" % (keytype, n_hash)
      if keystr in self._weak_keylist:
        logging.warning("OpensslDenylist check failed!\n%s", key.rsa_info)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckContinuedFractions(base_check.RSAKeyCheck):
  """Runs continued fractions checks on the input RSA keys (artifacts)."""

  def __init__(self, bound: Optional[int] = 2**48):
    """CheckContinuedFractions check constructor.

    Args:
      bound: A lower bound for the coefficients in the continued fraction that
        are flagged as suspicious. Bound should be chosen larger than the number
        of test keys the bit size a key to avoid false positives. The default
        value 2**48 has been chosen so that testing 1 billion 2048-bit RSA keys
        has likely no false positive.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    self._bound = bound

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      ok, factors = rsa_util.CheckContinuedFraction(n, self._bound)
      if not ok:
        if factors:
          logging.warning("Key factored! Factors: %s\n%s", factors,
                          key.rsa_info)
          util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, factors)
        else:
          logging.warning(
              "Key with large coefficient in continued fraction:\n%s",
              key.rsa_info)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckBitPatterns(base_check.RSAKeyCheck):
  """Tries to find factors of RSA keys with a repeating bit pattern.

  The factoring algorithm tries to find repeating bit patterns for a list
  pattern sizes. The algorithm is successful even if some of the most
  significant bits and some of the least significant bits deviate
  from the pattern, though the size of the repeating bit pattern shrinks in
  this case. In the best case, when almost all bits of the prime have the
  repeating pattern, it is possible to find patterns of size close to
  n.bit_length() // 8, but not longer.
  """

  def __init__(self, pattern_sizes: Optional[list[int]] = None):
    """CheckBitPatterns check constructor.

    Args:
      pattern_sizes: An optional list of sizes for the bit patterns searched.
        Sizes above n.bit_length() // 8 will be skipped, since the algorithm
        used here can't find such patterns.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    self._pattern_sizes = pattern_sizes

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    pattern_sizes = self._pattern_sizes
    if pattern_sizes is None:
      # Selects a list of patterns to search. The default here is a
      # relatively short list of sizes that are likely to occur.

      # Short patterns: Such cases have been reported in the paper
      # "Factoring RSA keys from certified smart cards: Coppersmith in the
      # wild".
      pattern_sizes = list(range(1, 16, 2))
      # Patterns of size 2^n-1. Many simple LFSRs have periods of this size.
      pattern_sizes += [31, 63, 127, 255, 511]
      # Powers of 2. Copying memory blocks leads to such patterns.
      pattern_sizes += [8, 16, 32, 64, 128, 256]
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      # The maximal pattern size that will be tried. Attempting to find
      # factors with a larger patterns is pointless, since the algorithm is too
      # weak find such factorizations.
      max_pattern_size = n.bit_length() // 8
      for pattern_size in pattern_sizes:
        if pattern_size > max_pattern_size:
          continue
        d = 2**pattern_size - 1
        factors = rsa_util.CheckFraction(n, d)
        if factors:
          logging.warning("Key factored! Factors: %s\n%s", factors,
                          key.rsa_info)
          util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, factors)
          any_weak = True
          test_result.result = True
          break
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckPermutedBitPatterns(base_check.RSAKeyCheck):
  """Tries to find factors of RSA keys with a repeating permuted bit pattern.

  This method tries to find primes that have patterns similar to the ones
  found by the authors of the paper "Factoring RSA keys from certified smart
  cards: Coppersmith in the wild".
  (https://smartfacts.cr.yp.to/smartfacts-20130916.pdf)
  Many of the primes listed in this paper contain a small repeating pattern,
  but the words swapped.

  An example is the prime
  p = 0xc28550a128500a14850aa14250a114280a144285a14228501428850a428550a1
        28500a14850aa14250a114280a144285a14228501428850a428550a128500a6f.
  The prime p would contain the bit pattern '0010100' if adjacent 16-bit
  words were not swapped. Because of the swapping the size of the pattern
  is 7 * 32 = 224 bits long. This pattern size is too long for the method
  CheckBitPattern above, since p is only 512-bits long.

  A useful observation is that p can be represented as
  p = (a*2**511 + b) // d with
  a = 0xc0ff850060ff090152ff390093,
  b = 2ce2d2d72d42d2d42d4ed2a42d11 and
  d = (2**7 - 1) * (2**(7 * 16) + 1) // (2**16 + 1)
    = 0x7eff81007eff81007eff81007f.
  The denominator d as well as a and b are small enough so that
  rsa_util.CheckFraction(n, d) finds the factorization of n.

  The value for d is shared by all primes with a 7-bit pattern and 16-bit
  swaps. The value for d can be generalized to other "word" and pattern sizes.
  More generally for a pattern of size psize and a word size wsize it is
  possible to use the denominator
  d = (2**psize - 1) * (2**(psize * wsize) + 1) // (2**wsize + 1).
  This formula was derived partially by experimentation. That is by computing
  the continued fraction of actual primes and looking for denominators in
  good approximations.

  The following tries to explain what happens in the example above. To
  simplify the text integers are written with 16 bit limbs. E.g. the prime p
  above has the form p = XADCFEAGCBEDGFBADCFEAGCBEDFGBADY with limbs
  A = 0x50a1, B = 0x4285, C = 0x0a14, D = 0x02850  E = 0xa142, F = 0x0850a and
  G = 0x1428.
  The claim is that multiplying a prime p with the format above by
  m = (2**(7 * 16) + 1) // (2**16 + 1) gives a result with a repeating pattern
  in the middle. In particular it is the same pattern as m0*p0, where
  m0 = (2**(5 * 16) + 1) // (2**16 + 1)
     = W**4 - W**3 + W**2 - W + 1, and
  p0 = ABCDEFGABCDEFGABCDEFGABCDEFGABC
     = 0x50a142850a142850a142850a142850a142850a142850a142850a142850a1
       42850a142850a142850a142850a142850a142850a142850a142850a142850a14
  A reason why this happens is that equal limbs in p either have a distance
  5 or 9. If the distance is 5 then some terms cancel, because
  A*(W**5 + 1)*m = A*(W**5 + 1)*(W**6 - W**5 + W**4 - W**3 + W**2 - W + 1) =
  A*(W**11 - W**10 + W**9 - W**8 + W**7 + W**4 - W**3 + W**2 - W + 1) =
  A*(W**7 + 1) * m0.
  """

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      max_dsize = n.bit_length() // 8
      # bit size of the words that are swapped
      for wsize in 8, 16, 32, 64:
        # bit size of the pattern without swapping
        for psize in range(3, wsize, 2):
          d = int((2**psize - 1) * (2**(psize * wsize) + 1) // (2**wsize + 1))
          if d.bit_length() > max_dsize:
            break
          factors = rsa_util.CheckFraction(n, d)
          if factors:
            logging.warning("Key factored! Factors: %s\n%s", factors,
                            key.rsa_info)
            util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS,
                               factors)
            any_weak = True
            test_result.result = True
            break
        if test_result.result:
          break
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckPollardpm1(base_check.RSAKeyCheck):
  """Runs checks using Pollard's p-1 factorization algorithm."""

  def __init__(self, bound: Optional[int] = None):
    """CheckPollardpm1 check constructor.

    Args:
      bound: A bound B, such that the test fails if for one of the factors p, p
        - 1 is B-powersmooth. If bound is not specified, this function computes
        a value estimated to be able to find factors when p-1 is up to 20 bits.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    if bound:
      # bound-powersmooth
      powers = list(map(gmpy.mpz, ntheory_util.Sieve(bound)))
      for i in range(len(powers)):
        powers[i] = powers[i]**int(math.log(bound, powers[i]))
      self._m = ntheory_util.FastProduct(powers)
    else:
      # Rough estimated values for finding factors of p - 1 up to 20 bits.
      smooth = 2**20  # max prime factor from p - 1
      powersmooth = 2**64  # max power of a prime factor from p - 1
      powers = list(map(gmpy.mpz, ntheory_util.Sieve(smooth)))
      # When considering powersmooth numbers, usually first primes have higher
      # probability of appearing. Here we consider the first 150 prime numbers.
      # Larger primes have less probability of appearing, so we count just once.
      for i in range(150):
        powers[i] = powers[i]**int(math.log(powersmooth, powers[i]))
      self._m = ntheory_util.FastProduct(powers)

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      weak, factors = rsa_util.Pollardpm1(n, self._m)
      if weak:
        if factors:
          logging.warning("Key factored! Factors: %s\n%s", factors,
                          key.rsa_info)
          util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, factors)
        else:
          logging.warning("Key may be vulnerable to Pollard p-1:\n%s",
                          key.rsa_info)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckLowHammingWeight(base_check.RSAKeyCheck):
  """Runs checks for keys that are products of low Hamming weight primes."""

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      weak, factors = rsa_util.CheckLowHammingWeight(n)
      if weak:
        if factors:
          logging.warning("Key factored! Factors: %s\n%s", factors,
                          key.rsa_info)
          util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, factors)
        else:
          logging.warning(
              "Key may be product of low Hamming weight primes:\n%s",
              key.rsa_info)
          # To distinguish between keys where the factorization was found and
          # keys where a product of low Hamming weight primes is only suspected
          # we use SEVERITY_UNKNOWN for the latter.
          test_result.severity = paranoid_pb2.SeverityType.SEVERITY_UNKNOWN
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckUnseededRand(base_check.RSAKeyCheck):
  """Checks if the RSA keys were generated with unseeded PRNGs."""

  def __init__(self, paranoid_storage: Optional[storage.Storage] = None):
    """CheckUnseededRand check constructor.

    Args:
      paranoid_storage: Instance of storage.Storage, containing GetUnseededRands
        method to obtain possible RSA keys generated from unseeded PRNGs.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    self._storage = paranoid_storage or default_storage.DefaultStorage()

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      psize = (n.bit_length() + 1) // 2
      list_unseeded_rands = self._storage.GetUnseededRands(psize)
      test_result = self._CreateTestResult()

      msb_1 = 2**(psize - 1)
      msb_11 = msb_1 | 2**(psize - 2)
      factors = None
      for p_0 in list_unseeded_rands:
        # Also test with the most significant bits set to 1.
        for p_1 in {p_0, p_0 | msb_1, p_0 | msb_11}:
          factors = special_case_factoring.FactorWithGuess(n, p_1)
          if factors:
            break
        if factors:
          logging.warning("Key factored! Factors: %s\n%s", factors,
                          key.rsa_info)
          util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, factors)
          any_weak = True
          test_result.result = True
          break
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckSmallUpperDifferences(base_check.RSAKeyCheck):
  """Factors keys when the difference abs(p - q) is predictable."""

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(key.rsa_info.n))
      factors = rsa_util.CheckSmallUpperDifferences(n)
      if factors:
        logging.warning("Key factored! Factors: %s\n%s", factors, key.rsa_info)
        util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, factors)
        any_weak = True
        test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak


class CheckKeypairDenylist(base_check.RSAKeyCheck):
  """Checks Keypair CVE-2021-41117 vulnerability.

  Using the data provided by default_storage it's possible to detect up to
  90.6% of the weak keys, as it brute forces the first and two other bytes
  of the seed. See
  https://securitylab.github.com/advisories/GHSL-2021-1012-keypair/
  for a detailed description of the vulnerability.
  """

  def __init__(self, paranoid_storage: Optional[storage.Storage] = None):
    """CheckKeypairDenylist check constructor.

    Args:
      paranoid_storage: Instance of storage.Storage, containing GetKeypairData
        method.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    self._storage = paranoid_storage or default_storage.DefaultStorage()
    self._table = dict(self._storage.GetKeypairData().table)

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    any_weak = False
    for key in artifacts:
      test_result = self._CreateTestResult()
      n = util.Bytes2Int(key.rsa_info.n)
      n_msb = n >> (n.bit_length() - 64)
      if n_msb in self._table:
        metadata = self._table[n_msb]
        seed = bytearray([metadata[0]] + [0] * 31)
        for i in range(1, len(metadata), 2):
          seed[metadata[i]] = metadata[i + 1]
        p, q = keypair_generator.Generator(seed).generate_key(n.bit_length())
        if p * q == n:
          logging.warning("Key factored! Factors: %s\n%s", (p, q), key.rsa_info)
          util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, (p, q))
          any_weak = True
          test_result.result = True
      util.SetTestResult(key.test_info, test_result)
    return any_weak
