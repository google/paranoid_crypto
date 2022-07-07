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
"""Detects ROCA weak keys (https://en.wikipedia.org/wiki/ROCA_vulnerability)."""


class ROCAKeyDetector(object):
  """Detect weak ROCA keys."""

  PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
            71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
            149, 151, 157, 163, 167, 173)
  F4 = 0x10001

  def __init__(self):
    self.product_of_primes = 1
    for prime in self.PRIMES:
      self.product_of_primes *= prime

  def _HasDiscreteLog(self, value, base, n):
    b = base % n
    accumulator = 1
    for unused_exponent in range(1, n):
      if accumulator == value:
        return True
      accumulator = (accumulator * b) % n
    return False

  def IsWeak(self, modulus):
    """Check an RSA modulus for weakness against ROCA.

    Args:
      modulus: modulus of an RSA key with an exponent of 0x10001

    Returns:
      (bool) True if the provided key is (with high probability) weak.
    """
    mod_product_of_primes = modulus % self.product_of_primes
    for prime in self.PRIMES:
      mod_p = mod_product_of_primes % prime
      if not self._HasDiscreteLog(mod_p, self.F4, prime):
        return False
    return True


class ROCAKeyVariantDetector(object):
  """Tries to detect keys similar to ROCA but with unknown base."""

  # a list of the 48 smallest primes > 3
  PRIMES = (5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
            71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
            149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
            223, 227, 229)

  def __init__(self):
    self.roca_key_detector = ROCAKeyDetector()
    self.quadratic_residues = {}
    for p in self.PRIMES:
      self.quadratic_residues[p] = self._QuadraticResidues(p)

  def _QuadraticResidues(self, p: int) -> list[bool]:
    """Computes the quadratic residues modulo p.

    Args:
      p: the modulus

    Returns:
      a boolean array of length p, where a[i] == True if i is a quadratic
      residue modulo p.
    """
    a = [False] * p
    for i in range(p):
      a[i * i % p] = True
    return a

  def IsWeak(self, modulus: int) -> bool:
    """Checks an RSA modulus for a weakness against ROCA variants.

    The ROCA RSA keys were generated such that the primes modulo a product
    of small primes have a discrete log for the base 65537. Knowing the base
    allows to detect such keys with the method in ROCAKeyDetector.

    This function implements an alternative method, that works indepenently of
    the base, but only detects weak keys with a probability of 50%. The method
    is based on the observation that if M is the product of small primes,
    p = base^r1 (mod M) and q = base^r2 (mod M) and r1 == r2 (mod 2) then
    n = p * q is a quadratic residue modulo the prime factors of M.

    The probability that a randomly generated RSA key fails the test is about
    2^(-48).

    Args:
      modulus: modulus of an RSA key

    Returns:
      (bool) True if the provided key is suspicious.
    """
    for p, qr in self.quadratic_residues.items():
      if not qr[modulus % p]:
        return False
    # Excludes keys that are already detected by ROCAKeyDetector,
    # so that new vulnerabilities are easier to notice.
    if self.roca_key_detector.IsWeak(modulus):
      return False
    return True
