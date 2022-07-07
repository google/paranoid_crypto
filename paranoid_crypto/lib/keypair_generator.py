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
"""Module for generating RSA keys like https://www.npmjs.com/package/keypair.

NOTE: This implementation is vulnerable and has been written as a helper for the
solely purpose of testing keys potentially weak to CVE-2021-41117. Please do not
copy-paste nor use this code.
"""
import hashlib
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
import gmpy

GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2]


class Generator():
  """Class for generating Keypair modulus for a given seed and bit size."""

  def __init__(self, seed: bytes):
    """Initializes the PRNG given an initial seed.

    Args:
      seed: the initial seed used in the PRNG.
    """
    t = hashlib.sha1(seed).digest()
    key = hashlib.sha1(t).digest()
    self.orig_key = key
    seed = hashlib.sha1(key).digest()
    self.key = key[:16]
    self.seed = seed[:16]

  def generate_prime(self, p_size_bits: int) -> int:
    """Generates a prime using Keypair PRNG.

    The prime is assembled by concatenating AES blocks. Original implementation
    is at https://github.com/juliangruber/keypair/blob/master/index.js.

    Args:
      p_size_bits: bit size of the prime to be generated.

    Returns:
      The generated prime.
    """
    p_size_bytes = p_size_bits // 8
    while True:
      prime_bytes = b''
      idx = 0
      while len(prime_bytes) <= p_size_bytes:
        # Add chunk
        encryptor = ciphers.Cipher(algorithms.AES(self.key),
                                   modes.ECB()).encryptor()
        prime_bytes += encryptor.update(self.seed)
        # Update key and seed
        seed_inc = (int.from_bytes(self.seed, 'big') + 1).to_bytes(16, 'big')
        self.key = encryptor.update(seed_inc)
        encryptor = ciphers.Cipher(algorithms.AES(self.key),
                                   modes.ECB()).encryptor()
        self.seed = encryptor.update(seed_inc)

      # Discard first and last bytes
      prime_bytes = prime_bytes[1:p_size_bytes + 1]
      p = int.from_bytes(prime_bytes, 'big')
      p |= 1 << (p_size_bits - 1)  # Set MSB
      p += 31 - p % 30  # Align number on 30k+1 boundary
      while not gmpy.is_prime(p, 1):
        p += GCD_30_DELTA[idx % 8]
        idx += 1
      if gmpy.is_prime(p, 10):
        return p

  def generate_key(self, bits: int) -> tuple[int, int]:
    """Generates the primes as in an RSA key.

    Args:
      bits: bit size of the RSA key/modulus.

    Returns:
      a tuple containing the two primes of the RSA key/modulus.
    """
    p_size_bits = bits // 2
    p = self.generate_prime(p_size_bits)
    q = self.generate_prime(p_size_bits)
    while True:
      if q > p:
        p, q = q, p
      n = p * q
      if n.bit_length() == bits:
        return p, q
      q = self.generate_prime(p_size_bits)
