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
"""Module for finding ECDSA signatures with the CR50 U2F weakness."""

from collections.abc import Iterator

import gmpy

from paranoid_crypto.lib import lll


def Cr50U2fSubProblem(a: int, b: int, w: int, p: int,
                      basis: list[int]) -> Iterator[tuple[int, int]]:
  """Generalized subproblem for the U2F weakness.

  This function tries to find k1, k2 of the form
  k1 = sum(c1[i] * v for i,v in enumerate(basis))
  k2 = sum(c2[i] * v for i,v in enumerate(basis))
  k1 * a + k2 * b = w (mod p) and where c1 and c2 are arrays with small integers
  (i.e. all elements < 256)

  Args:
    a: see above
    b: see above
    w: see above
    p: the modulus
    basis: the values k1 and k2 are both linear combinations of this basis with
      small coefficients.

  Yields:
    potential guesses (k1, k2)
  """
  words = len(basis)
  # size of the lattice
  lat_size = 2 * words + 2
  lat = [[0] * lat_size for i in range(lat_size)]
  for j, v in enumerate(basis):
    lat[j][j] = 1
    lat[j][-1] = v * a % p
    lat[j + words][j + words] = 1
    lat[j + words][-1] = v * b % p
  lat[-2][-2] = 256
  lat[-2][-1] = w
  lat[-1][-1] = p
  reduced = lll.reduce(lat)
  for row in reduced:
    k1 = abs(sum(v * w for v, w in zip(basis, row[:words])))
    k2 = abs(sum(v * w for v, w in zip(basis, row[words:2 * words])))
    if (k1 * a + k2 * b - w) % p == 0:
      yield k1, k2


def Cr50U2fGuesses(r1: int, s1: int, z1: int, r2: int, s2: int, z2: int,
                   n: int) -> set[int]:
  """Checks, whether two signatures use weak nonces like in the U2F flaw.

  This function tries to find x, k1, k2 such that:
     s1 * k1 == z1 + r1 * x (mod n),
     s2 * k2 == z2 + r2 * x (mod n),
     where k1 and k2 are of the form ababababcdcdcdcdefefefef...
  Args:
    r1: value r of the first signature
    s1: value s of the first signature
    z1: truncated hash of the first signature
    r2: value r of the second signature
    s2: value s of the second signature
    z2: truncated hash fo the second signature
    n: order of the EC group. The size of n must be a multiple of 32.

  Returns:
    a set of guesses for x. This function does not try to verify whether the
    values returned are likely private keys. Rather it is left to the caller
    to check if one of the values returned matches a given public key.
  Raises:
    ArithmeticError: when invariants are violated.
  """
  guesses = set()
  if n.bit_length() % 32 != 0:
    return guesses  # Not implemented
  # This function tries to find x, k1, k2 such that:
  #   s1 * k1 == z1 + r1 * x (mod n),
  #   s2 * k2 == z2 + r2 * x (mod n),
  # After eliminating x from the two equations above we get
  #   r2 * s1 * k1 - r1 * s2 * k2 == r2 * z1 - r1 * z2 (mod n)
  a = r2 * s1 % n
  b = -r1 * s2 % n
  w = (r2 * z1 - r1 * z2) % n
  basis = [0x1010101 << j for j in range(0, n.bit_length(), 32)]
  for k1, k2 in Cr50U2fSubProblem(a, b, w, n, basis):
    r1inv = int(gmpy.invert(r1, n))  # python 3.8 allows pow(r1, -1, n)
    x1 = (s1 * k1 - z1) * r1inv % n
    # Sanity check: The private keys computed from k1 or k2 must match even
    # if the guess for the private key is wrong. A mismatch indicates an
    # arithmetic error. E.g., one possible source for such errors is to mix
    # integer types from different libraries.
    x2 = (s2 * k2 - z2) * int(gmpy.invert(r2, n)) % n
    if x1 != x2:
      raise ArithmeticError("Sanity check failed")
    # The type checker can't derive that x1 is an integer, hence we need an
    # explicit coercion.
    x = int(x1)
    guesses.add(x)
  return guesses
