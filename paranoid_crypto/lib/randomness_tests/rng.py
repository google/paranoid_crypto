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
"""This module implements pseudorandom number generators for testing.

Many of the pseudorandom number generators in this module have serious
weaknesses.
Hence they should not be used in production.
"""

import hashlib
import math
import os
import random
from typing import Optional

import gmpy
from numpy import random as numpy_random


class Rng:
  """Interface for pseudorandom number generators defined here."""

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """Generates random bits.

    Args:
      n: the number of bits to generate.
      seed: a seed to initialize the pseudorandom number generator. Should be
        used for testing only. If the seed is None then the pseudorandom number
        generator is seeded randomly and subsequent calls to this function
        return unrelated results.

    Returns:
      an integer in the range 0 .. 2**n - 1
    """
    raise NotImplementedError("must be implemented by subclass")


class Urandom(Rng):
  """A pseodorandom number generator using os.urandom.

  The results of this pseudorandom number generator should be indistinguishable
  from random data.
  """

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    del seed  # Cannot seed os.urandom
    ba = os.urandom((n + 7) // 8)
    seq = int.from_bytes(ba, "little")
    if n % 8 != 0:
      seq >>= -n % 8
    return seq


class Shake128(Rng):
  """Uses SHAKE128 to generate pseudorandom bits.

  SHAKE128 is a cryptographically strong pseudorandom number generator.
  It is defined in FIPS 202 "SHA-3 Standard: Permutation-Based Hash and
  Extendable-Output Functions."
  Hence, we expect that all statistical tests pass with this generator.
  If test don't pass then the test is very likely buggy or uses incorrect
  statistics.
  """

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    shake = hashlib.shake_128()
    if seed is None:
      shake.update(os.urandom(8))
    else:
      shake.update(
          seed.to_bytes((seed.bit_length() + 8) // 8, "little", signed=True))
    seq = int.from_bytes(shake.digest((n + 7) // 8), "little")  # pylint: disable=too-many-function-args
    if n % 8 != 0:
      seq >>= -n % 8
    return seq


class Mt19937(Rng):
  """Mersenne Twister with 19937 bits of state.

  The module random in python uses this Mersenne Twister.
  The same pseudorandom number generator is also implemented in
  numpy.random.MT19937.

  This a LFSR, and hence can be recognized for example by determining
  the linear complexity of the output. The rank of a n*n binary matrix
  where the rows are generated with this pseudorandom number generator
  is at most 19937. Hence a matrix rank test with sufficiently large
  matrices can recognize this pseudorandom number generator.
  """

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    random.seed(seed)
    return random.getrandbits(n)


class GmpRand(Rng):
  """A random number generator using GMP.

  The random number generator of GMP uses a truncated LCG.
  Therefore instances of this random number generator should be detected
  with the test FindBias.

  GMP defines several LCGs of different size. The LCG depends on the
  output size. The size of the state of the LCG is twice the size of its
  output. This is the case, since GMP only outputs the upper half of its
  state.

  GmpRand(16) fails:
    FindBias with 5'000 bits
    Spectral with 10'000'000 bits

  GmpRand(20) fails:
    Spectral with 100'000'000 bits
  FindBias needs better alignment

  GmpRand(32) fails:
    FindBias with 5'000 bits

  GmpRand(64) fails:
    FindBias with 5'000 bits

  GmpRand(128) fails:
    FindBias with 10'000 bits
  """

  def __init__(self, output_size: int):
    """Constructs a random number generator using GMP.

    Args:
      output_size: the output size of the LCG. The internal state of the LCG is
        2*output_size.
    """
    self.output_size = output_size

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    if seed is None:
      seed = int.from_bytes(os.urandom(16), "little")
    gmpy.rand("init", self.output_size)
    gmpy.rand("seed", seed)
    return int(gmpy.rand("next", 1 << n))


class XorShift128plus(Rng):
  """A random number generator using XorShift128+.

  The biggest weakness of XorShift128+ is that the lsb of its output
  has a low linear complexity. Hence it should be easy to distinguish
  from random.

  MatrixRank should fail if large matrices were used.
  """

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    if seed:
      x, y = divmod(seed, 2**64)
    else:
      x = int.from_bytes(os.urandom(8), "little")
      y = int.from_bytes(os.urandom(8), "little")
    blocks = []
    for _ in range((n + 63) // 64):
      x = (x ^ (x << 23)) % 2**64
      x ^= x >> 17
      x ^= y ^ (y >> 26)
      blocks.append((x + y) % 2**64)
    ba = bytearray().join(z.to_bytes(8, "little") for z in blocks)
    res = int.from_bytes(ba, "little")
    if n % 64 != 0:
      res &= (1 << n) - 1
    return res


class XorShiftStar(Rng):
  """A random number generator using XorShift*.

  The biggest weakness of XorShift* is that the lsb of its output
  has a low linear complexity. Hence it should be easy to distinguish
  from random.

  Reference: https://en.wikipedia.org/wiki/Xorshift

  MatrixRank should fail if large matrices were used.
  """

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    if seed:
      x = seed % 2**64
    else:
      x = int.from_bytes(os.urandom(8), "little")
    blocks = []
    for _ in range((n + 63) // 64):
      x ^= x >> 12
      x = (x ^ (x << 25)) % 2**64
      x ^= x >> 27
      blocks.append(x * 0x2545f4914f6cdd1d % 2**64)
    ba = bytearray().join(z.to_bytes(8, "little") for z in blocks)
    res = int.from_bytes(ba, "little")
    if n % 64 != 0:
      res &= (1 << n) - 1
    return res


class Xorwow(Rng):
  """A random number generator using Xorwow.

  The biggest weakness of XorShift* is that the lsb of its output
  has a low linear complexity. Hence it should be easy to distinguish
  from random.

  Reference: https://en.wikipedia.org/wiki/Xorshift

  MatrixRank should fail if large matrices were used.
  """

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    if seed:
      seed, state = divmod(seed, 2**160)
      ctr = seed % 2**32
    else:
      state = int.from_bytes(os.urandom(20), "little")
      ctr = int.from_bytes(os.urandom(4), "little")
    blocks: list[int] = []
    for _ in range((n + 31) // 32):
      s = state % 2**32
      t, s0 = divmod(state, 2**160)
      t ^= t >> 2
      t ^= (t << 1) % 2**32
      t ^= (s ^ (s << 4)) % 2**32
      state = t + (s0 << 32)
      # For some reason pytype thinks that (t + ctr) % 2**32) can be of type
      # float.
      out = int((t + ctr) % 2**32)
      blocks.append(out)
      ctr = (ctr + 362437) % 2**32
    ba = bytearray().join(z.to_bytes(4, "little") for z in blocks)
    res = int.from_bytes(ba, "little")
    if n % 32 != 0:
      res &= (1 << n) - 1
    return res


class JavaRandom(Rng):
  """A random number generator implemented in Java.

  This class is a reimplementation of java.util.Random.
  RandomBits() has been implemented so that it gives the same output
  as new BigInteger(n, new java.util.Random()).

  This random number generator uses a truncated LCG.
  Hence it should be detected by FindBias. Other weaknesses are
  that it has a small state (48 bits) and that the least significant
  bits of its output have a small period.

  The following tests fail:
    FindBias with 10'000 bits.
    Spectral with 100'000'000 bits.
  """

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    a = 0x5deece66d
    c = 0xb
    mask = 0xffffffffffff
    if seed is None:
      seed = int.from_bytes(os.urandom(6), "big")
    state = (seed ^ a) & mask
    num_bytes = (n + 7) // 8
    values = (num_bytes + 3) // 4
    ba = bytearray(4 * values)
    for j in range(values):
      state = (state * a + c) & mask
      output = state >> 16
      ba[4 * j:4 * (j + 1)] = output.to_bytes(4, "little")
    if len(ba) != num_bytes:
      ba = ba[:num_bytes]
    if n % 8 != 0:
      ba[0] &= (1 << (n % 8)) - 1
    return int.from_bytes(ba, "big")


class LcgNist(Rng):
  """A pseudorandom number generator proposed in SP 800-22 for testing.

  Described in Section D.1 of SP 800-22. The random number generator is based
  on the paper "An exhaustive analysis of multiplicative congruential random
  number generators with modulus 2**31-1" by Fishman, G. S. and L. R. Moore,
  SIAM Journal on Scientific and Statistical Computation, 7, 24-45, 1986.

  The LCG only outputs a single bit per step. Because of this the LCG is
  somewhat more difficult to detect than LCGs that output multiple bits.
  The Sectral test detects it with 10'000'000 bits of input.
  """

  def __init__(self, a: int = 950706376):
    self.a = a

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    # Default by NIST: seed = 23482349
    if seed is not None:
      seed = 1 + (seed - 1) % ((1 << 31) - 2)
    else:
      while True:
        seed = int.from_bytes(os.urandom(4), "little")
        if 1 < seed < 2**31 - 1:
          break
    res = bytearray((n + 7) // 8)
    for i in range(len(res)):
      b = 0
      for j in range(8):
        seed = self.a * seed % ((1 << 31) - 1)
        b ^= (seed >> 30) << j
      res[i] = b
    if n % 8:
      res[-1] &= (1 << (n % 8)) - 1
    return int.from_bytes(res, "little")


class Mwc(Rng):
  """Implements the multiply-with-carry pseudorandom number generator.

  MWC is equivalent to a Lehmer pseudorandom number generator. It uses
  parameters that are specifically chosen so that the generator can be
  implemented efficiently even with a large modulus.

  FindBias detects this pseudorandom number generator.
  """

  def __init__(self, a: int, b: int):
    if 1 << (b.bit_length() - 1) != b or b.bit_length() % 8 != 1:
      raise ValueError("Expecting b to be a power of 256")
    self.a = a
    self.b = b
    self.ab1 = a * b - 1
    self.output_bits = b.bit_length() - 1

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    if seed is None:
      y = int.from_bytes(os.urandom(self.ab1.bit_length() // 8 + 8),
                         "little") % self.ab1
    else:
      y = seed
    ba = bytearray()
    chunk_size = self.output_bits // 8
    for _ in range((n + self.output_bits - 1) // self.output_bits):
      # MWC is equivalent to a Lehmer generator. This equivalence is used here,
      # since it simplifies the implementation and performance is not very
      # important here.
      y = self.a * y % self.ab1
      ba += (y % self.b).to_bytes(chunk_size, "little")
    res = int.from_bytes(ba, "little")
    if len(ba) * 8 != n:
      res &= (1 << n) - 1
    return res


class NumpyRng(Rng):
  """Base class for wrapping numpy's pseodurandom number generators."""

  def __init__(self, bit_generator: type[numpy_random.BitGenerator]):
    self.bit_generator = bit_generator

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    rand = numpy_random.Generator(self.bit_generator(seed=seed))
    ba = rand.bytes((n + 7) // 8)
    res = int.from_bytes(ba, "little")
    if n % 8:
      res &= (1 << n) - 1
    return res


class Lehmer(Rng):
  """Lehmer pseudorandom number generator.

  https://en.wikipedia.org/wiki/Lehmer_random_number_generator.
  Default parameters use a 128 bit instance proposed by L'Ecuyer.

  FindBias can detect this pseudorandom number generator. Detection still
  works if the output is truncated to 16 bits, but fails when only 8 bits per
  step are used as output. The spectral test
  can detect some LCGs that only output 1 bit per step. Hence,
  a Lehmer generator with a small number of output bits per step
  is currently a blind spot for the testing.
  """

  def __init__(self,
               a: int = 25096281518912105342191851917838718629,
               mod: int = 2**128,
               bits: int = 64):
    """Constructs a Lehmer pseudo random number generator.

    Args:
      a: the multiplier
      mod: the modulus
      bits: the number of bits of output per step. This implementation only
        supports output sizes that are a multiple of 8.
    """
    if bits % 8 != 0:
      raise ValueError("not implemented")
    self.a = a
    self.mod = mod
    self.bits = bits

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    if seed is None:
      while True:
        seed = int.from_bytes(
            os.urandom(self.mod.bit_length() // 8 + 8), "little") % self.mod
        if math.gcd(seed, self.mod) == 1:
          break
    state = seed
    ba = bytearray()
    while 8 * len(ba) < n:
      state = state * self.a % self.mod
      output = (state << self.bits) // self.mod
      output_bytes = output.to_bytes(self.bits // 8, "little")
      ba += bytearray(output_bytes)
    res = int.from_bytes(ba, "little")
    if 8 * len(ba) != n:
      res &= (1 << n) - 1
    return res


class Pcg64(NumpyRng):
  """PCG 64.

  Based on the paper
  "PCG: A Family of Simple Fast Space-Efficient Statistically
  Good Algorithms for Random Number Generation" by Melissa E. O’Neill
  https://www.cs.hmc.edu/tr/hmc-cs-2014-0905.pdf
  """

  def __init__(self):
    super().__init__(numpy_random.PCG64)


class Philox(NumpyRng):
  """Philox random number generator.

  Probposed in J. K. Salmon, M. A. Moraes, R. O. Dror, and D. E. Shaw,
  “Parallel Random Numbers: As Easy as 1, 2, 3,”,
  Proceedings of the International Conference for High Performance Computing,
  Networking, Storage and Analysis (SC11), ACM, 2011.
  """

  def __init__(self):
    super().__init__(numpy_random.Philox)


class Sfc64(NumpyRng):
  """SFC64 random number generator.

  http://pracrand.sourceforge.net/RNG_engines.txt
  """

  def __init__(self):
    super().__init__(numpy_random.SFC64)


class SubsetSum(Rng):
  """Generates random integers as the sum of a subset of generators.

  Subset sums are sometimes proposed as a short cut to generate ephemeral
  key pairs s, g**s for public key cryptosystems or signature schemes.
  The idea is to use a list of precomputed pairs (x_i, g**x_i) and then generate
  s as sum of a subset of the values {x_i} and g**s as the product of the
  corresponding values {g**x_i}.

  Cryptographic schemes using such short cuts are often susceptible to attacks.
  Hence, we want to know if a subset sum generator can be detected with a
  statistical analysis.

  The difficulty to detect such pseudorandom number generators depends on
  the number of generators:

  SubsetSum(256, 16) has significant statistical deficiencies and thus fails
  a lot of tests. E.g., with 100'000'000 bits of inputs
  FindBias, LongestRun, ApproximateEntropy, Serial and NonOverlappingTemplates
  all fail. OverlappingTemplates and Frequency might also fail with more
  testing.

  SubsetSum(256, 24) is still easy to detect since collisions are likely.
  FindBias, ApproximateEntropy using m>=16 and Serial using m>=16 all fail.

  SubsetSum(256, 32) can be detected with FindBias.
  ApproximateEntropy may detect the PRNG with large m. However, the test as
  described by NIST does not give conclusive results.

  SubsetSum(256, 40) can be detected with FindBias. Also possible is to
  detect SubsetSum(512, 56). Larger generator sets such as SubsetSum(256, 48)
  or SubsetSum(512, 64) are currently not detectable. The main reason is
  that FindBias is a relatively general algorithm. Additionally, the size
  of lattice used in FindBias has an upper bound of 72.

  A better algorithm was proposed by J.-S. Coron and A. Gini in the paper
  "A Polynomial-Time Algorithm for Solving the Hidden Subset Sum Problem",
  https://eprint.iacr.org/2020/461.pdf.
  """

  def __init__(self, bits: int, n: int):
    """Constructs a SubsetSum generator.

    Args:
      bits: the size of the generators in bits
      n: the number of generators
    """
    if bits % 8 != 0:
      raise ValueError("only implemented if bits is a multiple of 8")
    self.bits = bits
    self.n = n

  def _Generators(self) -> list[int]:
    """Returns a new list of generators.

    Returns:
      a list of n random integers in the range 0 .. 2**self.bits - 1.
    """
    generators = []
    for _ in range(self.n):
      generators.append(int.from_bytes(os.urandom(self.bits // 8), "little"))
    return generators

  def RandomBits(self, n: int, *, seed: Optional[int] = None) -> int:
    """See base class."""
    del seed
    generators = self._Generators()
    ba = bytearray()
    while len(ba) * 8 < n:
      subset_sum = 0
      rand_bits = os.urandom((len(generators) + 7) // 8)
      for i, g in enumerate(generators):
        if (rand_bits[i // 8] >> (i % 8)) & 1:
          subset_sum += g
      if subset_sum == 0:
        continue
      subset_sum &= (1 << self.bits) - 1
      ba += bytearray(subset_sum.to_bytes(self.bits // 8, "little"))
    res = int.from_bytes(ba, "little")
    if 8 * len(ba) != n:
      res &= (1 << n) - 1
    return res


RNGS = {
    "urandom": Urandom(),
    "mt19937": Mt19937(),
    "shake128": Shake128(),
    "gmp16": GmpRand(16),
    "gmp20": GmpRand(20),
    "gmp28": GmpRand(28),
    "gmp32": GmpRand(32),
    "gmp64": GmpRand(64),
    "gmp128": GmpRand(128),
    "mwc64": Mwc(2**64 - 742, 2**64),
    "mwc128": Mwc(2**128 - 10480, 2**128),
    "mwc256": Mwc(2**256 - 9166, 2**256),
    "mwc512": Mwc(2**512 - 150736, 2**512),
    "lehmer128": Lehmer(),
    "lehmer128/16": Lehmer(bits=16),
    "lehmer128/8": Lehmer(bits=8),
    "xorshift128+": XorShift128plus(),
    "xorshift*": XorShiftStar(),
    "xorwow": Xorwow(),
    "java": JavaRandom(),
    "lcgnist": LcgNist(),
    "pcg64": Pcg64(),
    "philox": Philox(),
    "sfc64": Sfc64(),
    "subsetsum256/16": SubsetSum(256, 16),
    "subsetsum256/24": SubsetSum(256, 24),
    "subsetsum256/32": SubsetSum(256, 32),
    "subsetsum256/40": SubsetSum(256, 40),
    "subsetsum256/48": SubsetSum(256, 48),
    "subsetsum512/56": SubsetSum(512, 56),
    "subsetsum512/64": SubsetSum(512, 64),
    "subsetsum1024/64": SubsetSum(1024, 64),
}


def RngNames() -> list[str]:
  """Returns the names of available random number generators.

  Returns:
    a list of names
  """
  return list(RNGS)


def GetRng(name: str) -> Rng:
  """Returns a random number generator for a given name.

  Args:
    name: the name of the random number generator

  Returns:
    the random number generator
  """
  if name not in RNGS:
    raise ValueError(f"{name} unknown")
  return RNGS[name]
