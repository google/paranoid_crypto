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
"""Module for finding solutions for hidden number problems.

The hidden number problems that this module tries to solve are defined as
follows: Given two list of integers a, b, a modulus n. Find an integer x
such that the values k[i] = a[i] + b[i] * x % n are biased.

This module has implementations for different kinds of biases. A description
is given in the function GetLattice.

Hidden number problems arise when the values k in the generation of ECDSA
are chosen in a non-uniform manner. In particular, we use the formulation of
a hidden number problem above, because it simplifies analyzing ECDSA signatures.
"""

from collections.abc import Iterator
import enum
from typing import Optional

import gmpy

from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import ec_util
from paranoid_crypto.lib import lcg_constants
from paranoid_crypto.lib import lll


class Bias(enum.Enum):
  """Describes the bias of the values k[i] = a[i] + b[i] * x % n."""
  MSB = 1  # The most significant bits of k[i] are 0.
  COMMON_PREFIX = 2  # The most significant bits of k[i] are the same.
  COMMON_POSTFIX = 3  # The least significant bits of k[i] are the same
  # There exists an integer m such that the most significant bits of
  # m * k[i] % n are the same.
  GENERALIZED = 4


class SearchStrategy(enum.Flag):
  """Describes how to select subsets from large sets of signatures.

  Generally, using more signatures make it easier to detect an LCG.
  Using just a small number of signatures sometimes gives flaky
  results. However using small sets of signatures can be used to
  detect weak keys if a weak random number generator is only used
  partially.

  There is of course room for additional methods:
  E.g., more strategies to select subsets are described in Section
  5.2 of https://eprint.iacr.org/2019/023.pdf. The authors of this
  paper use a lot of randomized tests. The hope here is that
  signatures can be approximately sorted by their creation time
  and that signatures with weaknesses are generated because of
  a weak version of the corresponding implementation.

  The paper above also brute forces over signature normalization.
  I.e., some implementation replace s by min(s, n-s). This is typical
  for 'secp256k1', since bitcoin requires non-malleable signatures.
  This kind of brute forcing is not necessary in many cases, since
  the constants used to detect LCGs can be precomputed so that
  weak random numbers in normalized signatures can be detected.
  """

  # Just performs a single test with a large set of signatures.
  SINGLE = 1
  # Performs multiple tests, with small sets of consecutive signatures.
  # This option allows to catch cases where only part of the signatures
  # are generated with a weak random number generator. For this option
  # it would be helpful if the signatures are for example sorted by date.
  SLIDING = 2
  # Allows to assume that the private key uses the same random
  # number generator as the signatures. This option is being used
  # to perform tests that are otherwise not possible. In some cases
  # just a key and a signature are sufficient to detect an LCG.
  INCLUDE_KEY = 4

  DEFAULT = SINGLE | SLIDING | INCLUDE_KEY


def GetLattice(a: list[int], b: list[int], w: Optional[int], n: int,
               bias: Bias):
  """Returns a lattice for a hidden number problem.

  Generally the goal is to find a hidden integer x such that the elements of
  k = [(ai + bi * x) % n for ai, bi in zip(a, b)] have a non-uniform
  distribution. As described below the bias describes the nature of the
  distribution.

  The lattice returned has the following form
  |u  0  a[0] a[1] .... a[k-1]|
  |0  v  b[0] a[1] .....b[k-1]|
  |0  0                       | * w
  | ...             L         |
  |0  0                       |

  The integers u, v and the target lattice L depend on the bias.
  Independent of the bias u and v are always chosen such that
  u % n == v % n. The effect of this is that if [r, s, ...] is a short
  vector in the lattice then hopefully x = s * r^(-1) % n.

  Generally, the goal is to find a linear combination of the vectors a and b
  such that it is close to a point in the target lattice L.

  Multiplying the lattice by a factor w has no effect on the solution. It is
  simply done so that all entries are integers. In particular using v = 1/w is
  a typical choice.

  If bias == MSB then the algorithm tries to find x, such that the elements
  of k are all close to 0 or close to n.
  To find such solutions the algorithms selects u about n, v = 1/w and L
  is the lattice of points with coordinates that are multiples of n.

  If bias == COMMON_PREFIX then the algorithm tries to find x, such that the
  elements of k have the same common prefix.
  To find such solutions the algorithm modifies the lattice used for
  bias == MSB by adding a vector [1, 1, ...., 1] to the basis of L.

  If bias == COMMON_POSTFIX then the algorithm tries to find x, such that
  the elements of k have the same value modulo w. Multiplying by each element
  of k by w^-1 mod n results in a COMMON_PREFIX problem.

  If bias == GENERALIZED then the algorithm tries to find x and m such that
  [ki * m % n for ki in k] have a common prefix. To find such solutions the
  algorithm searches for linear combinations of a and b with common prefixes.
  I.e. both u and v are set to 1/w, L is chosen as in the COMMON_PREFIX case.

  Args:
    a: an integer array
    b: an integer array
    w: expected bias. The choice of w influences the results only marginally. If
      w is None then a default value based on the input parameters is chosen.
    n: modulus
    bias: the type of the hidden number problem to be solved.

  Returns:
    an integer lattice
  """
  if len(a) != len(b):
    raise ValueError("a and b must have the same length")

  # If w is not defined then a value is chosen based on experiments.
  # We performed experiments with different values of w against a large
  # number of biased input sets. The experiments covered LCGs, truncated
  # LCGs, the Cr50 weakness, hidden subset sum problems, integers with
  # fixed parts.
  if w is None:
    if bias == Bias.MSB or bias == Bias.COMMON_PREFIX:
      # A good choice is to select w to match approximately as large as
      # the bias of the inputs.
      if len(a) < 4:
        w = 2**128
      elif len(a) < 9:
        w = 2**64
      elif len(a) < 14:
        w = 2**48
      else:
        w = 2**32
    elif bias == Bias.COMMON_POSTFIX:
      # Estimates the smallest number of bits that be detected with the
      # given number of signatures.
      bits = max(3, int(n.bit_length() / len(a) * 1.25))
      w = 2**bits
    elif bias == Bias.GENERALIZED:
      # The results of the experiments did not differ a lot:
      # w=2**64 tends to require somewhat fewer input values when the
      # input size is small. 2**32 seems a bit better for larger input sets.
      if len(a) < 20:
        w = 2**64
      elif len(a) < 32:
        w = 2**48
      else:
        w = 2**64
    else:
      raise ValueError("Unknown bias:" + str(bias))

  if bias == Bias.COMMON_POSTFIX:
    w_inv = int(gmpy.invert(w, n))
    a = [v * w_inv % n for v in a]
    b = [v * w_inv % n for v in b]
    bias = Bias.COMMON_PREFIX

  lat_size = len(a) + 2
  lat = [[0] * lat_size for _ in range(lat_size)]
  lat[0] = [n * w + 1, 0] + [v * w for v in a]
  lat[1] = [0, 1] + [v * w for v in b]
  for j in range(2, lat_size):
    lat[j][j] = n * w
  if bias == Bias.MSB:
    pass
  elif bias == Bias.COMMON_PREFIX:
    for j in range(2, lat_size):
      lat[2][j] = w
  elif bias == Bias.GENERALIZED:
    lat[0][0] = 1
    for j in range(2, lat_size):
      lat[2][j] = w
  else:
    raise ValueError("Bias not implemented:" + str(bias))
  return lat


def HiddenNumberProblem(a: list[int], b: list[int], w: Optional[int], n: int,
                        bias: Bias):
  """Solves a hidden number problem.

  Tries to find an integer x, such that
  [(ai + bi * x) % n for ai, bi in zip(a, b)] is biased.
  The nature of the bias is determined by bias and w. (see GetLattice for more
  details).

  Args:
    a: an integer array
    b: an integer array
    w: expected bias, (if w=None then a reasonable default is chosen)
    n: modulus
    bias: the type of the hidden number problem to be solved.

  Returns:
    a list of guesses for x
  """
  lat = GetLattice(a, b, w, n, bias=bias)
  res = lll.reduce(lat)
  guesses = set()
  for v in res:
    if v[0] % n != 0:
      inverse = int(gmpy.invert(v[0], n))
      guess = (v[1] * inverse) % n
      guesses.add(int(guess))
  return list(guesses)


def HiddenNumberProblemWithPrecomputation(a: list[int], b: list[int], n: int,
                                          constants: list[tuple[int, int]],
                                          w: int) -> list[int]:
  """Tries to solve a hidden number problem with precomputed constants.

  This function tries to find an integer x, such that all values
  (a[i] + b[i] * x) * constants[j][0] - constants[j][1] are close to a
  multiple of n.

  This function can for example be used to detect ECDSA signatures where
  the values k were generated with known weak random number generator.
  For many weak random number generators there exist constants (c, d) such
  that c*k mod n is close to d for any k generated with this random number
  generator. For many curves and random number generators there exist
  multiple pairs (c, d) that can detect this random number generator
  independently. By using multiple constants simultaneously it is possible
  to detect such random number generators even with only a small number
  of signatures.

  The procomputed constants can be obtained by generating a list of outputs
  k of the random number generator and generating the following lattice.
  |1/w  0   k[0] k[1] .... k[m-1]|
  |0  1/w      1    1           1|
  |0  0        n                 |  * w
  |0  0             n            |
  | ...                          |
  |0  0                         n|

  If (c, d, ...) is a short vector in this lattice then this means that
  c * k + d is potentially close to a multiple of n for all outputs of
  the random number generator.

  Args:
    a: first part of the hidden number problem
    b: second part of the hidden number problem
    n: a prime modulus
    constants: precomputed constants
    w: expected bias. This value depends on the constants and is determined
      experimentally. Typical values are 2**32 or 2**64.

  Returns:
    a list of guesses for x
  """
  lattice_size = len(a) * len(constants) + 2
  lattice = [[0] * lattice_size for _ in range(lattice_size)]
  lattice[0][0] = n * w + 1
  lattice[1][1] = 1
  for i in range(len(a)):
    for j, (c, d) in enumerate(constants):
      t = i * len(constants) + j + 2
      lattice[0][t] = (a[i] * c - d) % n * w
      lattice[1][t] = (b[i] * c % n) * w
      lattice[t][t] = n * w
  reduced = lll.reduce(lattice)
  guesses = set()
  for v in reduced:
    if v[0] % n != 0:
      guess = v[1] * gmpy.invert(v[0], n) % n
      guesses.add(int(guess))
  return list(guesses)


def _HiddenNumberProblemSubsets(
    a: list[int], b: list[int], curve_type: paranoid_pb2.CurveType,
    lcg: Optional[lcg_constants.LcgName], flags: SearchStrategy
) -> Iterator[tuple[list[int], list[int], list[tuple[int, int]], int]]:
  """Yields subsets for the hidden number problem.

  This is just a helper function for HiddenNumberProblemForCurve.

  Args:
    a: the first part of the hidden number problem
    b: the second part of the hidden number problem
    curve_type: the EC curve
    lcg: if specified then the function checks only against the given LCG. If
      lcg == None then all LCG with precomputed constants for the given curve
      are tried.
    flags: describes the subsets of signatures that are tested.

  Yields:
    tuples (a0, b0, constants, w), where a0 and b0 are subsets of a and b,
    constants are constant pair to detect an LCG, w is a parameter that
    depends on the bias of the generated samples.
  """
  if not flags:
    raise ValueError("No flags specified")
  for constants in lcg_constants.CONSTANT_FACTORY:
    if constants["curve"] != curve_type:
      continue
    if lcg not in [constants["lcg"], None]:
      continue
    sample_size = constants["sample_size"]
    min_signatures = constants["min_signatures"]
    sliding_window_size = constants["sliding_window_size"]
    constant_list = constants["constants"]
    w = constants["w"]
    if len(a) > sliding_window_size:
      # There are more signatures than necessary. The subsets are
      # chosen depending on the flags.
      tests_done = 0
      if flags & SearchStrategy.SLIDING:
        num_constants = (sample_size - 1) // sliding_window_size + 1
        for i in range(len(a) - sliding_window_size + 1):
          a0 = a[i:i + sliding_window_size]
          b0 = b[i:i + sliding_window_size]
          yield a0, b0, constant_list[:num_constants], w
          tests_done += 1

      if flags & SearchStrategy.SINGLE or not tests_done:
        size = min(len(a), 2 * sample_size)
        a0 = a[:size]
        b0 = b[:size]
        num_constants = (sample_size - 1) // size + 1
        yield a0, b0, constant_list[:num_constants], w
    elif len(a) >= min_signatures:
      # Just one test with all signatures is done.
      num_constants = (sample_size - 1) // len(a) + 1
      yield a, b, constant_list[:num_constants], w
    elif len(a) == min_signatures - 1:
      if flags & SearchStrategy.INCLUDE_KEY:
        # There is one signature missing. A detection might still be possible
        # if the private key used the same LCG as the signatures.
        num_constants = (sample_size - 1) // (len(a) + 1) + 1
        yield a + [0], b + [1], constant_list[:num_constants], w
    else:
      # There are not enogh signatures to do any reasonable test.
      continue


def HiddenNumberProblemForCurve(a: list[int], b: list[int],
                                curve_type: paranoid_pb2.CurveType,
                                lcg: Optional[lcg_constants.LcgName],
                                flags: SearchStrategy) -> list[int]:
  """Attempts to detect ECDSA signatures for a given curve.

  This function tries to find the private key used to generate
  ECDSA signatures LCGs with precomputed constants.

  Args:
    a: the first part of the hidden number problem
    b: the second part of the hidden number problem
    curve_type: the EC curve
    lcg: if specified then the function checks only against the given LCG.
    flags: describes the subsets of signatures that are tested.

  Returns:
    a list of guesses for the private key x.
  """
  if len(a) != len(b):
    raise ValueError("a and b are not of the same size")
  curve = ec_util.CURVE_FACTORY[curve_type]
  if curve is None:
    raise ValueError("Unsupported curve:" + str(curve_type))
  n = curve.n
  guesses = []
  for a0, b0, constants, w in _HiddenNumberProblemSubsets(
      a, b, curve_type, lcg, flags):
    guesses += HiddenNumberProblemWithPrecomputation(a0, b0, n, constants, w)
  return guesses
