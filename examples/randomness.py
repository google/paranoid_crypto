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
"""This module contains an example for the randomness test suites.

The individual tests are implemented in paranoid_crypto/lib/randomness_tests.
This module is essentially just one way to call these tests.
It assumes that a large number of bytes of a random number generator
are available for testing. Many examples of pseudorandom number generators are
implemented at paranoid_crypto/lib/randomness_tests/rng.py for testing purposes.
"""

import cProfile
from absl import app
from absl import flags
from paranoid_crypto.lib.randomness_tests import random_test_suite
from paranoid_crypto.lib.randomness_tests import rng

_SOURCE = flags.DEFINE_enum("source", "urandom",
                            rng.RngNames() + ["all"],
                            "defines the source of the random bits to test")
_SIZE = flags.DEFINE_integer("size", 10000000, "number of bits to test")
_PROF = flags.DEFINE_bool("prof", None,
                          "generates a simple profile using cProfile")
_RESULT_LEVEL = flags.DEFINE_integer(
    "result_level", 1,
    "0: only logs failures, 1: logs summaries, 2:all results")
_SIGNIFICANCE_LEVEL_REPEAT = flags.DEFINE_float(
    "significance_level_repeat", 0.01,
    "repeats tests with significance level below this value")
_SIGNIFICANCE_LEVEL_FAIL = flags.DEFINE_float(
    "significance_level_fail", 1e-9,
    "tests with significance level below this value fail")
_MIN_REPETITIONS = flags.DEFINE_integer("min_repetitions", 1,
                                        "minimal number of repetitions")
_TEST = flags.DEFINE_string("test", None,
                            "restricts tests to ones starting with this value")


def test_source(prng_name: str) -> None:
  """Tests a named random number generator.

  Args:
    prng_name: the name of a random number generator defined in rng.RNGS.
  """
  prng = rng.GetRng(prng_name)
  size = _SIZE.value
  test = _TEST.value
  significance_level_repeat = _SIGNIFICANCE_LEVEL_REPEAT.value
  significance_level_fail = _SIGNIFICANCE_LEVEL_FAIL.value
  min_repetitions = _MIN_REPETITIONS.value
  result_level = _RESULT_LEVEL.value
  random_test_suite.TestSource(prng_name, prng.RandomBits, size,
                               significance_level_repeat,
                               significance_level_fail, test, result_level,
                               min_repetitions)


def test_sources() -> None:
  """Tests a specified pseudo random number generator or all of them."""
  if _SOURCE.value == "all":
    for prng_name in rng.RngNames():
      test_source(prng_name)
  else:
    test_source(_SOURCE.value)


# Sample output for 100 MB
# ------------------------
# $ python3 randomness.py --source=urandom --size=800000000
#
# -------- Testing: urandom --------
# number of bits: 800000000
# Frequency                      passed: p=0.412682        (0.07s)
# BlockFrequency                 passed: p=0.867963        (0.31s)
# Runs                           passed: p=0.790792        (0.25s)
# LongestRuns                    passed: p=0.167829        (0.90s)
# BinaryMatrixRank               passed: p=0.588735        (47.33s)
# Spectral                       passed: p=0.435987        (139.89s)
# OverlappingTemplateMatching    passed: p=0.887825        (1.70s)
# Universal                      passed: p=0.521065        (76.87s)
# LinearComplexity [512]         passed: 2                 (6.26s)
# LinearComplexity [1024]        passed: 2                 (5.50s)
# LinearComplexity [2048]        passed: 2                 (5.45s)
# LinearComplexity [4096]        passed: 2                 (5.88s)
# Serial                         passed: 42                (56.06s)
# ApproximateEntropy             passed: 19                (49.62s)
# RandomWalk                     passed: 28                (67.00s)
# LargeBinaryMatrixRank          passed: 9                 (7.54s)
# LinearComplexityScatter [32, 100000] passed: p=0.450327        (0.17s)
# LinearComplexityScatter [64, 50000] passed: p=0.640746        (0.10s)
# LinearComplexityScatter [128, 40000] passed: p=0.165547        (0.15s)
# FindBias [256]                 passed: p=0.818161        (5.23s)
# FindBias [384]                 passed: p=0.156196        (6.12s)
# FindBias [512]                 passed: p=0.218308        (9.21s)
# FindBias [1024]                passed: p=0.122032        (20.61s)
# NonOverlappingTemplateMatching passed: 284               (31.57s)
# passed    : 405/405
# total time: 575.29s


def main(argv: list[str]) -> None:
  """Main.

  Args:
    argv: command line arguments.
  """
  if len(argv) > 1:
    raise app.UsageError("Too many commandline arguments.")
  if _PROF.value:
    with cProfile.Profile() as profile:
      test_sources()
    profile.print_stats(sort=1)
  else:
    test_sources()


if __name__ == "__main__":
  app.run(main)
