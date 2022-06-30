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
"""This module contains the main function for the test suites.

The individual tests are implemented in random_test_suite.
This module is essentially just one way to call these tests.
It assumes that a large number of bytes of a random number generator
are available for testing.
"""

import cProfile
from absl import app
from absl import flags
from absl import logging
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
# blaze run -c opt demo -- --source=urandom --size=800000000
#
# -------- Testing: urandom --------
# number of bits: 800000000
# Frequency                      passed: p=0.537314        (0.05s)
# BlockFrequency                 passed: p=0.075785        (0.31s)
# Runs                           passed: p=0.482132        (0.17s)
# LongestRuns                    passed: p=0.268165        (0.66s)
# BinaryMatrixRank               passed: p=0.543245        (52.67s)
# Spectral                       passed: p=0.271534        (129.55s)
# OverlappingTemplateMatching    passed: p=0.125318        (1.90s)
# Universal                      passed: p=0.259407        (102.22s)
# LinearComplexity [512]         passed: 2                 (6.97s)
# LinearComplexity [1024]        passed: 2                 (5.93s)
# LinearComplexity [2048]        passed: 2                 (5.55s)
# LinearComplexity [4096]        passed: 2                 (6.68s)
# Serial                         passed: 42                (64.01s)
# ApproximateEntropy             passed: 19                (57.16s)
# RandomWalk                     passed: 28                (68.52s)
# LargeBinaryMatrixRank          passed: 9                 (8.49s)
# LinearComplexityScatter [32, 100000] passed: p=0.859695        (0.19s)
# LinearComplexityScatter [64, 50000] passed: p=0.846455        (0.11s)
# LinearComplexityScatter [128, 40000] passed: p=0.904050        (0.16s)
# FindBias [256]                 passed: p=0.474528        (5.11s)
# FindBias [384]                 passed: p=0.985698        (5.87s)
# FindBias [512]                 passed: p=0.086568        (7.98s)
# FindBias [1024]                passed: p=0.239451        (18.21s)
# NonOverlappingTemplateMatching passed: 284               (33.20s)
# passed    : 405/405
# total time: 615.81s


def main(argv: list[str]) -> None:
  """Main.

  Args:
    argv: command line arguments.
  """
  logging.use_python_logging()
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
