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
"""This module contains the main function for all test suites.

The individual tests are implemented in nist_suite.py and lattice_suite.py.
This module is essentially just one way to call these tests.
It assumes that a large number of bytes of a random number generator
are available for testing.
"""

import collections
from collections.abc import Callable
import enum
import time
from typing import Optional, Any, Union
from absl import logging
from paranoid_crypto.lib.randomness_tests import extended_nist_suite
from paranoid_crypto.lib.randomness_tests import lattice_suite
from paranoid_crypto.lib.randomness_tests import nist_suite
from paranoid_crypto.lib.randomness_tests import util

# Type hints:

# A source is a function that given an integer n returns n pseudorandom bits.
Source = Callable[[int], int]

# A test takes a bit string and additional parameters. It either returns a
# single p-value or a list of tuples with a name and pvalues.
Test = Callable[..., Union[float, nist_suite.NamedPValues]]

NIST_TESTS = [
    (nist_suite.Frequency, []),
    (nist_suite.BlockFrequency, []),
    (nist_suite.Runs, []),
    (nist_suite.LongestRuns, []),
    (nist_suite.BinaryMatrixRank, []),
    (nist_suite.Spectral, []),
    (nist_suite.NonOverlappingTemplateMatching, []),
    (nist_suite.OverlappingTemplateMatching, []),
    (nist_suite.Universal, []),
    (nist_suite.LinearComplexity, [512]),
    (nist_suite.LinearComplexity, [1024]),
    (nist_suite.LinearComplexity, [2048]),
    (nist_suite.LinearComplexity, [4096]),
    (nist_suite.Serial, []),
    (nist_suite.ApproximateEntropy, []),
    (nist_suite.RandomWalk, []),
]

EXTENDED_NIST_TESTS = [
    (extended_nist_suite.LargeBinaryMatrixRank, []),
    # Computing the linear complexity has quadratic complexity.
    # A consequence of this is that LinearComplexityScatter only
    # uses a fraction of the input. A parameter [n, m] means
    # that n m-bit sequences are tested, where the i-th sequence
    # consists of the bits i, i + n, ..., i + (m-1) * m.
    (extended_nist_suite.LinearComplexityScatter, [32, 100000]),
    (extended_nist_suite.LinearComplexityScatter, [64, 50000]),
    (extended_nist_suite.LinearComplexityScatter, [128, 40000]),
]

LATTICE_TESTS = [
    (lattice_suite.FindBias, [256]),
    (lattice_suite.FindBias, [384]),
    (lattice_suite.FindBias, [512]),
    (lattice_suite.FindBias, [1024]),
]

TESTS = NIST_TESTS + EXTENDED_NIST_TESTS + LATTICE_TESTS


class State(enum.Enum):
  """Defines the state of a test.

  Tests with state UNDECIDED have p-values that are low, but not low enough
  to exclude random flukes. Such tests are repeated.
  """
  PASSED = 1
  UNDECIDED = 2
  FAILED = 3


class TestStructure:
  """A structure to keep results from multiple runs of a test."""

  def __init__(self,
               test: Test,
               params: list[Any],
               p_value_fail: float,
               p_value_repeat: float,
               min_repetitions: int = 1):
    """Constructs a new TestStructure.

    Instances keep track of results from possibly several test runs.
    A combined p-value is computed whenever muptiple p-values for the same
    test exist.

    For example, calling LinearComplexity returns a list with two p-values
    such as
      [('distribution', 0.271381), ('extreme values', 0.413929)]
    If this test is repeated, all the p-values for the two sub-tests
    'distribution' and 'extreme values' are combined into two values
    combined_p_values['distribution'] and combined_p_values['extreme values']
    A test fails if the combined p-value is smaller than p_value_fail.
    A test passes if the combined p-value is larger than combining
    p_value_repeat the same number of times.

    Args:
      test: The test. This is a function that takes a bit string and its length
        as the first two parameters and additional parameters.
      params: Additional parameters for test.
      p_value_fail: the test fails
      p_value_repeat: a value smaller than this value causes the test to repeat.
      min_repetitions: minimal number of repetitions regardless of p-value.
    """
    self.test = test
    self.params = params
    self.p_value_fail = p_value_fail
    self.p_value_repeat = p_value_repeat
    self.min_repetitions = min_repetitions
    self.p_values = collections.defaultdict(list)
    self.combined_p_values = {}
    self.state = {}
    self.finished = False
    self.test_name = test.__name__
    if params:
      self.test_name += " " + str(params)
    self.runs = 0
    self.runtime = 0.0

  def Run(self, bits: int, n: int) -> bool:
    """Runs the test with a bit string.

    Args:
      bits: the bit string to test
      n: the length of the bit string

    Returns:
      True if the test is finished and False if it needs to be repeated.
    """
    start = time.time()
    self.runs += 1
    try:
      test_result = self.test(bits, n, *self.params)
    except nist_suite.InsufficientDataError as ex:
      logging.info("%-30s skipped: %s", self.test_name, str(ex))
      self.finished = True
      return True
    self.runtime = time.time() - start

    # Merges results
    if isinstance(test_result, float) or isinstance(test_result, int):
      test_result = [("result", test_result)]
    undecided = 0
    for name, p_value in test_result:
      pvals = self.p_values[name]
      pvals.append(p_value)
      pval = util.CombinedPValue(pvals)
      self.combined_p_values[name] = pval
      if pval < self.p_value_fail:
        self.state[name] = State.FAILED
      else:
        repeat_prob = util.CombinedPValue([self.p_value_repeat] * len(pvals))
        if repeat_prob < pval:
          self.state[name] = State.PASSED
        else:
          self.state[name] = State.UNDECIDED
          undecided += 1
    self.finished = undecided == 0 and self.runs >= self.min_repetitions
    return self.finished

  def FormatPValue(self, name: str) -> str:
    """Formats a p-value.

    Args:
      name: the name of the p-value.

    Returns:
      the formatted p-value.
    """
    p_value = self.combined_p_values[name]
    if p_value < 1e-5:
      pv = f"{p_value:g}"
    else:
      pv = f"{p_value:.6f}"
    state = self.state[name].name.lower()
    return f"{state}: p={pv:10}"

  def StateCount(self) -> collections.Counter[State]:
    """A counter for the state of this.

    Returns:
      a counter containing the number of test of each state.
    """
    return collections.Counter(self.state.values())

  def LogState(self, log_level: int = 1) -> None:
    """Logs the state of the tests.

    This method is typically called after the test has no more undecided
    sub-tests.

    Args:
      log_level: 0: only prints failing values of tests with multiple p-values
                 1: prints a summary for each test
                 2: prints all p-values
    """
    num_tests = len(self.p_values)
    count = self.StateCount()
    if num_tests == 1:
      state = self.FormatPValue(list(self.p_values)[0])
    elif count[State.FAILED] == 0:
      state = f"passed: {count[State.PASSED]}"
    else:
      state = f"failed: {count[State.FAILED]}/{num_tests}"
    if count[State.UNDECIDED]:
      state += f"inconclusive: {count[State.UNDECIDED]}"
    if count[State.FAILED] or log_level >= 1:
      logging.info("%-30s %-22s    (%4.2fs)", self.test_name, state,
                   self.runtime)
    if num_tests > 1:
      for name, state in self.state.items():
        if state != State.PASSED or log_level >= 2:
          logging.info("  %-28s %s", name, self.FormatPValue(name))
          pvs = self.p_values[name]
          if len(pvs) > 1:
            avg = sum(pvs) / len(pvs)
            logging.info("      individual tests:[%s] avg:%s",
                         ", ".join(format(pv, "g") for pv in pvs), avg)

  def Failed(self) -> bool:
    """Determines if the any of the tests failed.

    Returns:
      True, if an test failed.
    """
    return any(state == State.FAILED for state in self.state.values())


def LogTotal(tests: list[TestStructure]) -> None:
  """Logs the total number tests in each state (passed, undecided, failed).

  Args:
    tests: a list of test structures
  """
  total = collections.Counter()
  for test in tests:
    total += test.StateCount()
  num_total_tests = sum(total.values())
  for state in State:
    if total[state]:
      logging.info("%-10s: %d/%d", state.name.lower(), total[state],
                   num_total_tests)


def TestSource(source_name: str,
               source: Source,
               n: int,
               significance_level_repeat: float,
               significance_level_fail: float,
               test_prefix: Optional[str] = None,
               log_level: int = 1,
               min_repetitions: int = 1) -> bool:
  """Tests random bit generator.

  Args:
    source_name: describes the source of the random bits.
    source: a pseudorandom generator
    n: the length of the bit string.
    significance_level_repeat: a p-value for which the test is repeated.
    significance_level_fail: a p-value lower than this value fails the test.
    test_prefix: only runs tests that start with test_prefix. If this value is
      None then all suitable tests are run.
    log_level: 0: only prints failing values of tests with multiple p-values
               1: prints a summary for each test
               2: prints all p-values
    min_repetitions: minimal number of repetitions

  Returns:
    False, if any of the tests fail.
  """

  if source_name:
    logging.info("-------- Testing: %s --------", source_name)
  if log_level >= 1:
    logging.info("number of bits: %d", n)
  start_total = time.time()

  tests = []
  for test, params in TESTS:
    if not test_prefix or test.__name__.startswith(test_prefix):
      tests.append(
          TestStructure(
              test,
              params,
              significance_level_fail,
              significance_level_repeat,
              min_repetitions=min_repetitions))

  if not tests:
    logging.info("no tests specified")
    return

  undecided = len(tests)
  while undecided:
    bits = source(n)
    undecided = 0
    for test_struct in tests:
      if test_struct.finished:
        continue
      if test_struct.Run(bits, n):
        test_struct.LogState(log_level)
      else:
        undecided += 1
  LogTotal(tests)
  if log_level >= 1:
    logging.info("total time: %4.2fs", time.time() - start_total)
  return any(test.Failed() for test in tests)


def TestBitString(source_name: str,
                  bits: int,
                  n: int,
                  significance_level: float,
                  test_prefix: Optional[str] = None,
                  log_level: int = 1) -> bool:
  """Runs all tests on a long consecutive output of a random bit generator.

  Args:
    source_name: describes the source of the random bits.
    bits: the bit string to test.
    n: the length of the bit string.
    significance_level: a p-value lower than this value fails the test.
    test_prefix: only runs tests that start with test_prefix. If this value is
      None then all suitable tests are run.
    log_level: 0: only prints failing values of tests with multiple p-values
               1: prints a summary for each test
               2: prints all p-values

  Returns:
    False, if any of the tests fail.
  """
  if source_name:
    logging.info("-------- Testing: %s --------", source_name)
  if log_level >= 1:
    logging.info("number of bits: %d", n)
  start_total = time.time()

  tests = []
  for test, params in TESTS:
    if not test_prefix or test.__name__.startswith(test_prefix):
      tests.append(
          TestStructure(test, params, significance_level, significance_level))

  for test_struct in tests:
    test_struct.Run(bits, n)
    test_struct.LogState(log_level)
  LogTotal(tests)
  if log_level >= 1:
    logging.info("total time: %4.2fs", time.time() - start_total)
  return any(test.Failed() for test in tests)
