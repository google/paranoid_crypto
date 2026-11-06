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
"""Module containing Paranoid checks on group of RSA keys by aggregation."""

import abc
from absl import logging
import gmpy2 as gmpy
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import base_check
from paranoid_crypto.lib import consts
from paranoid_crypto.lib import util
from paranoid_crypto.lib.cc_util.pybind import rsa_batch

_MODULUS_INGEST_CHUNK = 65536


class _RSABatchGCDCheck(base_check.RSAKeyCheck):
  """Base class for C++-accelerated aggregate RSA batch-GCD checks."""

  @property
  @abc.abstractmethod
  def _subtract_one(self) -> bool:
    """Whether to compute GCD over `n - 1` instead of `n`."""

  @property
  @abc.abstractmethod
  def _min_gcd_bytes(self) -> bytes:
    """Big-endian unsigned lower bound for flagging a GCD hit."""

  @abc.abstractmethod
  def _RecordWeakKey(self, key: paranoid_pb2.RSAKey, gcd_val: int) -> None:
    """Logs and attaches factor metadata for a flagged weak RSA key."""

  def Check(self, artifacts: list[paranoid_pb2.RSAKey]) -> bool:
    if not artifacts:
      return False

    acc = rsa_batch.RsaBatchAccumulator()
    first_limb_bytes = (len(artifacts[0].rsa_info.n) + 7) & ~7
    expected_limb_bytes = (
        len(artifacts) * first_limb_bytes if first_limb_bytes <= 2048 else 0
    )
    acc.Reserve(len(artifacts), expected_limb_bytes)
    sub_one = self._subtract_one
    for start in range(0, len(artifacts), _MODULUS_INGEST_CHUNK):
      chunk = [
          key.rsa_info.n
          for key in artifacts[start : start + _MODULUS_INGEST_CHUNK]
      ]
      acc.AddModulusBatch(chunk, sub_one)

    hits = acc.ComputeFilteredGcds(self._min_gcd_bytes)
    del acc

    weak_gcds = {
        idx: gmpy.mpz(int.from_bytes(gcd_be, "big")) for idx, gcd_be in hits
    }
    any_weak = bool(weak_gcds)
    passed_result = self._CreateTestResult()
    if not any_weak:
      for key in artifacts:
        util.SetTestResult(key.test_info, passed_result)
      return False

    for i, key in enumerate(artifacts):
      gcd_val = weak_gcds.get(i)
      if gcd_val is not None:
        self._RecordWeakKey(key, gcd_val)
        weak_result = self._CreateTestResult()
        weak_result.result = True
        util.SetTestResult(key.test_info, weak_result)
      else:
        util.SetTestResult(key.test_info, passed_result)
    return True


class CheckGCD(_RSABatchGCDCheck):
  """Runs GCD checks among artifacts."""

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)

  @property
  def _subtract_one(self) -> bool:
    return False

  @property
  def _min_gcd_bytes(self) -> bytes:
    return b"\x02"

  def _RecordWeakKey(self, key: paranoid_pb2.RSAKey, gcd_val: int) -> None:
    logging.warning("GCD check failed! GCD: %x\n%s", gcd_val, key.rsa_info)
    factors = [gcd_val, gmpy.mpz(util.Bytes2Int(key.rsa_info.n)) // gcd_val]
    util.AttachFactors(key.test_info, consts.INFO_NAME_N_FACTORS, factors)


class CheckGCDN1(_RSABatchGCDCheck):
  """Runs GCD n-1 checks among artifacts.

  This test finds pairs of key with moduli n1 and n2 that have the property
  that GCD(n1 - 1, n2 - 1) >= gcd_bound. The test is heuristic. By itself
  it does not lead to a factorization of the key. It merely finds unusual
  patterns, that indicate a non-random key generation. But further analysis
  is necessary to determine if the non-random pattern is a vulnerability.

  The motivation for this test are as follows:
  (1) it has a non-negligible chance to detect ROCA keys as well as
      keys generated with similar failures (e.g. it does not depend on the
      generator). The ROCA test below detects ROCA keys reliably, but
      would fail when the implementation is modified.
  (2) Provable prime numbers p can be constructed by recursively
      constructing the factors of p-1. If these factors were reused then
      the test might catch this.
  (3) Strong prime number are primes p, where among other properties p - 1
      has a large prime divisor q. If these prime factors are reused then
      the test might catch this.

  The test requires a parameter gcd_bound. This bound should be chosen such
  that the probability of a false positve is small. Rough estimates and
  experiments suggest that this bound should be around 2**128.

  If two integers x and y are chosen uniformly at random in a range 1 .. m
  then then their GCD is larger than k with a probability <= 1 / k.
  While the values n-1 are a bit biased (e.g. they are always even), the
  actual probability of a large GCD shouldn't deviate from the probability
  above by more than a small constant. Hence it would be an unexpected event
  to see two keys n1, n2 with GCD(n1-1, n2-2) > 2^72. Similarly, if a GCD
  computed here had a prime factor > 2^72 the this would be unexpected and
  possibly point to a large bias in the prime number generation.
  """

  def __init__(self, gcd_bound: int = 2**128):
    """CheckGCDN1 check constructor.

    Args:
      gcd_bound: A lower bound for a GCD n-1 that is considered suspicious. This
        bound should be chosen so that false postives are unlikely.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_UNKNOWN)
    self._gcd_bound = gcd_bound

  @property
  def _subtract_one(self) -> bool:
    return True

  @property
  def _min_gcd_bytes(self) -> bytes:
    if self._gcd_bound <= 0:
      return b""
    return util.Int2Bytes(self._gcd_bound)

  def _RecordWeakKey(self, key: paranoid_pb2.RSAKey, gcd_val: int) -> None:
    logging.warning("GCD N-1 check failed! GCD: %x\n%s", gcd_val, key.rsa_info)
    util.AttachFactors(key.test_info, consts.INFO_NAME_NM1_FACTORS, [gcd_val])
