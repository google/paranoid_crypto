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
"""Python library to check public keys/signatures and detect weaknesses.

The library tests the input public keys/signatures (e.g, RSA and ECC) for known
weaknesses. It does pure math verifications and can be used for in a pipeline.
"""
import collections
import enum
import time
from typing import TypeVar
from absl import logging
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import base_check
from paranoid_crypto.lib import ec_aggregate_checks
from paranoid_crypto.lib import ec_single_checks
from paranoid_crypto.lib import ecdsa_sig_checks
from paranoid_crypto.lib import rsa_aggregate_checks
from paranoid_crypto.lib import rsa_single_checks

T = TypeVar("T")

_ACTIVE_EC_SINGLE_CHECKS = (
    ec_single_checks.CheckValidECKey,
    ec_single_checks.CheckWeakCurve,
    ec_single_checks.CheckWeakECPrivateKey,
)

_ACTIVE_EC_AGGREGATE_CHECKS = (ec_aggregate_checks.CheckECKeySmallDifference,)

_ACTIVE_RSA_SINGLE_CHECKS = (
    rsa_single_checks.CheckSizes,
    rsa_single_checks.CheckExponents,
    rsa_single_checks.CheckROCA,
    rsa_single_checks.CheckROCAVariant,
    rsa_single_checks.CheckFermat,
    rsa_single_checks.CheckHighAndLowBitsEqual,
    rsa_single_checks.CheckOpensslDenylist,
    rsa_single_checks.CheckContinuedFractions,
    rsa_single_checks.CheckBitPatterns,
    rsa_single_checks.CheckPermutedBitPatterns,
    rsa_single_checks.CheckPollardpm1,
    rsa_single_checks.CheckLowHammingWeight,
    rsa_single_checks.CheckUnseededRand,
    rsa_single_checks.CheckSmallUpperDifferences,
    rsa_single_checks.CheckKeypairDenylist,
)

_ACTIVE_RSA_AGGREGATE_CHECKS = (
    rsa_aggregate_checks.CheckGCD,
    rsa_aggregate_checks.CheckGCDN1,
)

_ACTIVE_ECDSA_SIG_CHECKS = (
    ecdsa_sig_checks.CheckLCGNonceGMP,
    ecdsa_sig_checks.CheckLCGNonceJavaUtilRandom,
    ecdsa_sig_checks.CheckNonceMSB,
    ecdsa_sig_checks.CheckNonceCommonPrefix,
    ecdsa_sig_checks.CheckNonceCommonPostfix,
    ecdsa_sig_checks.CheckNonceGeneralized,
    ecdsa_sig_checks.CheckIssuerKey,
    ecdsa_sig_checks.CheckCr50U2f,
)

# Keys used in the check dictonary factory:
_RSA_SINGLES = "rsa_singles"
_RSA_AGGREGATES = "rsa_aggregates"
_RSA_ALL = "rsa_all"
_EC_SINGLES = "ec_singles"
_EC_AGGREGATES = "ec_aggregates"
_EC_ALL = "ec_all"
_ECDSA_ALL = "ecdsa_all"

_check_factory = collections.defaultdict(dict)


def GetRSASingleChecks() -> dict[str, base_check.RSAKeyCheck]:
  if not _check_factory[_RSA_SINGLES]:
    for test_class in _ACTIVE_RSA_SINGLE_CHECKS:
      check = test_class()
      _check_factory[_RSA_SINGLES][check.check_name] = check
  return _check_factory[_RSA_SINGLES]


def GetRSAAggregateChecks() -> dict[str, base_check.RSAKeyCheck]:
  if not _check_factory[_RSA_AGGREGATES]:
    for test_class in _ACTIVE_RSA_AGGREGATE_CHECKS:
      check = test_class()
      _check_factory[_RSA_AGGREGATES][check.check_name] = check
  return _check_factory[_RSA_AGGREGATES]


def GetRSAAllChecks() -> dict[str, base_check.RSAKeyCheck]:
  if not _check_factory[_RSA_ALL]:
    _check_factory[_RSA_ALL].update(GetRSASingleChecks())
    _check_factory[_RSA_ALL].update(GetRSAAggregateChecks())
  return _check_factory[_RSA_ALL]


def GetECSingleChecks() -> dict[str, base_check.ECKeyCheck]:
  if not _check_factory[_EC_SINGLES]:
    for test_class in _ACTIVE_EC_SINGLE_CHECKS:
      check = test_class()
      _check_factory[_EC_SINGLES][check.check_name] = check
  return _check_factory[_EC_SINGLES]


def GetECAggregateChecks() -> dict[str, base_check.ECKeyCheck]:
  if not _check_factory[_EC_AGGREGATES]:
    for test_class in _ACTIVE_EC_AGGREGATE_CHECKS:
      check = test_class()
      _check_factory[_EC_AGGREGATES][check.check_name] = check
  return _check_factory[_EC_AGGREGATES]


def GetECAllChecks() -> dict[str, base_check.ECKeyCheck]:
  if not _check_factory[_EC_ALL]:
    _check_factory[_EC_ALL].update(GetECSingleChecks())
    _check_factory[_EC_ALL].update(GetECAggregateChecks())
  return _check_factory[_EC_ALL]


def GetECDSAAllChecks() -> dict[str, base_check.ECDSASignatureCheck]:
  if not _check_factory[_ECDSA_ALL]:
    for test_class in _ACTIVE_ECDSA_SIG_CHECKS:
      check = test_class()
      _check_factory[_ECDSA_ALL][check.check_name] = check
  return _check_factory[_ECDSA_ALL]


class _State(enum.Enum):
  """Defines the state of a check against a group of keys."""
  PASSED = 1
  FAILED = 2


def _CheckArtifacts(artifacts: list[T],
                    check_items: list[tuple[str, base_check.BaseCheck[T]]],
                    log_level: int) -> bool:
  """Generic function for testing artifacts.

  Args:
    artifacts: list of artifacts of the same type (e.g., a list of RSA public
      keys or a list of ECDSA signatures).
    check_items: list of tuples. Each tuple contains the name of the check and a
      BaseCheck instance that contains a Check method.
    log_level: 0: only prints existing logging of the library
               1: prints additional info stats about the checks

  Returns:
    Whether at least one of the artifacts is potentially weak.
  """
  any_weak = False
  start_total = time.time()
  for name, check in check_items:
    start = time.time()
    res = check.Check(artifacts)
    if log_level >= 1:
      state = _State.FAILED.name.lower() if res else _State.PASSED.name.lower()
      logging.info("%-30s %-22s    (%4.2fs)", name, state, time.time() - start)
    any_weak |= res

  if log_level >= 1:
    if any_weak:
      final_state = _State.FAILED.name.lower()
    else:
      final_state = _State.PASSED.name.lower()
    logging.info("final state: %s", final_state)
    logging.info("total time: %4.2fs", time.time() - start_total)
  return any_weak


def CheckAllRSA(rsa_keys: list[paranoid_pb2.RSAKey],
                log_level: int = 0) -> bool:
  """Runs all checks on the RSA input keys.

  Args:
    rsa_keys: RSA public keys. Each public key is a paranoid_pb2.RSAKey protobuf
      with at least the following attributes: rsa_info.n: The RSA modulus;
      rsa_info.e: The RSA exponent.
    log_level: 0: only prints existing logging of the library
               1: prints additional info stats about the checks

  Returns:
    Whether at least one of the keys is potentially weak.
  """
  if log_level >= 1:
    logging.info("-------- Testing %d RSA keys --------", len(rsa_keys))
  return _CheckArtifacts(rsa_keys, list(GetRSAAllChecks().items()), log_level)


def CheckAllEC(ec_keys: list[paranoid_pb2.ECKey], log_level: int = 0) -> bool:
  """Runs all checks on the EC input keys.

  Args:
    ec_keys: A list of EC public keys. Each public key is a paranoid_pb2.ECKey
      protobuf with at least the following attributes: ec_info.curve_type: the
      curve used; ec_info.x: the x-coordinate; ec_info.y: the y-coordinate.
    log_level: 0: only prints existing logging of the library
               1: prints additional info stats about the checks

  Returns:
    Whether at least one of the keys is potentially weak.
  """
  if log_level >= 1:
    logging.info("-------- Testing %d EC keys --------", len(ec_keys))
  return _CheckArtifacts(ec_keys, list(GetECAllChecks().items()), log_level)


def CheckAllECDSASigs(ecdsa_sigs: list[paranoid_pb2.ECDSASignature],
                      log_level: int = 0) -> bool:
  """Runs all checks on the ECDSA signatures.

  Args:
    ecdsa_sigs: A list of ECDSA signatures. Each signature is a
      paranoid_pb2.ECDSASignature protobuf with at least all the attributes of
      ecdsa_sig_info set.
    log_level: 0: only prints existing logging of the library
               1: prints additional info stats about the checks

  Returns:
    Whether at least one of the signatures is potentially weak.
  """
  if log_level >= 1:
    logging.info("-------- Testing %d ECDSA signatures --------",
                 len(ecdsa_sigs))
  return _CheckArtifacts(ecdsa_sigs, list(GetECDSAAllChecks().items()),
                         log_level)
