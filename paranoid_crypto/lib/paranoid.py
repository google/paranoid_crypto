"""Python library to check public keys/signatures and detect weaknesses.

The library tests the input public keys/signatures (e.g, RSA and ECC) for known
weaknesses. It does pure math verifications and can be used for in a pipeline.
"""
import collections
from typing import List, Dict
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import base_check
from paranoid_crypto.lib import ec_aggregate_checks
from paranoid_crypto.lib import ec_single_checks
from paranoid_crypto.lib import ecdsa_sig_checks
from paranoid_crypto.lib import rsa_aggregate_checks
from paranoid_crypto.lib import rsa_single_checks

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


def GetRSASingleChecks() -> Dict[str, base_check.BaseCheck]:
  if not _check_factory[_RSA_SINGLES]:
    for test_class in _ACTIVE_RSA_SINGLE_CHECKS:
      check = test_class()
      _check_factory[_RSA_SINGLES][check.check_name] = check
  return _check_factory[_RSA_SINGLES]


def GetRSAAggregateChecks() -> Dict[str, base_check.BaseCheck]:
  if not _check_factory[_RSA_AGGREGATES]:
    for test_class in _ACTIVE_RSA_AGGREGATE_CHECKS:
      check = test_class()
      _check_factory[_RSA_AGGREGATES][check.check_name] = check
  return _check_factory[_RSA_AGGREGATES]


def GetRSAAllChecks() -> Dict[str, base_check.BaseCheck]:
  if not _check_factory[_RSA_ALL]:
    _check_factory[_RSA_ALL].update(GetRSASingleChecks())
    _check_factory[_RSA_ALL].update(GetRSAAggregateChecks())
  return _check_factory[_RSA_ALL]


def GetECSingleChecks() -> Dict[str, base_check.BaseCheck]:
  if not _check_factory[_EC_SINGLES]:
    for test_class in _ACTIVE_EC_SINGLE_CHECKS:
      check = test_class()
      _check_factory[_EC_SINGLES][check.check_name] = check
  return _check_factory[_EC_SINGLES]


def GetECAggregateChecks() -> Dict[str, base_check.BaseCheck]:
  if not _check_factory[_EC_AGGREGATES]:
    for test_class in _ACTIVE_EC_AGGREGATE_CHECKS:
      check = test_class()
      _check_factory[_EC_AGGREGATES][check.check_name] = check
  return _check_factory[_EC_AGGREGATES]


def GetECAllChecks() -> Dict[str, base_check.BaseCheck]:
  if not _check_factory[_EC_ALL]:
    _check_factory[_EC_ALL].update(GetECSingleChecks())
    _check_factory[_EC_ALL].update(GetECAggregateChecks())
  return _check_factory[_EC_ALL]


def GetECDSAAllChecks() -> Dict[str, base_check.BaseCheck]:
  if not _check_factory[_ECDSA_ALL]:
    for test_class in _ACTIVE_ECDSA_SIG_CHECKS:
      check = test_class()
      _check_factory[_ECDSA_ALL][check.check_name] = check
  return _check_factory[_ECDSA_ALL]


def CheckAllRSA(rsa_keys: List[paranoid_pb2.RSAKey]) -> bool:
  """Runs all checks on the RSA input keys.

  Args:
    rsa_keys: RSA public keys. Each public key is a paranoid_pb2.RSAKey protobuf
      with at least the following attributes: rsa_info.n: The RSA modulus;
      rsa_info.e: The RSA exponent.

  Returns:
    Whether at least one of the keys is weak.
  """
  any_weak = False
  for _, check in GetRSAAllChecks().items():
    any_weak |= check.Check(rsa_keys)
  return any_weak


def CheckAllEC(ec_keys: List[paranoid_pb2.ECKey]) -> bool:
  """Runs all checks on the EC input keys.

  Args:
    ec_keys: A list of EC public keys. Each public key is a paranoid_pb2.ECKey
      protobuf with at least the following attributes: ec_info.curve_type: the
      curve used; ec_info.x: the x-coordinate; ec_info.y: the y-coordinate.

  Returns:
    Whether at least one of the keys is weak.
  """
  any_weak = False
  for _, check in GetECAllChecks().items():
    any_weak |= check.Check(ec_keys)
  return any_weak


def CheckAllECDSASigs(ecdsa_sigs: List[paranoid_pb2.ECDSASignature]) -> bool:
  """Runs all checks on the ECDSA signatures.

  Args:
    ecdsa_sigs: A list of ECDSA signatures. Each signature is a
      paranoid_pb2.ECDSASignature protobuf with at least all the attributes of
      ecdsa_sig_info set.

  Returns:
    Whether at least one of the signatures is weak.
  """
  any_weak = False
  for _, check in GetECDSAAllChecks().items():
    any_weak |= check.Check(ecdsa_sigs)
  return any_weak
