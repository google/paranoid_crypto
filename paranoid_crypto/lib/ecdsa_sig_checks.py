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
"""Module containing Paranoid checks for ECDSA signatures."""

import collections
from typing import Optional
from absl import logging
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import base_check
from paranoid_crypto.lib import consts
from paranoid_crypto.lib import cr50_u2f_weakness
from paranoid_crypto.lib import ec_util
from paranoid_crypto.lib import hidden_number_problem as hnp
from paranoid_crypto.lib import lcg_constants
from paranoid_crypto.lib import paranoid
from paranoid_crypto.lib import util


def _MapIssuerSigIndexes(
    sigs: list[paranoid_pb2.ECDSASignature]
) -> dict[tuple[int, int], list[int]]:
  """Maps issuer points/public keys into signature indexes."""
  pks = collections.defaultdict(list)
  for i, sig in enumerate(sigs):
    pks[ec_util.PublicPoint(sig.issuer_key_info)].append(i)
  return pks


def _IssuerDLogs(guesses: list[int], pks: dict[tuple[int, int], list[int]],
                 curve: ec_util.EcCurve) -> dict[int, int]:
  """Check which guesses match public key discrete logs on a specific curve.

  Args:
    guesses: list of potential discrete logs
    pks: a dictionary, mapping public key points into signature indexes
    curve: the EC curve

  Returns:
    a dictionary, mapping indexes into discrete logs for the correct guesses.
  """
  issuer_dlogs = {}
  for i, guess_pk in enumerate(curve.BatchMultiplyG(guesses)):
    if guess_pk in pks:
      for idx in pks[guess_pk]:
        issuer_dlogs[idx] = guesses[i]
  return issuer_dlogs


class BiasedBaseCheck(base_check.ECDSASignatureCheck):
  """Base class for checks whether signatures have biased nonces."""

  def __init__(self,
               bias: Optional[hnp.Bias] = None,
               lcg_params: Optional[tuple[lcg_constants.LcgName,
                                          hnp.SearchStrategy]] = None):
    """General construtor for biased nonce checks.

    Args:
      bias: describes the bias of the nonces of signatures that are tested.
      lcg_params: describes the parameters for the LCG checks (lcg type and
        flags).
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    self.bias, self.lcg_params = None, None
    if bias and not lcg_params:
      self.bias = bias
    elif not bias and lcg_params:
      self.lcg_params = lcg_params
    else:
      raise ValueError(
          "Either bias or lcg_params should be defined, but not both.")

  def Check(self, artifacts: list[paranoid_pb2.ECDSASignature]) -> bool:
    any_weak = False
    for curve_id, curve in ec_util.CURVE_FACTORY.items():
      if curve is None:
        continue
      sigs = [s for s in artifacts if s.issuer_key_info.curve_type == curve_id]
      if not sigs:
        continue
      pks = _MapIssuerSigIndexes(sigs)
      guesses = set()
      for _, idxs in pks.items():
        # Exclude duplicate signatures from the actual processing
        unique_vals = list({
            ec_util.ECDSAValues(sigs[idx].ecdsa_sig_info, curve) for idx in idxs
        })
        a, b = [None] * len(unique_vals), [None] * len(unique_vals)
        for i in range(len(unique_vals)):
          r, s, z = unique_vals[i]
          a[i], b[i] = curve.HiddenNumberParams(r, s, z)
        if self.bias:
          # For general biases it makes sense to check with different sizes for
          # the sets of signatures. E.g., 24 to catch simple LCGs, 48 to catch
          # truncated LCGs and large size to catch unknown bugs, biases, subset
          # sums etc.
          # TODO(bleichen): The sizes probably also depend on the curve.
          # Currently we have enough results only for secp256r1.
          for size in (24, 48, 120):
            for i in range(0, len(a), size):
              guesses.update(
                  hnp.HiddenNumberProblem(a[i:i + size], b[i:i + size], None,
                                          curve.n, self.bias))
            if len(a) <= size:
              # Tests with a larger window are not leading to additional tests.
              break
        elif self.lcg_params:
          guesses.update(
              hnp.HiddenNumberProblemForCurve(a, b, curve_id,
                                              self.lcg_params[0],
                                              self.lcg_params[1]))
      issuer_dlogs = _IssuerDLogs(list(guesses), pks, curve)
      # Store the test results
      for i, sig in enumerate(sigs):
        test_result = self._CreateTestResult()
        if i in issuer_dlogs:
          dlog = format(int(issuer_dlogs[i]), "x")
          logging.warning(
              "Check biased nonce %s failed. Issuer dlog found: %s %s",
              self.check_name, dlog, sig.ecdsa_sig_info)
          util.AttachInfo(sig.test_info, consts.INFO_NAME_DISCRETE_LOG, dlog)
          any_weak = True
          test_result.result = True
        util.SetTestResult(sig.test_info, test_result)
    return any_weak


class CheckLCGNonceGMP(BiasedBaseCheck):
  """Checks whether signature nonces were generated by GMP LCG."""

  def __init__(self):
    lcg_params = (
        lcg_constants.LcgName.GMP,
        hnp.SearchStrategy.DEFAULT,
    )
    super().__init__(lcg_params=lcg_params)


class CheckLCGNonceJavaUtilRandom(BiasedBaseCheck):
  """Checks whether signature nonces were generated by JAVA UTIL RANDOM LCG."""

  def __init__(self):
    lcg_params = (
        lcg_constants.LcgName.JAVA_UTIL_RANDOM,
        hnp.SearchStrategy.DEFAULT,
    )
    super().__init__(lcg_params=lcg_params)


class CheckNonceMSB(BiasedBaseCheck):
  """Checks whether signature nonces have most significant bits as 0."""

  def __init__(self):
    super().__init__(bias=hnp.Bias.MSB)


class CheckNonceCommonPrefix(BiasedBaseCheck):
  """Checks whether signature nonces have the same most significant bits."""

  def __init__(self):
    super().__init__(bias=hnp.Bias.COMMON_PREFIX)


class CheckNonceCommonPostfix(BiasedBaseCheck):
  """Checks whether signature nonces have the same least significant bits."""

  def __init__(self):
    super().__init__(bias=hnp.Bias.COMMON_POSTFIX)


class CheckNonceGeneralized(BiasedBaseCheck):
  """Checks a generalized bias method for the signature nonces.

    Checks whether there is an integer m such that the most significant bits of
    m*ki % n are the same, where ki is the signature nonce and n is the curve
    order.
  """

  def __init__(self):
    super().__init__(bias=hnp.Bias.GENERALIZED)


class CheckIssuerKey(base_check.ECDSASignatureCheck):
  """Checks whether the signature issuer public keys are weak.

  Runs all EC key tests against the issuer public keys. For this check we set
  the default severity as UNKNOWN but when a signature has a weak issuer key,
  we assign the same severity of the key check that found the issuer key as
  weak.
  """

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_UNKNOWN)

  def Check(self, artifacts: list[paranoid_pb2.ECDSASignature]) -> bool:
    any_weak = False
    # Maps points/public keys into signature indexes to avoid duplicated keys:
    points = {}
    # Actual ECKey protobufs, so we can provide to paranoid EC key checks:
    pks_pb = []
    for i, sig in enumerate(artifacts):
      point = ec_util.PublicPoint(sig.issuer_key_info)
      if point in points:
        points[point].append(i)
      else:
        points[point] = [i]
        pks_pb.append(paranoid_pb2.ECKey(ec_info=sig.issuer_key_info))

    # Test the keys. Results will be stored in the test_info protobuf field.
    paranoid.CheckAllEC(pks_pb)

    # Maps the keys back into the signatures, so we can set the test result.
    for key in pks_pb:
      test_result = self._CreateTestResult()
      if key.test_info.weak:
        logging.warning("Weak issuer public key: %s", key)
        any_weak = True
        test_result.result = True
        test_result.severity = util.GetHighestSeverity(key.test_info)
      for i in points[ec_util.PublicPoint(key.ec_info)]:
        util.SetTestResult(artifacts[i].test_info, test_result)
    return any_weak


class CheckCr50U2f(base_check.ECDSASignatureCheck):
  """Checks whether the signatures use weak nonces like in the CR50 U2F flaw."""

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)

  def Check(self, artifacts: list[paranoid_pb2.ECDSASignature]) -> bool:
    any_weak = False
    for curve_id, curve in ec_util.CURVE_FACTORY.items():
      if curve is None:
        continue
      sigs = [s for s in artifacts if s.issuer_key_info.curve_type == curve_id]
      if not sigs:
        continue
      pks = _MapIssuerSigIndexes(sigs)
      guesses = set()
      for _, idxs in pks.items():
        # Exclude duplicate signatures from the actual processing
        unique_vals = list({
            ec_util.ECDSAValues(sigs[idx].ecdsa_sig_info, curve) for idx in idxs
        })
        # Sliding window. Two signatures are enough to detect this vulnerability
        for i in range(len(unique_vals) - 1):
          r1, s1, z1 = unique_vals[i]
          r2, s2, z2 = unique_vals[i + 1]
          guesses.update(
              cr50_u2f_weakness.Cr50U2fGuesses(r1, s1, z1, r2, s2, z2, curve.n))
        # Also test a single/last signature, assuming also weak private key
        r1, s1, z1 = unique_vals[-1]
        guesses.update(
            cr50_u2f_weakness.Cr50U2fGuesses(r1, s1, z1, 1, 1, 0, curve.n))
      issuer_dlogs = _IssuerDLogs(list(guesses), pks, curve)
      # Store the test results
      for i, sig in enumerate(sigs):
        test_result = self._CreateTestResult()
        if i in issuer_dlogs:
          dlog = format(int(issuer_dlogs[i]), "x")
          logging.warning("Check Cr50 U2f failed. Issuer dlog found: %s %s",
                          dlog, sig.ecdsa_sig_info)
          util.AttachInfo(sig.test_info, consts.INFO_NAME_DISCRETE_LOG, dlog)
          any_weak = True
          test_result.result = True
        util.SetTestResult(sig.test_info, test_result)
    return any_weak
