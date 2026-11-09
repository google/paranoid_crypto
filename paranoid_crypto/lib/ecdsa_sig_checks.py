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

from __future__ import annotations

import array
import bisect
import collections
from typing import Optional
from absl import logging
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import base_check
from paranoid_crypto.lib import consts
from paranoid_crypto.lib import cr50_u2f_weakness
from paranoid_crypto.lib import ec_single_checks
from paranoid_crypto.lib import ec_util
from paranoid_crypto.lib import hidden_number_problem as hnp
from paranoid_crypto.lib import lcg_constants
from paranoid_crypto.lib import paranoid
from paranoid_crypto.lib import util
from paranoid_crypto.lib.data import debian_openssl_generator
from paranoid_crypto.lib.data import storage


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
        # Exclude duplicate and degenerate (r == 0 or s == 0 mod n) signatures
        # from the actual processing while preserving signature order for
        # sliding-window checks.
        vals = (
            ec_util.ECDSAValues(sigs[idx].ecdsa_sig_info, curve)
            for idx in idxs
        )
        unique_vals = list(
            dict.fromkeys(
                (r, s, z)
                for r, s, z in vals
                if r % curve.n != 0 and s % curve.n != 0
            )
        )
        if not unique_vals:
          continue
        a, b = [0] * len(unique_vals), [0] * len(unique_vals)
        seen_r: dict[int, tuple[int, int]] = {}
        for i in range(len(unique_vals)):
          r, s, z = unique_vals[i]
          ai, bi = curve.HiddenNumberParams(r, s, z)
          a[i], b[i] = ai, bi
          r_mod = int(r % curve.n)
          if r_mod in seen_r:
            a0, b0 = seen_r[r_mod]
            for da, db in ((ai - a0, bi - b0), (ai + a0, bi + b0)):
              db_mod = db % curve.n
              if db_mod != 0:
                guesses.add(
                    int((-da * ec_util.gmpy.invert(db_mod, curve.n)) % curve.n)
                )
          else:
            seen_r[r_mod] = (ai, bi)
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
                  hnp.HiddenNumberProblem(a[i:i + size], b[i:i + size], None,  # pyrefly: ignore[bad-argument-type]
                                          curve.n, self.bias))
            if len(a) <= size:
              # Tests with a larger window are not leading to additional tests.
              break
          if len(a) < 8 and self.bias != hnp.Bias.GENERALIZED:
            # Also test assuming the private key was generated with the same
            # biased RNG as the signature nonces (analogous to INCLUDE_KEY).
            guesses.update(
                hnp.HiddenNumberProblem(
                    a + [0], b + [1], None, curve.n, self.bias  # pyrefly: ignore[bad-argument-type]
                )
            )
        elif self.lcg_params:
          guesses.update(
              hnp.HiddenNumberProblemForCurve(a, b, curve_id,  # pyrefly: ignore[bad-argument-type]
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
        test_result.severity = util.GetHighestSeverity(key.test_info)  # pyrefly: ignore[bad-assignment]
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
        # Exclude duplicate and degenerate (r == 0 or s == 0 mod n) signatures
        # from the actual processing while preserving signature order for the
        # sliding window.
        vals = (
            ec_util.ECDSAValues(sigs[idx].ecdsa_sig_info, curve)
            for idx in idxs
        )
        unique_vals = list(
            dict.fromkeys(
                (r, s, z)
                for r, s, z in vals
                if r % curve.n != 0 and s % curve.n != 0
            )
        )
        # Sliding window. Two signatures are enough to detect this vulnerability
        for i in range(len(unique_vals) - 1):
          r1, s1, z1 = unique_vals[i]
          r2, s2, z2 = unique_vals[i + 1]
          guesses.update(
              cr50_u2f_weakness.Cr50U2fGuesses(r1, s1, z1, r2, s2, z2, curve.n))
        # Also test individual signatures, assuming also a weak private key
        for r1, s1, z1 in unique_vals:
          guesses.update(
              cr50_u2f_weakness.Cr50U2fGuesses(r1, s1, z1, 1, 1, 0, curve.n)
          )
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


def _RecoverIssuerKeyFromVerifiedNonce(
    curve: ec_util.EcCurve,
    issuer_point: tuple[int, int],
    sig_info: paranoid_pb2.ECDSASignatureInfo,
    r_mod: int,
    k: int,
) -> Optional[int]:
  """Recovers the issuer private key d once (k * G)_x % n == r_mod holds.

  Args:
    curve: Elliptic curve of the signature.
    issuer_point: Affine (x, y) public key point of the issuer.
    sig_info: ECDSASignatureInfo protobuf of the signature.
    r_mod: Non-zero r component reduced modulo curve.n.
    k: Candidate nonce in [1, curve.n - 1] whose x-coordinate matches r_mod.

  Returns:
    The verified private scalar d in [1, curve.n - 1] satisfying
    d * G == issuer_point, or None if the signature was not produced with +-k
    under issuer_point.
  """
  _, s, z = ec_util.ECDSAValues(sig_info, curve)
  n_int = int(curve.n)
  s_mod = int(s % curve.n)
  if s_mod == 0:
    return None
  r_inv = int(ec_util.gmpy.invert(r_mod, curve.n))
  sk = (s_mod * k) % n_int
  z_vals = [int(z)]
  if len(sig_info.message_hash) * 8 > n_int.bit_length():
    z_untrunc = util.Bytes2Int(sig_info.message_hash) % n_int
    if z_untrunc != z_vals[0]:
      z_vals.append(z_untrunc)
  for z_val in z_vals:
    for num in (sk - z_val, -sk - z_val):
      d_cand = (num * r_inv) % n_int
      if (
          1 <= d_cand < n_int
          and curve.Multiply(curve.g, d_cand) == issuer_point
      ):
        return d_cand
  return None


class CheckOpensslDenylistECDSANonce(base_check.ECDSASignatureCheck):
  """Checks ECDSA signatures for Debian OpenSSL PRNG nonces (CVE-2008-0166).

  Detects ECDSA signatures whose ephemeral signing nonce k (or n - k) was
  generated by Debian or Ubuntu's crippled OpenSSL 0.9.8c-0.9.8g PRNG
  (CVE-2008-0166) in ecdsa_sign_setup, even when the issuer's long-term key pair
  is strong and unaffected (which CheckIssuerKey cannot detect).

  Reuses the precomputed sorted 32-bit x-coordinate suffix tables from
  CheckOpensslDenylistEC. On any 32-bit suffix match of r (or r + n when
  r < p - n), reconstructs k via debian_openssl_generator, verifies
  (k * G)_x % n == r, solves d = (+-s * k - z) * r^(-1) mod n, and verifies
  d * G == Q to recover d from a single signature with zero false positives.
  """

  def __init__(self, paranoid_storage: Optional[storage.Storage] = None):
    """CheckOpensslDenylistECDSANonce check constructor.

    Args:
      paranoid_storage: Optional instance of storage.Storage providing
        GetOpensslDenylistEC. When omitted, shares the class-level table cache
        with CheckOpensslDenylistEC.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    if paranoid_storage is None:
      self._custom_tables = None
      self._GetTables()
    else:
      self._custom_tables = ec_single_checks.CheckOpensslDenylistEC.ParseTables(
          paranoid_storage.GetOpensslDenylistEC()
      )

  def _GetTables(
      self,
  ) -> dict[int, tuple[array.array[int], bytes, array.array[int]]]:
    if self._custom_tables is not None:
      return self._custom_tables
    return ec_single_checks.CheckOpensslDenylistEC.GetDefaultTables()

  def Check(self, artifacts: list[paranoid_pb2.ECDSASignature]) -> bool:
    any_weak = False
    tables = self._GetTables()
    for curve_id, curve in ec_util.CURVE_FACTORY.items():
      if curve is None:
        continue
      sigs = [s for s in artifacts if s.issuer_key_info.curve_type == curve_id]
      if not sigs:
        continue
      issuer_dlogs: dict[int, int] = {}
      curve_table = tables.get(curve_id)
      if curve_table is not None:
        xs, meta_hi, meta_lo = curve_table
        n_entries = len(xs)
        if n_entries > 0:
          n_int = int(curve.n)
          p_minus_n = max(0, int(curve.mod) - n_int)
          k_cache: dict[int, tuple[int, int]] = {}
          pks = _MapIssuerSigIndexes(sigs)
          for pk_point, idxs in pks.items():
            recovered_d: Optional[int] = None
            for idx in idxs:
              sig_info = sigs[idx].ecdsa_sig_info
              r_int = util.Bytes2Int(sig_info.r)
              if r_int <= 0:
                continue
              r_mod = r_int if r_int < n_int else r_int % n_int
              if r_mod == 0:
                continue
              x_cands = (
                  (r_mod,) if r_mod >= p_minus_n else (r_mod, r_mod + n_int)
              )
              for x_cand in x_cands:
                x_lsb32 = x_cand & 0xFFFFFFFF
                t_idx = bisect.bisect_left(xs, x_lsb32)
                while t_idx < n_entries and xs[t_idx] == x_lsb32:
                  meta = (meta_hi[t_idx] << 16) | meta_lo[t_idx]
                  cached = k_cache.get(meta)
                  if cached is None:
                    cfg_idx = meta >> 15
                    pid = meta & 0x7FFF
                    k = debian_openssl_generator.generate_ec_private_key(
                        cfg_idx, pid, n_int
                    )
                    kx, _ = curve.Multiply(curve.g, k)
                    kx_mod = -1 if kx is None else int(kx) % n_int
                    cached = (k, kx_mod)
                    k_cache[meta] = cached
                  k, kx_mod = cached
                  if kx_mod == r_mod:
                    recovered_d = _RecoverIssuerKeyFromVerifiedNonce(
                        curve, pk_point, sig_info, r_mod, k
                    )
                    if recovered_d is not None:
                      break
                  t_idx += 1
                if recovered_d is not None:
                  break
              if recovered_d is not None:
                for sig_idx in idxs:
                  issuer_dlogs[sig_idx] = recovered_d
                break
      for i, sig in enumerate(sigs):
        test_result = self._CreateTestResult()
        if i in issuer_dlogs:
          dlog = format(int(issuer_dlogs[i]), "x")
          logging.warning(
              "OpensslDenylistECDSANonce check failed! Issuer dlog found:"
              " %s %s",
              dlog,
              sig.ecdsa_sig_info,
          )
          util.AttachInfo(sig.test_info, consts.INFO_NAME_DISCRETE_LOG, dlog)
          any_weak = True
          test_result.result = True
        util.SetTestResult(sig.test_info, test_result)
    return any_weak


class CheckUnseededRandECDSANonce(base_check.ECDSASignatureCheck):
  """Checks if ECDSA nonces came from unseeded PRNGs or weak/zero seeds.

  Detects ECDSA signatures whose ephemeral signing nonce k (or n - k) was
  produced by unseeded or default-seeded PRNGs (GMP Mersenne Twister and linear
  congruential generators, Go math/rand, C++ std::mt19937 / std::mt19937_64,
  Python random.Random, Java java.util.Random, C glibc/BSD/MSVC rand()) or
  deterministic derivations from all-zero, repeated-byte, sequential-byte,
  small-integer, or common placeholder seeds via SHA-1/256/384/512, SHAKE-256,
  HMAC/HKDF-SHA256, or BIP-32.

  Reuses the precomputed 64-bit x-coordinate suffix hash map from
  CheckUnseededRandEC for O(1) lookup per signature, followed by exact
  verification d * G == Q to recover the issuer private key d from a single
  signature with zero false positives.
  """

  def __init__(self, paranoid_storage: Optional[storage.Storage] = None):
    """CheckUnseededRandECDSANonce check constructor.

    Args:
      paranoid_storage: Optional instance of storage.Storage providing
        GetUnseededRandsEC. When omitted, shares the class-level table cache
        with CheckUnseededRandEC.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    if paranoid_storage is None:
      self._custom_tables = None
      self._GetTables()
    else:
      self._custom_tables = ec_single_checks.CheckUnseededRandEC.ParseTables(
          paranoid_storage.GetUnseededRandsEC()
      )

  def _GetTables(self) -> dict[int, dict[int, bytes]]:
    if self._custom_tables is not None:
      return self._custom_tables
    return ec_single_checks.CheckUnseededRandEC.GetDefaultTables()

  def Check(self, artifacts: list[paranoid_pb2.ECDSASignature]) -> bool:
    any_weak = False
    tables = self._GetTables()
    for curve_id, curve in ec_util.CURVE_FACTORY.items():
      if curve is None:
        continue
      sigs = [s for s in artifacts if s.issuer_key_info.curve_type == curve_id]
      if not sigs:
        continue
      issuer_dlogs: dict[int, int] = {}
      curve_map = tables.get(curve_id)
      if curve_map:
        n_int = int(curve.n)
        p_minus_n = max(0, int(curve.mod) - n_int)
        kx_cache: dict[int, int] = {}
        pks = _MapIssuerSigIndexes(sigs)
        for pk_point, idxs in pks.items():
          recovered_d: Optional[int] = None
          for idx in idxs:
            sig_info = sigs[idx].ecdsa_sig_info
            r_int = util.Bytes2Int(sig_info.r)
            if r_int <= 0:
              continue
            r_mod = r_int if r_int < n_int else r_int % n_int
            if r_mod == 0:
              continue
            x_cands = (
                (r_mod,) if r_mod >= p_minus_n else (r_mod, r_mod + n_int)
            )
            for x_cand in x_cands:
              d_bytes = curve_map.get(x_cand & 0xFFFFFFFFFFFFFFFF)
              if not d_bytes:
                continue
              for k in ec_single_checks.CheckUnseededRandEC.UnpackCandidates(
                  d_bytes, n_int
              ):
                if not (1 <= k < n_int):
                  continue
                kx_mod = kx_cache.get(k)
                if kx_mod is None:
                  pt_x, _ = curve.Multiply(curve.g, k)
                  kx_mod = -1 if pt_x is None else int(pt_x) % n_int
                  kx_cache[k] = kx_mod
                if kx_mod == r_mod:
                  recovered_d = _RecoverIssuerKeyFromVerifiedNonce(
                      curve, pk_point, sig_info, r_mod, k
                  )
                  if recovered_d is not None:
                    break
              if recovered_d is not None:
                break
            if recovered_d is not None:
              for sig_idx in idxs:
                issuer_dlogs[sig_idx] = recovered_d
              break
      for i, sig in enumerate(sigs):
        test_result = self._CreateTestResult()
        if i in issuer_dlogs:
          dlog = format(int(issuer_dlogs[i]), "x")
          logging.warning(
              "UnseededRandECDSANonce check failed! Issuer dlog found: %s %s",
              dlog,
              sig.ecdsa_sig_info,
          )
          util.AttachInfo(sig.test_info, consts.INFO_NAME_DISCRETE_LOG, dlog)
          any_weak = True
          test_result.result = True
        util.SetTestResult(sig.test_info, test_result)
    return any_weak
