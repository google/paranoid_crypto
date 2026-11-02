# Copyright 2026 Google LLC
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
"""Detects and factors 'Short-Sleeve' RSA moduli via Z[x] polynomial factoring.

Short-sleeve RSA keys arise when big-integer prime generation populates each
w-bit limb with b << w bits of entropy (either unsigned zero-padded limbs or
signed sign-extended limbs, e.g., CompleteFTP CVE-2026-32648 and the patterns
described by Trail of Bits in 'Short-sleeve RSA'). When b is small enough that
limb products do not wrap modulo 2^w after aligning the sleeve boundary, a
shifted multiple 2^sh * n = P(2^w) * Q(2^w) embeds the exact integer polynomial
product P(x) * Q(x) in balanced base 2^w.
"""

from typing import Any, Optional
import gmpy2 as gmpy
from paranoid_crypto.lib import ntheory_util
from paranoid_crypto.lib import poly_util

_LIMB_WIDTHS = (16, 32, 64, 128, 256)
_MASK_W = {w: (gmpy.mpz(1) << w) - 1 for w in _LIMB_WIDTHS}
_MASK_8W = {w: (gmpy.mpz(1) << (8 * w)) - 1 for w in _LIMB_WIDTHS}
_HALF_MASK_W = {w: (1 << (w >> 1)) - 1 for w in _LIMB_WIDTHS}
_MAX_POLY_LIMBS = 256


def _fold_limbs_or(chunk: Any, m_limbs: int, w: int) -> Any:
  """Folds m_limbs w-bit limbs of chunk into 1 w-bit mask in O(log m) shifts."""
  k = 1 << (m_limbs.bit_length() - 1)
  if m_limbs > k:
    chunk |= chunk >> ((m_limbs - k) * w)
  while k > 1:
    k >>= 1
    chunk |= chunk >> (k * w)
  return chunk & _MASK_W[w]


def _has_one_run(z_circ: Any, min_run: int) -> bool:
  """Returns True iff z_circ contains at least min_run consecutive 1-bits."""
  t = z_circ
  r = 1
  while (r << 1) <= min_run:
    t &= t >> r
    if not t:
      return False
    r <<= 1
  if r < min_run:
    t &= t >> (min_run - r)
  return bool(t)


def _primitive_poly(coeffs: list[int]) -> Optional[tuple[int, ...]]:
  """Strips x^k valuation and integer content so f(0) != 0 and lc(f) > 0."""
  lo = 0
  while lo < len(coeffs) and coeffs[lo] == 0:
    lo += 1
  f = coeffs[lo:]
  if len(f) - 1 < 2:
    return None
  content = 0
  for c in f:
    content = int(gmpy.gcd(content, abs(c)))
    if content == 1:
      break
  if content > 1:
    f = [c // content for c in f]
  if f[-1] < 0:
    f = [-c for c in f]
  return tuple(f)


def factor_short_sleeve(n: int) -> Optional[list[int]]:
  """Attempts to factor a Short-Sleeve RSA modulus n = p * q.

  First applies a fast O(log m) bitwise limb-transition filter on n ^ (n >> 1)
  across limb widths w in (16, 32, 64, 128, 256) to detect shared runs of
  identical bits (either 00...0 or signed 11...1 sign-extension) across the
  limbs of n. Normal random RSA moduli are rejected in ~6 microseconds with
  negligible (~2^-36) false-trigger probability.

  When a limb-aligned transition sleeve is detected, extracts the balanced
  base-2^w polynomial representation of 2^sh * n via ntheory_util.BalancedDigits
  and factors it over Z[x] via poly_util.factor_zz_poly.

  Args:
    n: RSA modulus to test and factor.

  Returns:
    Sorted list [p, q] of two non-trivial factors of n if factored, else None.
  """
  n_mpz = gmpy.mpz(n)
  nbits = n_mpz.bit_length()
  if nbits < 128 or not (n_mpz & 1):
    return None

  x = n_mpz ^ (n_mpz >> 1)
  prev_tested = False

  for w in _LIMB_WIDTHS:
    total_limbs = (nbits - 1) // w + 1
    if total_limbs < 6 or total_limbs > _MAX_POLY_LIMBS:
      prev_tested = False
      continue
    mask_w = _MASK_W[w]

    if total_limbs >= 20:
      lo1 = 2
      lo2 = total_limbs // 2 + 1
      m8_mask = _MASK_8W[w]
      chunk = ((x >> (lo1 * w)) & m8_mask) | ((x >> (lo2 * w)) & m8_mask)
      m_limbs = 16
      folded = _fold_limbs_or(chunk, 8, w)
    else:
      lo = 2 if total_limbs >= 8 else 1
      hi = total_limbs - 2 if total_limbs >= 8 else total_limbs - 1
      m_limbs = hi - lo
      chunk = (x >> (lo * w)) & ((gmpy.mpz(1) << (m_limbs * w)) - 1)
      folded = _fold_limbs_or(chunk, m_limbs, w)

    if folded == mask_w or folded == 0:
      prev_tested = True
      continue

    min_run = max(3, (36 + m_limbs - 1) // m_limbs)
    z = (~folded) & mask_w
    z_w = int(z)
    if prev_tested and (z_w & _HALF_MASK_W[w]) == (z_w >> (w >> 1)):
      continue
    prev_tested = True

    z_circ = z | (z << w)
    if not _has_one_run(z_circ, min_run):
      continue

    z_int = z_w | (z_w << w)
    runs = []
    for i in range(w):
      if ((z_w >> i) & 1) and not ((z_w >> ((i - 1) % w)) & 1):
        j = i
        while j + 1 < 2 * w and ((z_int >> (j + 1)) & 1):
          j += 1
        run_len = j - i + 1
        if run_len >= min_run:
          runs.append((run_len, j))
    if not runs:
      continue
    runs.sort(reverse=True)
    best_run = runs[0][0]
    runs = [r for r in runs if r[0] >= best_run - 2][:2]

    cand_shifts = []
    seen_shifts = set()
    for run_len, j in runs:
      sh = (w - 2 - j) % w
      max_int = min(3 << (w - 3), 1 << max(2, w - max(0, run_len - 7)))
      for delta in (0, 2, 4, 1, -1, 3):
        s_cand = (sh + delta) % w
        if s_cand not in seen_shifts:
          seen_shifts.add(s_cand)
          cand_shifts.append((s_cand, max_int))

    base = 1 << w
    n_int = int(n_mpz)
    seen_polys: set[tuple[int, ...]] = set()
    for sh, max_interior in cand_shifts:
      coeffs = ntheory_util.BalancedDigits(int(n_mpz << sh), w)
      if sum(c != 0 for c in coeffs) * 3 < len(coeffs):
        continue
      if len(coeffs) >= 6:
        if any(abs(c) >= max_interior for c in coeffs[2:-2]):
          continue
      poly_key = _primitive_poly(coeffs)
      if poly_key is None or poly_key in seen_polys:
        continue
      seen_polys.add(poly_key)
      factored = poly_util.factor_zz_poly(poly_key)
      if factored is None:
        continue
      _, factors = factored
      if len(factors) == 1 and factors[0][1] == 1:
        continue
      for fac_coeffs, _ in factors:
        val = poly_util.eval_poly(fac_coeffs, base)
        g = int(gmpy.gcd(abs(val), n_int))
        if 1 < g < n_int:
          return sorted([g, n_int // g])

  return None
