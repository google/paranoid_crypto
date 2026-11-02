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
"""Polynomial utility functions over Z[x] using SymPy and fpylll LLL."""

import collections
from collections.abc import Sequence
import itertools
import math
from typing import Any, Optional
import gmpy2 as gmpy
from paranoid_crypto.lib import lll
from sympy.polys import densearith
from sympy.polys import densebasic
from sympy.polys import densetools
from sympy.polys import domains
from sympy.polys import factortools
from sympy.polys import galoistools
from sympy.polys import sqfreetools

_ZASSENHAUS_CUTOFF = 6


def eval_poly(coeffs: Sequence[int], x: int) -> int:
  """Evaluates sum(coeffs[i] * x**i) at integer x via Horner's rule."""
  acc = gmpy.mpz(0)
  x_mpz = gmpy.mpz(x)
  for c in reversed(coeffs):
    acc = acc * x_mpz + c
  return int(acc)


def _power_sums_dup_mod(u_dup: list[Any], max_j: int, mod_m: int) -> list[int]:
  """Computes Newton power sums S_1(u), ..., S_max_j(u) mod mod_m."""
  d = len(u_dup) - 1
  psums = [0] * (max_j + 1)
  for j in range(1, max_j + 1):
    acc = int(j * u_dup[j]) if j <= d else 0
    for idx in range(1, min(j, d + 1)):
      acc += int(u_dup[idx]) * psums[j - idx]
    psums[j] = (-acc) % mod_m
  return psums[1:]


def _fujiwara_bound_dup(f_dup: list[Any]) -> int:
  """Upper bound on |lc(f) * alpha| for any complex root alpha of f."""
  d = len(f_dup) - 1
  lc = abs(int(f_dup[0]))
  best = 1
  for k in range(1, d + 1):
    ck = abs(int(f_dup[k]))
    if ck == 0:
      continue
    val = (lc ** (d - 1) * ck + 1) // 2 if k == d else (lc ** (k - 1)) * ck
    root_k, exact = gmpy.iroot(gmpy.mpz(val), k)
    if not exact:
      root_k += 1
    best = max(best, 2 * int(root_k))
  return best


def _prod_monic_mod(
    lifted: list[list[Any]], indices: Sequence[int], pl: Any
) -> list[Any]:
  """Multiplies monic polynomials lifted[i] modulo pl over ZZ."""
  zz = domains.ZZ
  prod = [zz.one]
  for idx in indices:
    prod = densetools.dup_trunc(
        densearith.dup_mul(prod, lifted[idx], zz), pl, zz
    )
    if prod[0] < 0:
      prod[0] += pl
  return prod


def _recombine_blocks(
    g_sqf: list[Any], blocks: list[list[Any]], pl: Any
) -> list[list[Any]]:
  """Recombines monic mod-pl factor blocks into irreducible Z[x] factors."""
  zz = domains.ZZ
  factors: list[list[Any]] = []
  f_cur = g_sqf
  active = list(range(len(blocks)))
  pl_int = int(pl)
  half_pl = pl_int >> 1
  const_terms = [int(densebasic.dup_TC(blk, zz)) % pl_int for blk in blocks]
  s = 1

  while 2 * s <= len(active):
    if s >= 2 and len(active) > 10:
      break
    b_cur = densebasic.dup_LC(f_cur, zz)
    b_int = int(b_cur)
    bfc = b_int * int(densebasic.dup_TC(f_cur, zz))
    found = False
    combos: Any = itertools.combinations(active, s)
    if 2 * s == len(active):
      combos = (
          (active[0],) + rest
          for rest in itertools.combinations(active[1:], s - 1)
      )
    for subset in combos:
      q0 = b_int
      for idx in subset:
        q0 = (q0 * const_terms[idx]) % pl_int
      if q0 > half_pl:
        q0 -= pl_int
      if q0 == 0 or bfc % q0 != 0:
        continue
      cand = [b_cur]
      for idx in subset:
        cand = densetools.dup_trunc(
            densearith.dup_mul(cand, blocks[idx], zz), pl, zz
        )
      _, cand_prim = densetools.dup_primitive(cand, zz)
      if densebasic.dup_LC(cand_prim, zz) < 0:
        cand_prim = densearith.dup_neg(cand_prim, zz)
      quo, rem = densearith.dup_div(f_cur, cand_prim, zz)
      if not rem:
        factors.append(cand_prim)
        f_cur = quo
        subset_set = set(subset)
        active = [idx for idx in active if idx not in subset_set]
        found = True
        break
    if not found:
      s += 1

  factors.append(f_cur)
  return factors


def _factor_sqf_primitive(
    g_sqf: list[Any], max_modular_factors: int
) -> Optional[list[list[Any]]]:
  """Factors a primitive square-free dup polynomial over ZZ."""
  if len(g_sqf) <= 2:
    return [g_sqf]
  zz = domains.ZZ
  cyc = factortools.dup_zz_cyclotomic_factor(g_sqf, zz)
  if cyc is not None:
    return cyc

  deg = len(g_sqf) - 1
  lc = densebasic.dup_LC(g_sqf, zz)
  tc = densebasic.dup_TC(g_sqf, zz)
  best_p: Any = None
  best_fsqf: Optional[list[list[Any]]] = None
  best_r = 10**9
  tested = 0
  max_good = 2 if deg >= 64 else 3
  p_cand = 17
  while tested < max_good:
    if lc % p_cand != 0 and tc % p_cand != 0:
      px = zz(p_cand)
      f_modp = galoistools.gf_from_int_poly(g_sqf, px)
      if galoistools.gf_sqf_p(f_modp, px, zz):
        _, fsqf = galoistools.gf_factor_sqf(f_modp, px, zz)
        r = len(fsqf)
        if r <= 1:
          return [g_sqf]
        if r < best_r:
          best_r, best_p, best_fsqf = r, px, fsqf
          if r <= 4 or (deg >= 96 and r <= _ZASSENHAUS_CUTOFF):
            break
        tested += 1
    p_cand = int(gmpy.next_prime(p_cand))

  if best_fsqf is None or best_r > max_modular_factors:
    return None

  modular = [galoistools.gf_to_int_poly(ff, best_p) for ff in best_fsqf]
  mig_bound = int(factortools.dup_zz_mignotte_bound(g_sqf, zz))
  base_min_m = 2 * abs(int(lc)) * mig_bound + 2
  r = best_r

  if r <= _ZASSENHAUS_CUTOFF:
    l_exp = int(math.ceil(math.log(base_min_m, int(best_p))))
    pl = best_p**l_exp
    lifted = factortools.dup_zz_hensel_lift(best_p, g_sqf, modular, l_exp, zz)
    return _recombine_blocks(g_sqf, lifted, pl)

  t = min(max(3, (r + 2) // 3), 6)
  d_lat = r + t
  scale_bits = max(64, (4 * d_lat * d_lat) // (5 * t) + (8 * d_lat) // t + 16)
  two_l = 1 << scale_bits
  fujiwara = _fujiwara_bound_dup(g_sqf)
  b_bounds = [deg * (fujiwara**j) + 1 for j in range(1, t + 1)]
  min_m = max(base_min_m, two_l * b_bounds[-1])
  l_exp = int(math.ceil(math.log(min_m + 1, int(best_p))))
  pl = best_p**l_exp
  mod_m = int(pl)

  lifted = factortools.dup_zz_hensel_lift(best_p, g_sqf, modular, l_exp, zz)

  half_m = mod_m >> 1
  lc_int = int(lc)
  lc_pows = [pow(lc_int, j, mod_m) for j in range(1, t + 1)]
  taus = [[0] * t for _ in range(r)]
  weight_c = r // 2 + 2
  lat = [[0] * d_lat for _ in range(d_lat)]
  for i in range(r):
    lat[i][i] = weight_c
    psums = _power_sums_dup_mod(lifted[i], t, mod_m)
    for j in range(t):
      tau_ij = (lc_pows[j] * psums[j]) % mod_m
      taus[i][j] = tau_ij
      lat[i][r + j] = ((tau_ij << scale_bits) + half_m) // mod_m
  for j in range(t):
    lat[r + j][r + j] = two_l

  reduced = lll.reduce(lat)
  short_rows = []
  for row in reduced:
    if any(row[i] % weight_c != 0 for i in range(r)):
      continue
    u = [row[i] // weight_c for i in range(r)]
    u_max = max(abs(v) for v in u)
    if u_max == 0:
      continue
    ok = True
    for j in range(t):
      rem = sum(u[i] * taus[i][j] for i in range(r)) % mod_m
      if rem > half_m:
        rem -= mod_m
      if abs(rem) > u_max * b_bounds[j]:
        ok = False
        break
    if ok:
      short_rows.append(u)

  if not short_rows:
    return [g_sqf]

  groups = collections.defaultdict(list)
  for i in range(r):
    groups[tuple(sr[i] for sr in short_rows)].append(i)
  group_list = list(groups.values())
  if len(group_list) < 2:
    return [g_sqf]

  blocks = [_prod_monic_mod(lifted, grp, pl) for grp in group_list]
  return _recombine_blocks(g_sqf, blocks, pl)


def factor_zz_poly(
    coeffs: Sequence[int], max_modular_factors: int = 32
) -> Optional[tuple[int, list[tuple[list[int], int]]]]:
  """Factors a univariate integer polynomial sum(coeffs[i] * x**i) over Z[x].

  Uses SymPy for square-free decomposition, finite-field factorization, and
  quadratic Hensel lifting, combined with van Hoeij's truncated-trace fpylll LLL
  recombination when the modular factor count exceeds _ZASSENHAUS_CUTOFF.

  Args:
    coeffs: Polynomial coefficients [c_0, c_1, ..., c_d] (low-to-high degree).
    max_modular_factors: Maximum F_p factor count r to attempt recombining.

  Returns:
    Tuple (content, [(factor_coeffs, multiplicity), ...]) where each factor is
    primitive with positive leading coefficient in low-to-high order, or None
    if the modular factor count exceeds max_modular_factors.
  """
  hi = len(coeffs) - 1
  while hi >= 0 and coeffs[hi] == 0:
    hi -= 1
  if hi < 0:
    return 0, []

  lo = 0
  while lo <= hi and coeffs[lo] == 0:
    lo += 1
  if lo == hi:
    factors: list[tuple[list[int], int]] = []
    if lo > 0:
      factors.append(([0, 1], lo))
    return int(coeffs[lo]), factors

  zz = domains.ZZ
  f_dup = [zz(c) for c in reversed(coeffs[lo : hi + 1])]
  cont, g = densetools.dup_primitive(f_dup, zz)
  if densebasic.dup_LC(g, zz) < 0:
    cont = -cont
    g = densearith.dup_neg(g, zz)

  g_sqf = sqfreetools.dup_sqf_part(g, zz)
  if densebasic.dup_LC(g_sqf, zz) < 0:
    g_sqf = densearith.dup_neg(g_sqf, zz)

  irred_dups = _factor_sqf_primitive(g_sqf, max_modular_factors)
  if irred_dups is None:
    return None

  dup_with_mult = factortools.dup_trial_division(g, irred_dups, zz)
  result: list[tuple[list[int], int]] = []
  if lo > 0:
    result.append(([0, 1], lo))
  for fac_dup, mult in dup_with_mult:
    result.append(([int(c) for c in reversed(fac_dup)], int(mult)))
  result.sort(key=lambda item: (len(item[0]), item[0]))
  return int(cont), result
