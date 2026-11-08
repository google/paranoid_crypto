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
"""Wrapper around fpylll."""

from collections.abc import Callable
from typing import Optional
import fpylll


def reduce(matrix: list[list[int]]) -> list[list[int]]:
  """Performs a lattice reduction.

  This function calls LLL to find a reduce basis of the input.

  Args:
    matrix: the integer lattice to reduce

  Returns:
    the reduce basis. Typically the first row of the result is one of the
    shortest vectors in the lattice
  """
  # Convert the input to python integers if necessary.
  # This is done to avoid potential problems, when the underlying library uses
  # different int implementations. (E.g. using sagemath instead of fpylll had
  # previously lead to problems).
  tmp = [[int(v) for v in row] for row in matrix]
  m = fpylll.IntegerMatrix.from_matrix(tmp)
  reduced = fpylll.LLL.reduction(m)
  res = [[0] * reduced.ncols for _ in range(reduced.nrows)]
  reduced.to_matrix(res)
  return res


def reduce_bkz(
    matrix: list[list[int]],
    block_size: int = 16,
    max_loops: int = 3,
    pre_reduced: bool = False,
    stop_fn: Optional[Callable[[list[list[int]]], bool]] = None,
) -> list[list[int]]:
  """Performs BKZ lattice basis reduction.

  Uses fpylll's C++ Schnorr-Euchner enumeration without external strategy files
  so reduction remains hermetic in packaged builds, and selects a floating-point
  type that avoids double-precision exponent overflow on large moduli (such as
  secp521r1) and Gram-Schmidt precision loss in higher dimensions.

  Args:
    matrix: the integer lattice to reduce.
    block_size: target BKZ block size.
    max_loops: maximum number of BKZ tours.
    pre_reduced: if True, skips initial LLL reduction when `matrix` is already
      LLL-reduced.
    stop_fn: optional predicate called with the current reduced basis; if it
      returns True, reduction terminates early and returns that basis.

  Returns:
    the reduced basis.
  """
  if not matrix:
    return []
  tmp = [[int(v) for v in row] for row in matrix]
  m = fpylll.IntegerMatrix.from_matrix(tmp, int_type="mpz")
  nrows = len(tmp)
  actual_block_size = min(block_size, nrows)
  reduced = m if pre_reduced else fpylll.LLL.reduction(m)
  res = [[0] * reduced.ncols for _ in range(reduced.nrows)]
  reduced.to_matrix(res)
  if nrows <= 2 or actual_block_size <= 2 or max_loops <= 0:
    return res
  if stop_fn is not None and stop_fn(res):
    return res

  max_bits = 0
  for row in res:
    for v in row:
      max_bits = max(max_bits, abs(v).bit_length())
  if max_bits < 470 and nrows <= 115:
    float_type = "double"
    precision = 0
  elif max_bits < 7500 and nrows <= 170:
    float_type = "long double"
    precision = 0
  else:
    float_type = "mpfr"
    precision = max(128, nrows + 40)

  bkz_flags = (
      fpylll.BKZ.DEFAULT | fpylll.BKZ.BOUNDED_LLL | fpylll.BKZ.NO_LLL
  )
  if actual_block_size > 22 and max_loops > 1:
    tour_blocks = [22] + [actual_block_size] * (max_loops - 1)
  else:
    tour_blocks = [actual_block_size] * max_loops

  def _lll_step(
      mat: fpylll.IntegerMatrix, ft: str
  ) -> fpylll.IntegerMatrix:
    if ft in ("double", "long double"):
      try:
        return fpylll.LLL.reduction(mat, method="fast", float_type=ft)
      except fpylll.ReductionError:
        return fpylll.LLL.reduction(mat)
    return fpylll.LLL.reduction(mat)

  def _run_tours(
      mat: fpylll.IntegerMatrix, ft: str, prec: int
  ) -> fpylll.IntegerMatrix:
    prev_heads = None
    for bsize in tour_blocks:
      param = fpylll.BKZ.Param(
          block_size=bsize,
          max_loops=1,
          flags=bkz_flags,
      )
      mat = fpylll.BKZ.reduction(
          mat, param, float_type=ft, precision=prec
      )
      mat = _lll_step(mat, ft)
      mat.to_matrix(res)
      if stop_fn is not None and stop_fn(res):
        break
      heads = tuple((res[i][0], res[i][1]) for i in range(nrows))
      if bsize == actual_block_size and heads == prev_heads:
        break
      prev_heads = heads
    return mat

  try:
    reduced = _run_tours(reduced, float_type, precision)
  except (fpylll.ReductionError, RuntimeError):
    m_fallback = fpylll.IntegerMatrix.from_matrix(tmp, int_type="mpz")
    reduced = fpylll.LLL.reduction(m_fallback)
    if float_type == "double" and nrows <= 170:
      try:
        reduced = _run_tours(reduced, "long double", 0)
      except (fpylll.ReductionError, RuntimeError):
        m_mpfr = fpylll.IntegerMatrix.from_matrix(tmp, int_type="mpz")
        reduced = fpylll.LLL.reduction(m_mpfr)
        reduced = _run_tours(reduced, "mpfr", max(128, nrows + 40))
    else:
      reduced = _run_tours(reduced, "mpfr", max(128, nrows + 40))
    reduced.to_matrix(res)
  return res
