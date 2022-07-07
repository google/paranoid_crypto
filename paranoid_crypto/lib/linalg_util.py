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
"""Set of useful linear algebra functions."""

from typing import Optional
import gmpy


def echelon_form(a: list[list[int]], b: Optional[list[int]] = None) -> int:
  """Puts the matrix of integers a in row echelon form.

  All the operations are over the integers. Only exact divisions are performed.
  Thus, this function is useful when working over the integers.

  This is an adapted implementation of the proposal of Peter R. Turner,
  'A Simplified Fraction-Free Integer Gauss Elimination Algorithm', U. S. Naval
  Academy, 1995. The difference is that the original algorithm doesn't perform
  row swapping to the bottom when linear dependent rows are found, and fails
  when encounters zero pivots.

  It is interesting to note that the last element of the matrix in echelon form
  through this algorithm is the determinat of the original matrix.

  In order to work with Integers only, comparing with original gaussian
  elimination, it requires twice multiplications and divisions are increased
  from O(n^2) to O(n^3). The author, however, shows that working with Rationals
  wouldn't provide any improvement, and would require additional GCD
  computations.

  The b parameter can be provided for the useful cases when solving a linear
  system. I.e., it will be equivalent of performing gaussian elimination on the
  augmented matrix a||b.

  The changes on a and b are in place. Thus, if one wants to preserve the
  original a and b, one should pass copies of them to this function. The return
  value is the rank of the matrix a.

  Args:
    a: matrix of integers with m rows and n columns, with m >= n.
    b: optional vector of integers of size m. Useful when solving a system.

  Returns:
    rank of a.
  """

  nrows, ncols = len(a), len(a[0])
  if b and nrows != len(b):
    raise ValueError("Number of rows of a must be equal to the length of b.")
  n = min(nrows, ncols)
  rank = 1  # Assuming last row isn't zero. We deal with corner case at the end
  i = 0
  while i < n - 1:
    # Searches for a non-zero pivot
    pivots = i
    while pivots < n - 1 and a[i][i] == 0:
      if b:
        b.insert(nrows, b.pop(i))
      a.insert(nrows, a.pop(i))
      pivots += 1

    j = i + 1
    while j < nrows:
      if b:
        b[j] = a[i][i] * b[j] - a[j][i] * b[i]
      all_zeros = True
      for k in range(i + 1, ncols):
        a[j][k] = a[i][i] * a[j][k] - a[j][i] * a[i][k]
        if all_zeros and a[j][k] != 0:
          all_zeros = False
      a[j][i] = 0
      if all_zeros:
        # Found a linear dependent row. Move it to the bottom and retry.
        if b:
          b.insert(nrows, b.pop(j))
        a.insert(nrows, a.pop(j))
        nrows -= 1
      else:
        if rank < n:
          rank += 1
        j += 1

    if i >= 1:
      for j in range(i + 1, nrows):
        if b:
          b[j] //= a[i - 1][i - 1]
        for k in range(i + 1, ncols):
          a[j][k] //= a[i - 1][i - 1]
    i += 1
  # Corner case for the last row being zero
  if all([v == 0 for v in a[nrows - 1]]):
    rank -= 1
  return rank


def upper_triangular_solve(a: list[list[int]],
                           b: list[int]) -> Optional[list[gmpy.mpq]]:
  """Solves a matrix equation a*x = b, with a being an upper triangular matrix.

  Given an integer upper triangular matrix 'a' with m rows and m columns, and an
  integer vector b of size m, this function finds the vector of rationals
  (gmpy.mpq) x for the equation a*x = b.

  Args:
    a: upper triangular matrix of integers with m rows and m columns.
    b: vector of integers of size m.

  Returns:
    A solution x for a*x == b over the rationals if found. If a zero on the
      diagonal is found it returns None.
  """
  nrows, ncols = len(a), len(a[0])
  if nrows != ncols:
    raise ValueError("Matrix must be square.")
  if nrows != len(b):
    raise ValueError("Number of rows of a must be equal to the length of b.")
  xs = [0] * ncols
  for i in range(nrows - 1, -1, -1):
    den = a[i][i]
    if den == 0:
      return None
    num = b[i] - sum(a[i][j] * xs[j] for j in range(i + 1, ncols))
    xs[i] = gmpy.mpq(num, den)
  return xs


def solve_right(a: list[list[int]], b: list[int]) -> Optional[list[gmpy.mpq]]:
  """Solves a matrix equation a*x = b.

  Given an integer matrix 'a' of m rows and n columns, with m >= n and an
  integer vector b of size m, this function finds the vector of rationals
  (gmpy.mpq) x for the equation a*x = b.

  Args:
    a: matrix of integers with m rows and n columns, with m >= n.
    b: vector of integers of size m.

  Returns:
    A solution x for a*x == b over the rationals if found. None for the case of
      not enough linear independent rows provided.
  """
  nrows, ncols = len(a), len(a[0])
  if nrows != len(b):
    raise ValueError("Number of rows of a must be equal to the length of b.")
  if nrows < ncols:
    raise ValueError("Not enough rows/equations to solve the system.")
  rank = echelon_form(a, b)
  if rank != ncols:
    return None  # Not enough linear independent rows/equations
  return upper_triangular_solve(a[:rank], b[:rank])
