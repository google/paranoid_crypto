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
