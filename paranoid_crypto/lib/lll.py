"""Wrapper around fpylll."""

from typing import List
import fpylll


def reduce(matrix: List[List[int]]) -> List[List[int]]:
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
