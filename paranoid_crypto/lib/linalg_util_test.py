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
"""Tests for paranoid_crypto.lib.linalg_util.py."""

from absl.testing import absltest
from paranoid_crypto.lib import linalg_util


class LinAlgUtilTest(absltest.TestCase):

  def testEchelonForm(self):
    # Examples from Peter R. Turner, 'A Simplified Fraction-Free Integer Gauss
    # Elimination Algorithm', U. S. Naval Academy, 1995.

    # Example 1
    a = [[8, 7, 4, 1], [4, 6, 7, 3], [6, 3, 4, 6], [4, 5, 8, 2]]
    res_a = [[8, 7, 4, 1], [0, 20, 40, 20], [0, 0, 110, 150], [0, 0, 0, -450]]
    rank = linalg_util.echelon_form(a)
    self.assertEqual(a, res_a)
    self.assertEqual(rank, 4)

    # Example 2
    a = [[7, 4, 1, 8], [6, 7, 3, 4], [3, 4, 6, 6], [5, 8, 2, 4]]
    res_a = [[7, 4, 1, 8], [0, 25, 15, -20], [0, 0, 105, 110], [0, 0, 0, 450]]
    rank = linalg_util.echelon_form(a)
    self.assertEqual(a, res_a)
    self.assertEqual(rank, 4)

    # Example 3
    a = [[8, 7, 4, 1], [4, 6, 7, 3], [6, 3, 4, 6], [4, 5, 8, 2]]
    res_a = [[8, 7, 4, 1], [0, 20, 40, 20], [0, 0, 110, 150], [0, 0, 0, -450]]
    b = [45, 30, 40, 30]
    res_b = [45, 60, 260, -450]
    rank = linalg_util.echelon_form(a, b)
    self.assertEqual(a, res_a)
    self.assertEqual(b, res_b)
    self.assertEqual(rank, 4)

    # Test with some linear dependent rows
    a = [[8, 7, 4, 1], [4, 6, 7, 3], [2 * 8, 2 * 7, 2 * 4, 2 * 1], [6, 3, 4, 6],
         [4, 5, 8, 2]]
    res_a = [[8, 7, 4, 1], [0, 20, 40, 20], [0, 0, 110, 150], [0, 0, 0, -450],
             [0, 0, 0, 0]]
    b = [45, 30, 2 * 45, 40, 30]
    res_b = [45, 60, 260, -450, 0]
    rank = linalg_util.echelon_form(a, b)
    self.assertEqual(a, res_a)
    self.assertEqual(b, res_b)
    self.assertEqual(rank, 4)

    a = [[8, 7, 4, 1], [4, 6, 7, 3], [0, 0, 0, 0], [0, 0, 0, 0], [6, 3, 4, 6],
         [4, 5, 8, 2]]
    res_a = [[8, 7, 4, 1], [0, 20, 40, 20], [0, 0, 110, 150], [0, 0, 0, -450],
             [0, 0, 0, 0], [0, 0, 0, 0]]
    b = [45, 30, 0, 0, 40, 30]
    res_b = [45, 60, 260, -450, 0, 0]
    rank = linalg_util.echelon_form(a, b)
    self.assertEqual(a, res_a)
    self.assertEqual(b, res_b)
    self.assertEqual(rank, 4)

  def testUpperTriangularSolve(self):
    # Example 3
    a = [[8, 7, 4, 1], [0, 20, 40, 20], [0, 0, 110, 150], [0, 0, 0, -450]]
    b = [45, 60, 260, -450]
    res = [5, 0, 1, 1]
    x = linalg_util.upper_triangular_solve(a, b)
    self.assertEqual(x, res)

    # Although below is a 3x3 system, we expect the result to be None
    a = [[0, 20, 40, 20], [0, 0, 110, 150], [0, 0, 0, -450], [0, 0, 0, 0]]
    b = [60, 260, -450, 0]
    res = None
    x = linalg_util.upper_triangular_solve(a, b)
    self.assertEqual(x, res)

    # But if one knows it's a 3x3 system, it should still be possible to solve:
    a = [[20, 40, 20], [0, 110, 150], [0, 0, -450]]
    b = [60, 260, -450]
    res = [0, 1, 1]
    x = linalg_util.upper_triangular_solve(a, b)
    self.assertEqual(x, res)

  def testSolveRight(self):
    # Example 3
    a = [[8, 7, 4, 1], [0, 20, 40, 20], [0, 0, 110, 150], [0, 0, 0, -450]]
    b = [45, 60, 260, -450]
    res = [5, 0, 1, 1]
    x = linalg_util.solve_right(a, b)
    self.assertEqual(x, res)

    # Test with more rows than columns
    a = [[8, 7, 4, 1], [4, 6, 7, 3], [2 * 8, 2 * 7, 2 * 4, 2 * 1], [6, 3, 4, 6],
         [4, 5, 8, 2]]
    b = [45, 30, 2 * 45, 40, 30]
    res = [5, 0, 1, 1]
    x = linalg_util.solve_right(a, b)
    self.assertEqual(x, res)

    a = [[8, 7, 4, 1], [4, 6, 7, 3], [0, 0, 0, 0], [0, 0, 0, 0], [6, 3, 4, 6],
         [4, 5, 8, 2]]
    b = [45, 30, 0, 0, 40, 30]
    res = [5, 0, 1, 1]
    x = linalg_util.solve_right(a, b)
    self.assertEqual(x, res)


if __name__ == '__main__':
  absltest.main()
