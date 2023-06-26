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
"""Tests for paranoid_crypto.lib.rsa_util.py."""

import random
from absl.testing import absltest
import gmpy
from paranoid_crypto.lib import rsa_util


class RsaUtilTest(absltest.TestCase):

  def testBatchGcd(self):
    self.assertFalse(
        all(value == 1 for value in rsa_util.BatchGCD([1, 2, 3, 2 * 2])))
    self.assertFalse(
        all(value == 1 for value in rsa_util.BatchGCD([1, 2, 3, 2 * 2, 5])))
    self.assertFalse(
        all(value == 1
            for value in rsa_util.BatchGCD([2 * 5, 3 * 7, 11, 13, 17, 19 * 5])))
    self.assertTrue(
        all(value == 1
            for value in rsa_util.BatchGCD([2 * 5, 3 * 7, 11, 13, 17, 19 *
                                            23])))
    self.assertTrue(
        all(value == 1
            for value in rsa_util.BatchGCD([3 * 7, 13, 17, 19, 25], 11 * 16 *
                                           23 * 29)))
    # 13, 17 and 19 are repeated values. They should be filtered by
    # OnSetRSAContext, before passing to this function.
    self.assertEqual(
        rsa_util.BatchGCD(list(range(2, 22)), 13 * 17 * 19),
        [2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21])
    self.assertEqual(
        rsa_util.BatchGCD([2 * 3, 5 * 7, 5 * 11, 2 * 3]), [1, 5, 5, 1])
    self.assertEqual(
        rsa_util.BatchGCD([2 * 3, 2 * 5, 3 * 5]), [2 * 3, 2 * 5, 3 * 5])

  def testFermat(self):
    p_fermat = gmpy.next_prime(random.getrandbits(1024))
    q_fermat = gmpy.next_prime(p_fermat + 2**100)
    # abs(p_fermat - q_fermat) is much smaller than the square root
    # of the two primes. Hence the first or second attempt should already
    # factor their product.
    max_steps = 2
    result = rsa_util.FermatFactor(p_fermat * q_fermat, max_steps)
    self.assertEqual(result[0] * result[1], p_fermat * q_fermat)
    result = rsa_util.FermatFactor(2 * p_fermat, max_steps)
    self.assertEqual(result[0] * result[1], 2 * p_fermat)
    result = rsa_util.FermatFactor(q_fermat * q_fermat, max_steps)
    self.assertEqual(result[0] * result[1], q_fermat * q_fermat)

  def testPollardpm1(self):
    # Only p-1 is smooth enough:
    res, factors = rsa_util.Pollardpm1(
        23 * 47, m=2 * 3 * 5 * 7 * 11, gcd_bound=1)
    self.assertTrue(res)
    self.assertEqual(factors[0] * factors[1], 23 * 47)

    # Both p-1 and q-1 are smooth enough:
    res, factors = rsa_util.Pollardpm1(
        23 * 47, m=2 * 3 * 5 * 7 * 11 * 23, gcd_bound=1)
    self.assertTrue(res)
    self.assertEmpty(factors)

    # Not smoooth enough.
    res, factors = rsa_util.Pollardpm1(23 * 47, m=2 * 3 * 5 * 7, gcd_bound=1)
    self.assertFalse(res)
    self.assertEmpty(factors)

    # gcd(n-1, m) is too low, so test is skipped:
    res, factors = rsa_util.Pollardpm1(23 * 47, m=2 * 3 * 5 * 7 * 11 * 23)
    self.assertFalse(res)
    self.assertEmpty(factors)


if __name__ == '__main__':
  absltest.main()
