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
"""Tests for paranoid_crypto.lib.special_case_factoring."""

from absl.testing import absltest
from paranoid_crypto.lib import special_case_factoring


class SpecialCaseFactoringTest(absltest.TestCase):

  def testFactorWithGuess(self):
    """Tests factorization with approximations of different accuracy.

    The test uses an RSA modulus n and a factor p of n. The test tries to factor
    n with approximations p_0 and p_1, with increasing differences between
    p_0, p_1 and p until factorization fails.

    The test expects that factorizations succeed if the bit-length of p - pi
    is at most one third of the bit-length of p.
    """
    p = int("1620135664989517375797021518152900353185954124309260254110623329"
            "3874580244686173539991131620905981676447491534489829613156440269"
            "2546706815825922215329727068889962786698544393083370831665822889"
            "0028288533417931777187356095276472495247783537821374334125451825"
            "26865069990845841384161378904481475156830434010842277")
    n = int("2400788315383008472064647022508680364495290859484354903648899190"
            "4238774047764896864991935511769148535426791877007864705315664681"
            "5530169470125794737077830571461677172940571818998083789247486476"
            "7932534067428346660262904537995178748917749116421090776344705136"
            "0735356585723271778554898259677413639861606365469221539571959502"
            "4201839302386916963518955431779480289455311588938386419017161521"
            "6203005887205076630138199740993414942137563451649593769363773454"
            "5461647285816470539997875564800443589521536124335806335125861721"
            "8000880245008713378870738482220205532320816865737162459061907758"
            "41442311840621539850546721032146438828819")

    assert n % p == 0
    expected = {p, n // p}

    best_factorization = 0
    for bits in range(8, p.bit_length()):
      p_0 = p // 2**bits * 2**bits
      res = special_case_factoring.FactorWithGuess(n, p_0)
      if res is None or set(res) != expected:
        break
      p_1 = p_0 + 2**bits
      res = special_case_factoring.FactorWithGuess(n, p_1)
      if res is None or set(res) != expected:
        break
      best_factorization = bits

    assert best_factorization >= p.bit_length() // 3

  def testFactorWithGuessSmallDifference(self):
    """Checks factorization of n = p * q where p and q have a small difference.

    The test expects that similar results as Fermat factorization. Hence,
    p * q can be factored if abs(p - q) is about n ** (1 / 4). The primes
    below are both 1024 bit long. Their difference is 510 bits.
    """
    p = int(
        "e7aa005a74cb576528c95e9c2780f224e178f5ef519bfdb24d52ab92806baef7"
        "ed3ba8693bd78b9584e4df38eb9bbeab2ef2c72f77a46fbb080d3c80e1d1219d"
        "4968b8a99dfc8faa9da3d0ac936122aebcb469e769c2e7cfe1370399b6d2d51f"
        "1b380885ff9af2666664520cdd575ae9e1f97f203caffbd3ee05d9544b2ea45d", 16)
    q = int(
        "e7aa005a74cb576528c95e9c2780f224e178f5ef519bfdb24d52ab92806baef7"
        "ed3ba8693bd78b9584e4df38eb9bbeab2ef2c72f77a46fbb080d3c80e1d1219d"
        "717463f06b4c935daf9cd60080308426a02baac7b540667738caf6cb9d2570bb"
        "6bdb5ea9a9b15dfcfc7eae842284b901a50b1cdcd824d5b84ab53ddfd24555db", 16)
    n = p * q
    # p_0 is approximately the square root of n.
    p_0 = (p + q) // 2
    res = special_case_factoring.FactorWithGuess(n, p_0)
    self.assertIsNotNone(res)
    self.assertSameElements(res, [p, q])


if __name__ == "__main__":
  absltest.main()
