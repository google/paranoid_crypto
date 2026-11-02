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

import random
from absl.testing import absltest
from absl.testing import parameterized
import gmpy2 as gmpy
from paranoid_crypto.lib import short_sleeve


def _generate_short_sleeve_prime(
    rng: random.Random,
    limbs: int,
    w: int,
    b: int,
    shift: int = 0,
    signed: bool = False,
    msb_mode: int = 1,
    use_next_prime: bool = True,
) -> int:
  base = 1 << w
  while True:
    val = 0
    for i in range(limbs):
      if signed:
        a = rng.randrange(-(1 << (b - 1)), 1 << (b - 1))
      else:
        a = rng.randrange(0, 1 << b)
      if i == limbs - 1 and a <= 0:
        a = rng.randrange(1, 1 << (b - 1))
      val += (a << shift) * (base**i)
    if val <= 0:
      continue
    psize = limbs * w
    if msb_mode == 1:
      val |= 1 << (psize - 1)
    elif msb_mode == 2:
      val |= 3 << (psize - 2)
    val |= 1
    if use_next_prime:
      p = int(gmpy.next_prime(val - 1))
      if p.bit_length() <= psize + 1:
        return p
    elif gmpy.is_prime(val):
      return val


class ShortSleeveTest(parameterized.TestCase):

  @parameterized.named_parameters(
      dict(
          testcase_name="completeftp_unsigned_w32_msb1",
          seed=101,
          limbs=32,
          w=32,
          b=8,
          shift=0,
          signed=False,
          msb_mode=1,
          use_next_prime=True,
      ),
      dict(
          testcase_name="completeftp_signed_sbyte_w32_msb2",
          seed=102,
          limbs=32,
          w=32,
          b=8,
          shift=0,
          signed=True,
          msb_mode=2,
          use_next_prime=True,
      ),
      dict(
          testcase_name="completeftp_unsigned_w32_msb0",
          seed=103,
          limbs=32,
          w=32,
          b=8,
          shift=0,
          signed=False,
          msb_mode=0,
          use_next_prime=True,
      ),
      dict(
          testcase_name="trail_of_bits_w128_low_sleeve",
          seed=104,
          limbs=8,
          w=128,
          b=40,
          shift=0,
          signed=False,
          msb_mode=1,
          use_next_prime=True,
      ),
      dict(
          testcase_name="ct_wild_pattern_w128_high_sleeve",
          seed=105,
          limbs=8,
          w=128,
          b=32,
          shift=96,
          signed=False,
          msb_mode=1,
          use_next_prime=True,
      ),
      dict(
          testcase_name="w64_signed_msb2",
          seed=106,
          limbs=16,
          w=64,
          b=16,
          shift=0,
          signed=True,
          msb_mode=2,
          use_next_prime=True,
      ),
      dict(
          testcase_name="w64_shifted_high",
          seed=107,
          limbs=16,
          w=64,
          b=20,
          shift=44,
          signed=False,
          msb_mode=1,
          use_next_prime=True,
      ),
      dict(
          testcase_name="w16_mcu_rejection",
          seed=108,
          limbs=64,
          w=16,
          b=3,
          shift=0,
          signed=False,
          msb_mode=1,
          use_next_prime=False,
      ),
      dict(
          testcase_name="w256_wide_limb",
          seed=109,
          limbs=4,
          w=256,
          b=96,
          shift=0,
          signed=False,
          msb_mode=1,
          use_next_prime=True,
      ),
      dict(
          testcase_name="rsa_1024_w128",
          seed=110,
          limbs=4,
          w=128,
          b=40,
          shift=0,
          signed=False,
          msb_mode=1,
          use_next_prime=True,
      ),
      dict(
          testcase_name="rsa_4096_w32",
          seed=111,
          limbs=64,
          w=32,
          b=8,
          shift=0,
          signed=False,
          msb_mode=1,
          use_next_prime=True,
      ),
  )
  def test_factors_short_sleeve_configurations(
      self,
      seed: int,
      limbs: int,
      w: int,
      b: int,
      shift: int,
      signed: bool,
      msb_mode: int,
      use_next_prime: bool,
  ):
    rng = random.Random(seed)
    p = _generate_short_sleeve_prime(
        rng, limbs, w, b, shift, signed, msb_mode, use_next_prime
    )
    q = _generate_short_sleeve_prime(
        rng, limbs, w, b, shift, signed, msb_mode, use_next_prime
    )
    self.assertEqual(short_sleeve.factor_short_sleeve(p * q), sorted([p, q]))

  def test_factors_high_modular_factor_count_with_lll(self):
    rng = random.Random(2026)
    # Construct p and q whose base-2^32 product splits into >= 6 factors mod p
    # so van Hoeij LLL recombination is exercised directly.
    p = _generate_short_sleeve_prime(rng, 16, 32, 8, 0, True, 0, False)
    q = _generate_short_sleeve_prime(rng, 16, 32, 8, 0, True, 0, False)
    r = _generate_short_sleeve_prime(rng, 16, 32, 8, 0, True, 0, False)
    # Product of two composite short-sleeve integers (4 prime factors in Z[x] ->
    # >= 4 modular factors over every F_p).
    n = (p * q) * r
    factors = short_sleeve.factor_short_sleeve(n)
    self.assertIsNotNone(factors)
    assert factors is not None
    self.assertLen(factors, 2)
    self.assertEqual(factors[0] * factors[1], n)
    self.assertGreater(factors[0], 1)

  def test_factors_square_short_sleeve_modulus(self):
    rng = random.Random(303)
    p = _generate_short_sleeve_prime(rng, 8, 128, 32, 96, False, 1, True)
    self.assertEqual(short_sleeve.factor_short_sleeve(p * p), [p, p])

  def test_rejects_random_small_even_and_corrupted_moduli(self):
    rng = random.Random(404)
    p = int(gmpy.next_prime(rng.getrandbits(1024) | (1 << 1023) | 1))
    q = int(gmpy.next_prime(rng.getrandbits(1024) | (1 << 1023) | 1))
    with self.subTest("random_rsa_2048"):
      self.assertIsNone(short_sleeve.factor_short_sleeve(p * q))
    with self.subTest("even_integer"):
      self.assertIsNone(short_sleeve.factor_short_sleeve((p * q) - 1))
    with self.subTest("too_small"):
      self.assertIsNone(short_sleeve.factor_short_sleeve(3233))
    with self.subTest("corrupted_zero_middle_bytes"):
      # Zeroing half of a random modulus creates zero runs in one half but is
      # not a Short-Sleeve polynomial product.
      corrupted = ((p * q) & ~(((1 << 1024) - 1) << 256)) | 1
      self.assertIsNone(short_sleeve.factor_short_sleeve(corrupted))
    with self.subTest("sparse_oversized_binomial"):
      self.assertIsNone(short_sleeve.factor_short_sleeve((1 << 16383) + 1))
    with self.subTest("all_ones_modulus"):
      self.assertIsNone(short_sleeve.factor_short_sleeve((1 << 4096) - 1))
    with self.subTest("periodic_unfactorable_limbs"):
      periodic = int("0001" * 128, 16) | (1 << 2047) | 1
      self.assertIsNone(short_sleeve.factor_short_sleeve(periodic))


if __name__ == "__main__":
  absltest.main()
