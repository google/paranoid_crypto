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
"""Test for paranoid_crypto.lib.ec_util."""

import random
from unittest import mock
from absl.testing import absltest
from absl.testing import parameterized
import gmpy2 as gmpy
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import ec_util
from paranoid_crypto.lib import util

ec_key_secp256k1 = paranoid_pb2.ECKey()
ec_key_secp256k1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256K1
ec_key_secp256k1.ec_info.x = util.Hex2Bytes(
    "c5d466e27280bb015418bdddbe6d74ba61fb54cdea23446ec966964c261361f1"
)
ec_key_secp256k1.ec_info.y = util.Hex2Bytes(
    "0e16ea79206f8039a817854ce05284995b3968c6ff6e3de7e443690902a5e7c6"
)


class EcUtilTest(parameterized.TestCase):
  curves = [
      (c.name, c) for n, c in ec_util.CURVE_FACTORY.items() if c is not None
  ]

  # Primary NIST curves tested by ExtendedBatchDL (covers both byte-aligned
  # orders and secp521r1's 521-bit non-byte-aligned order).
  main_curves = [
      (n, c)
      for n, c in curves
      if n in ("secp256r1", "secp384r1", "secp521r1")
  ]

  @parameterized.named_parameters(*curves)
  def testGroup(self, c: ec_util.EcCurve):
    """Checks that c is a valid elliptic curve group.

    This test mainly checks for typos. It is not a full validation, e.g.,
    it does not check whether computing DLs is indeed difficult.

    Args:
      c: the group to test
    """
    self.assertTrue(gmpy.is_prime(c.mod), "c.mod should be prime")
    self.assertTrue(gmpy.is_prime(c.n), "c.n is expected to be a prime")
    self.assertTrue(c.OnCurve(c.g), "c.g must be on the curve")
    self.assertNotEqual(c.g, ec_util.INFINITY, "c.g must not be at infinity")
    self.assertEqual(
        c.Multiply(c.g, c.n), ec_util.INFINITY, "c.n should be the order of c.g"
    )
    self.assertIn(c.h, (1, 2, 3, 4), "the cofactor should be small")
    # Hasse's theorem states that the  number of points on an elliptic curve
    # satisfies abs(c.n * h - (c.mod + 1)) <= 2*sqrt(c.mod).
    self.assertLessEqual(
        (c.n * c.h - (c.mod + 1)) ** 2,
        4 * c.mod,
        "Hasse's theorem is not satisfied",
    )
    self.assertNotEqual(
        (4 * c.a**3 + 27 * c.b**2) % c.mod, 0, "The curve must not be singular"
    )

  @parameterized.named_parameters(*curves)
  def testConversion(self, c: ec_util.EcCurve):
    """Converts a point to Jacobian coordinates and back.

    Args:
      c: the group to test
    """
    c_jacobian = c.AffineToJacobian(c.g)
    # The representation in Jacobian coordinates is not unique.
    x, y, z = c_jacobian
    m = 12345678  # just an arbitrary integer
    x = x * m**2 % c.mod
    y = y * m**3 % c.mod
    z = z * m % c.mod
    c_affine = c.JacobianToAffine((x, y, z))
    self.assertEqual(c_affine, c.g)

  @parameterized.named_parameters(*curves)
  def testMultiply(self, c: ec_util.EcCurve):
    """Compares multiplication using affine and Jacobian coordinates.

    Args:
      c: the group to test
    """
    for i in range(-10, 100):
      m_affine = c.MultiplyAffine(c.g, i)
      m_jacobian = c.Multiply(c.g, i)
      self.assertEqual(m_affine, m_jacobian)
      self.assertTrue(c.OnCurve(m_affine))

  @parameterized.named_parameters(*curves)
  def testDH(self, c: ec_util.EcCurve):
    """Tests the associativity of the multiplication.

    Args:
      c: the group to test
    """
    x = random.randint(1, c.n)
    y = random.randint(1, c.n)
    a = c.Multiply(c.g, x)
    b = c.Multiply(c.g, y)
    ay = c.Multiply(a, y)
    bx = c.Multiply(b, x)
    self.assertEqual(ay, bx)

  @parameterized.named_parameters(*curves)
  def testBatchInverse(self, c: ec_util.EcCurve):
    """Tests the inversion of a list of integers in a batch.

    Args:
      c: an EC group. The test uses its modulus.
    """
    values = list(range(-100, 100))
    inverses = c.BatchInverse(values)  # pyrefly: ignore[bad-argument-type]
    for v, inv in zip(values, inverses):
      if v == 0:
        self.assertIs(inv, None)
      else:
        self.assertEqual(v * inv % c.mod, 1)  # pyrefly: ignore[unsupported-operation]

  @parameterized.named_parameters(*curves)
  def testBatchAdd(self, c: ec_util.EcCurve):
    points = [c.Multiply(c.g, i) for i in range(-10, 100)]
    sums = c.BatchAdd(c.g, points)
    sumsx = c.BatchAddX(c.g, points)
    for i in range(len(points) - 1):
      self.assertEqual(points[i + 1], sums[i], "point %d" % i)
    for i in range(len(points)):
      self.assertEqual(sumsx[i], sums[i][0], "point %d" % i)

  @parameterized.named_parameters(*curves)
  def testBatchAddList(self, c: ec_util.EcCurve):
    points1 = [c.Multiply(c.g, i) for i in range(-50, 50)]
    points2 = [c.Multiply(c.g, abs(i) % 7) for i in range(-50, 50)]
    sums = c.BatchAddList(points1, points2)
    for i in range(len(points1) - 1):
      self.assertEqual(c.Add(points1[i], points2[i]), sums[i], "point %d" % i)

  @parameterized.named_parameters(*curves)
  def testBatchDouble(self, c: ec_util.EcCurve):
    points = [c.Multiply(c.g, i) for i in range(-20, 20)]
    double = c.BatchDouble(points)
    for i in range(len(points) - 1):
      self.assertEqual(c.Double(points[i]), double[i], "point %d" % i)

  @parameterized.named_parameters(*curves)
  def testBatchAddSubtractX(self, c: ec_util.EcCurve):
    points = [c.Multiply(c.g, i) for i in range(-10, 100)]
    sums, diffs = c.BatchAddSubtractX(c.g, points)
    for i, _ in enumerate(points):
      self.assertEqual(sums[i], c.Add(c.g, points[i])[0], "addition %d" % i)
      self.assertEqual(
          diffs[i], c.Subtract(c.g, points[i])[0], "subtraction %d" % i
      )

  @parameterized.named_parameters(*curves)
  def testBatchMultiplyG(self, c: ec_util.EcCurve):
    scalars = [0, 1, c.n - 1, c.n] + [random.randint(0, c.n) for _ in range(64)]
    points1 = [c.Multiply(c.g, x) for x in scalars]
    points2 = c.BatchMultiplyG(scalars)
    for i in range(len(points1)):
      self.assertEqual(
          points1[i], points2[i], "i: %d, scalar: %d" % (i, scalars[i])
      )

  @parameterized.named_parameters(*curves)
  def testBatchDL(self, c: ec_util.EcCurve):
    dl_bound = random.randint(2**23, 2**24)
    dls = [random.randint(0, dl_bound) for i in range(32)]
    dls += [1, dl_bound - 1, dl_bound + 1, 2 * dl_bound]
    points = [c.Multiply(c.g, i) for i in dls]
    res = c.BatchDL(points, dl_bound)
    for i, dl in enumerate(res):
      if dl is None:
        self.assertLessEqual(dl_bound, abs(dls[i]))
      else:
        self.assertEqual(dls[i], dl)
    # Verify negative discrete logs within the first baby-step table range are
    # normalized modulo c.n.
    neg_point = c.Multiply(c.g, c.n - 1)
    neg_res = c.BatchDL([neg_point], 16)
    self.assertEqual(neg_res[0], c.n - 1)

  @parameterized.named_parameters(*main_curves)
  def testExtendedBatchDL(self, c: ec_util.EcCurve):
    dl_bound = 2**32
    order = int(c.n)
    bits = c.n.bit_length()
    byte_bits = ((bits + 7) // 8) * 8
    quad_words = (bits + 31) // 32
    rng = random.Random(42)

    # 1. 0x00-padded 4-byte windows (including top byte-aligned shift and
    #    bit-aligned 32-MSB window on secp521r1).
    dls = [
        (rng.randint(1, dl_bound - 1) << (i * 32)) % order
        for i in range(bits // 32)
    ]
    dls.append((0xCAFEBABE << (byte_bits - 32)) % order)
    if bits % 8 != 0:
      dls.append((0x87654321 << (bits - 32)) % order)

    # 2. Repeated 32-bit words (including full ceil(bits / 32) words).
    for words in (2, quad_words):
      mult = sum(1 << (32 * i) for i in range(words))
      dls.append((rng.randint(1, dl_bound - 1) * mult) % order)

    # 3. 0xff-padded 4-byte windows and sign-extended negative 32-bit integers.
    mask_bits = (1 << bits) - 1
    for shift in (0, (byte_bits // 16) * 8, byte_bits - 32):
      dls.append((mask_bits - (0x12345678 << shift)) % order)
    if bits % 8 != 0:
      dls.append((mask_bits - (0x2468ACE0 << (bits - 32))) % order)
      mask_bytes = (1 << byte_bits) - 1
      dls.append((mask_bytes - (0x13579BDF << 64)) % order)
    dls.append(((1 << byte_bits) - 123456789) % order)

    # 4. Negative 32-bit integers reduced modulo n, plus INFINITY (0).
    dls.append(order - 1)
    dls.append(order - 0xDEADBEEF)
    dls.append(0)

    strong_priv = rng.randint(2**64, order - 2**64)
    points = [c.Multiply(c.g, d) for d in dls] + [c.Multiply(c.g, strong_priv)]
    res = c.ExtendedBatchDL(points)
    self.assertEqual(res[:-1], dls)
    self.assertIsNone(res[-1])

  @parameterized.named_parameters(*curves)
  def testBatchDLOfDifferences(self, c: ec_util.EcCurve):
    max_difference = 2**16
    rand = [random.randint(0, c.n) for _ in range(4)]
    priv = [
        rand[0],
        rand[1],
        rand[0]
        + random.choice((-1, 1)) * random.randint(1, max_difference - 1),
        rand[2],
        rand[3],
        rand[1]
        + random.choice((-1, 1)) * random.randint(1, max_difference - 1),
    ]
    points = [c.Multiply(c.g, p) for p in priv]
    new_points = points[:4]
    old_points = points[4:]
    res = c.BatchDLOfDifferences(new_points, old_points, max_difference)
    self.assertIsNotNone(res[0], "DL of new_points[2] is close to this")
    self.assertIsNotNone(res[1], "DL of old_points[1] is close to this")
    self.assertIsNotNone(res[2], "DL of new_points[0] is close to this")
    self.assertIsNone(res[3], "This is a random point")

  def testBatchDLOfDifferencesStrategies(self):
    c = ec_util.CURVE_FACTORY[paranoid_pb2.CurveType.CURVE_SECP256R1]
    assert c is not None
    self.assertIsNotNone(c._cc_engine)
    rng = random.Random(20261105)
    max_diff = 2**16
    base_a = rng.randint(2**80, int(c.n) - 2**80)
    base_b = rng.randint(2**80, int(c.n) - 2**80)
    base_other = rng.randint(2**80, int(c.n) - 2**80)
    unrelated_1 = rng.randint(2**80, int(c.n) - 2**80)
    unrelated_2 = rng.randint(2**80, int(c.n) - 2**80)

    other_points = [c.Multiply(c.g, base_other)]
    privs = [
        base_a,  # 0: matches idx 1 (+65535)
        base_a + max_diff - 1,  # 1: boundary +max_diff - 1
        base_b,  # 2: matches idx 3 (-65535)
        base_b - (max_diff - 1),  # 3: boundary -(max_diff - 1)
        base_other - 42,  # 4: matches other_points[0]
        unrelated_1,  # 5: duplicate with idx 6 -> must NOT match
        unrelated_1,  # 6: duplicate with idx 5 -> must NOT match
        unrelated_2,  # 7: diff == +max_diff with idx 8 -> out of range
        unrelated_2 + max_diff,  # 8: out of range
        1,  # 9: baby step hits INFINITY (1*G - 1*G), matches idx 10
        2,  # 10: matches idx 9 (+1)
        base_a,  # 11: duplicate weak key (same as idx 0) -> must match idx 1
    ]
    points = [c.Multiply(c.g, d) for d in privs]

    res_cc = c.BatchDLOfDifferences(points, other_points, max_diff)
    expected_matched = [
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        True,
        True,
        True,
    ]
    self.assertEqual([r is not None for r in res_cc], expected_matched)

    # Force multi-tile C++ DiffBatchDL execution and symmetric (no other_points)
    # mode, verifying identical detection.
    with mock.patch.object(ec_util, "_MAX_DIFF_CC_BABY_ENTRIES", 20):
      res_cc_tiled = c.BatchDLOfDifferences(points, other_points, max_diff)
      res_cc_sym = c.BatchDLOfDifferences(points, None, max_diff)
    self.assertEqual(res_cc_tiled, res_cc)
    expected_sym = expected_matched[:]
    expected_sym[4] = False
    self.assertEqual([r is not None for r in res_cc_sym], expected_sym)

    # Verify exact strict-inequality boundary |dl| < max_diff for small bounds.
    self.assertEqual(
        c.BatchDLOfDifferences(
            [c.Multiply(c.g, 10), c.Multiply(c.g, 10 + 16)], max_diff=16
        ),
        [None, None],
    )
    self.assertTrue(
        all(
            r is not None
            for r in c.BatchDLOfDifferences(
                [c.Multiply(c.g, 10), c.Multiply(c.g, 10 + 15)], max_diff=16
            )
        )
    )

  def testOutOfRangeBoundsRaiseValueError(self):
    c = ec_util.CURVE_FACTORY[paranoid_pb2.CurveType.CURVE_SECP256R1]
    assert c is not None
    with self.assertRaises(ValueError):
      c.BatchDL([c.g], 1 << 62)
    with self.assertRaises(ValueError):
      c.BatchDLOfDifferences([c.g, c.Multiply(c.g, 2)], max_diff=1 << 62)
    with self.assertRaises(ValueError):
      ec_util.EcCurve("bad_even_mod", a=-3, b=1, mod=8, gx=1, gy=1, n=7)

  @parameterized.named_parameters(*curves)
  def testHiddenNumberParams(self, c: ec_util.EcCurve):
    d = random.randint(1, c.n)
    k = random.randint(1, c.n)
    z = random.randint(1, c.n)
    x1, _ = c.Multiply(c.g, k)
    r = x1 % c.n
    s = gmpy.invert(k, c.n) * (z + r * d) % c.n
    a, b = c.HiddenNumberParams(r, s, z)
    k2 = (a + b * d) % c.n
    self.assertEqual(k, k2)

  def testPublicPoint(self):
    point = (
        0xC5D466E27280BB015418BDDDBE6D74BA61FB54CDEA23446EC966964C261361F1,
        0xE16EA79206F8039A817854CE05284995B3968C6FF6E3DE7E443690902A5E7C6,
    )
    self.assertEqual(ec_util.PublicPoint(ec_key_secp256k1.ec_info), point)


if __name__ == "__main__":
  absltest.main()
