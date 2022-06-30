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
from absl.testing import absltest
from absl.testing import parameterized
import gmpy
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import ec_util
from paranoid_crypto.lib import util

ec_key_secp256k1 = paranoid_pb2.ECKey()
ec_key_secp256k1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256K1
ec_key_secp256k1.ec_info.x = util.Hex2Bytes(
    "c5d466e27280bb015418bdddbe6d74ba61fb54cdea23446ec966964c261361f1")
ec_key_secp256k1.ec_info.y = util.Hex2Bytes(
    "0e16ea79206f8039a817854ce05284995b3968c6ff6e3de7e443690902a5e7c6")


class EcUtilTest(parameterized.TestCase):
  curves = [
      (c.name, c) for n, c in ec_util.CURVE_FACTORY.items() if c is not None
  ]

  # Some tests are expensive and are only performed with the most important
  # curves,
  main_curves = [(n, c) for n, c in curves if n in ["secp256r1"]]

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
        c.Multiply(c.g, c.n), ec_util.INFINITY,
        "c.n should be the order of c.g")
    self.assertIn(c.h, (1, 2, 3, 4), "the cofactor should be small")
    # Hasse's theorem states that the  number of points on an elliptic curve
    # satisfies abs(c.n * h - (c.mod + 1)) <= 2*sqrt(c.mod).
    self.assertLessEqual((c.n * c.h - (c.mod + 1))**2, 4 * c.mod,
                         "Hasse's theorem is not satisfied")
    self.assertNotEqual((4 * c.a**3 + 27 * c.b**2) % c.mod, 0,
                        "The curve must not be singular")

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
    inverses = c.BatchInverse(values)
    for v, inv in zip(values, inverses):
      if v == 0:
        self.assertIs(inv, None)
      else:
        self.assertEqual(v * inv % c.mod, 1)

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
      self.assertEqual(diffs[i],
                       c.Subtract(c.g, points[i])[0], "subtraction %d" % i)

  @parameterized.named_parameters(*curves)
  def testBatchMultiplyG(self, c: ec_util.EcCurve):
    scalars = [0, 1, c.n - 1, c.n] + [random.randint(0, c.n) for _ in range(64)]
    points1 = [c.Multiply(c.g, x) for x in scalars]
    points2 = c.BatchMultiplyG(scalars)
    for i in range(len(points1)):
      self.assertEqual(points1[i], points2[i],
                       "i: %d, scalar: %d" % (i, scalars[i]))

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

  @parameterized.named_parameters(*main_curves)
  def testExtendedBatchDL(self, c: ec_util.EcCurve):
    dl_bound = 2**32
    quad_words = c.n.bit_length() // 32
    dls = [random.randint(0, dl_bound) << (i * 32) for i in range(quad_words)]
    mult = sum(2**(32 * i) for i in range(quad_words))
    dls += [random.randint(0, dl_bound) * mult for i in range(4)]
    points = [c.Multiply(c.g, i) for i in dls]
    res = c.ExtendedBatchDL(points)
    for i, dl in enumerate(res):
      self.assertEqual(dls[i], dl)

  @parameterized.named_parameters(*curves)
  def testBatchDLOfDifferences(self, c: ec_util.EcCurve):
    max_difference = 2**16
    rand = [random.randint(0, c.n) for _ in range(4)]
    priv = [
        rand[0], rand[1],
        rand[0] + random.randint(-max_difference + 1, max_difference), rand[2],
        rand[3], rand[1] + random.randint(-max_difference + 1, max_difference)
    ]
    points = [c.Multiply(c.g, p) for p in priv]
    new_points = points[:4]
    old_points = points[4:]
    res = c.BatchDLOfDifferences(new_points, old_points, max_difference)
    self.assertIsNotNone(res[0], "DL of new_points[2] is close to this")
    self.assertIsNotNone(res[1], "DL of old_points[1] is close to this")
    self.assertIsNotNone(res[2], "DL of new_points[0] is close to this")
    self.assertIsNone(res[3], "This is a random point")

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
    point = (0xc5d466e27280bb015418bdddbe6d74ba61fb54cdea23446ec966964c261361f1,
             0xe16ea79206f8039a817854ce05284995b3968c6ff6e3de7e443690902a5e7c6)
    self.assertEqual(ec_util.PublicPoint(ec_key_secp256k1.ec_info), point)


if __name__ == "__main__":
  absltest.main()
