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
"""EC Tests for paranoid_crypto.lib.paranoid."""

from absl.testing import absltest
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import paranoid
from paranoid_crypto.lib import paranoid_base_test
from paranoid_crypto.lib import util
from paranoid_crypto.lib.paranoid import ec_aggregate_checks
from paranoid_crypto.lib.paranoid import ec_single_checks

# Good EC keys.
good_ec_key_brainpoolp256r1 = paranoid_pb2.ECKey()
good_ec_key_brainpoolp256r1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_BRAINPOOLP256R1
good_ec_key_brainpoolp256r1.ec_info.x = util.Hex2Bytes(
    '533fc03ea6a7453eeccd293f59e7bada79fc46560c613c54ae4aac4e9024c2ca')
good_ec_key_brainpoolp256r1.ec_info.y = util.Hex2Bytes(
    '8bc00c3f39edd7b41a356fa939714644c3db948c59fb6c70a3d0cb1f12c2e41b')

good_ec_key_brainpoolp384r1 = paranoid_pb2.ECKey()
good_ec_key_brainpoolp384r1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_BRAINPOOLP384R1
good_ec_key_brainpoolp384r1.ec_info.x = util.Hex2Bytes(
    '156d9ab48d3502e759bb9983007ab1a9c35e7fc7eeb437c60d27305b533a4a32786a88f0aa6ca1273d1565dcb40d6453'
)
good_ec_key_brainpoolp384r1.ec_info.y = util.Hex2Bytes(
    '08fa19590d9d2794459d212566505a81259d17e4ee1a14a0350ade58c89e9026e37e71051d270a793b27cad50f74b9cb'
)

good_ec_key_brainpoolp512r1 = paranoid_pb2.ECKey()
good_ec_key_brainpoolp512r1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_BRAINPOOLP512R1
good_ec_key_brainpoolp512r1.ec_info.x = util.Hex2Bytes(
    '56e97ec1b01d8fa0a9d2a4492c3f5c3b5d0e06737d374b790d4cf0fa869a200882ae38a141ea08643b7f98d8d0a7a386b96f45415de00ece51805f41a2232464'
)
good_ec_key_brainpoolp512r1.ec_info.y = util.Hex2Bytes(
    '795115155acb3e63b203b1dd88c3e2ea6746a8ea2c4890554b2af488db9c2da10ea2493c1b99e0b76cad91fca319a68e6427943378791797c791f54bb6ef1112'
)

good_ec_key_secp224r1 = paranoid_pb2.ECKey()
good_ec_key_secp224r1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP224R1
good_ec_key_secp224r1.ec_info.x = util.Hex2Bytes(
    '662c0aac233aabaf2c14a4a548de90477d44ffc1b82957f13f7c7b6c')
good_ec_key_secp224r1.ec_info.y = util.Hex2Bytes(
    '911c83ed510fdd039a66d99cb68a156af9b2d0addb0711b8e72e0519')

good_ec_key_secp256k1 = paranoid_pb2.ECKey()
good_ec_key_secp256k1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256K1
good_ec_key_secp256k1.ec_info.x = util.Hex2Bytes(
    'c5d466e27280bb015418bdddbe6d74ba61fb54cdea23446ec966964c261361f1')
good_ec_key_secp256k1.ec_info.y = util.Hex2Bytes(
    '0e16ea79206f8039a817854ce05284995b3968c6ff6e3de7e443690902a5e7c6')

good_ec_key_secp256r1 = paranoid_pb2.ECKey()
good_ec_key_secp256r1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
good_ec_key_secp256r1.ec_info.x = util.Hex2Bytes(
    '972ba353e0252fc905ba62045b1acbee742f1744382e05ddd66e1f59c7940a43')
good_ec_key_secp256r1.ec_info.y = util.Hex2Bytes(
    'f291ef22b804b01c7df7644070bb727f62071b51470909216b52773f62231721')

good_ec_key_secp384r1 = paranoid_pb2.ECKey()
good_ec_key_secp384r1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP384R1
good_ec_key_secp384r1.ec_info.x = util.Hex2Bytes(
    '5177b515d785c6541662b6f462599b8b395dd63a479cdd77d03ee5acf75a41785ebcc5193c1560a96cd4831b1bf2a409'
)
good_ec_key_secp384r1.ec_info.y = util.Hex2Bytes(
    'af0e6b13cb1e1f9b3fc970e4c6f98b962b43062f6e259fa9e1a248980d8384230a36c31d36e22748f105411166c4dacc'
)

good_ec_key_secp521r1 = paranoid_pb2.ECKey()
good_ec_key_secp521r1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP521R1
good_ec_key_secp521r1.ec_info.x = util.Hex2Bytes(
    'ce4de5d56050f410cc55e4518cf04b0370511e8aa38f2ba59a30c677382c79280ebadf1970cc309e20438b584fd0213b72fdf5862a80285a70e71162cf76b020dd'
)
good_ec_key_secp521r1.ec_info.y = util.Hex2Bytes(
    '5e7a70affa243ad9f54a84b8263e08b756f73d99a8b9336d0561a4b46c041fd81d8a4e56dd5ba3086fb00a378c98e41800695b8877d5bcefb6ac30d60d88b273ca'
)

good_ec_keys = [
    good_ec_key_brainpoolp256r1, good_ec_key_brainpoolp384r1,
    good_ec_key_brainpoolp512r1, good_ec_key_secp224r1, good_ec_key_secp256k1,
    good_ec_key_secp256r1, good_ec_key_secp384r1, good_ec_key_secp521r1
]

# An EC key where the point is not on the curve
bad_ec_key_invalid = paranoid_pb2.ECKey()
bad_ec_key_invalid.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ec_key_invalid.ec_info.x = util.Hex2Bytes(
    '1cd4a8cf4dc90104e45e8a8a59f598c76ad19d1234912313964d0454b92c3cae')
bad_ec_key_invalid.ec_info.y = util.Hex2Bytes(
    '1482742fb02284f75f603f9b0057a89f32ff0a361694fb178a75de56efd61469')

# An EC key on a weak curve
bad_ec_key_weak_curve = paranoid_pb2.ECKey()
bad_ec_key_weak_curve.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP192R1
bad_ec_key_weak_curve.ec_info.x = util.Hex2Bytes(
    'c10f8a2043ba6f7859d88c7a71650813d53fe1ae3a813d57')
bad_ec_key_weak_curve.ec_info.y = util.Hex2Bytes(
    'c92c238c133469673ddcec2e02f80af83f72193ba5db2cc7')

# An EC key with private key = 0xfac29dac
bad_ec_key_small = paranoid_pb2.ECKey()
bad_ec_key_small.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ec_key_small.ec_info.x = util.Hex2Bytes(
    '1cd4a8cf4dc90104e45e8a8a59f598c76ad19dcf420f1e13964d0454b92c3cae')
bad_ec_key_small.ec_info.y = util.Hex2Bytes(
    'bbf3783fb02284f75f603f9b0057a89f32ff0a361694fb178a75de56efd61469')

# An EC key where only the most significant bits are set.
# The private key is
# 0xcdd0a1f300000000000000000000000000000000000000000000000000000000
bad_ec_key_high_bits = paranoid_pb2.ECKey()
bad_ec_key_high_bits.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ec_key_high_bits.ec_info.x = util.Hex2Bytes(
    '76735383072de0a595944e2ea0fc1d9edf8f996e033599c4bd609cb4da69d945')
bad_ec_key_high_bits.ec_info.y = util.Hex2Bytes(
    'e04e18ef1532fd84cd7992415199702d2d881f7505f0c9b60f4822d018d89003')

# An EC key where the words in the private key repeat.
# The private key is
# 0xe899250fe899250fe899250fe899250fe899250fe899250fe899250fe899250f
bad_ec_key_repeat = paranoid_pb2.ECKey()
bad_ec_key_repeat.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ec_key_repeat.ec_info.x = util.Hex2Bytes(
    '7139faa536fc4b313b77fa7c2c8dd737a7a66bac756593867f797d6fb3bec5a5')
bad_ec_key_repeat.ec_info.y = util.Hex2Bytes(
    '1a75275829d4ca8353f3706cc584f019da41ec3eb093c0996990a6e0929be9fd')

ec_keys_weak_private = [
    bad_ec_key_small, bad_ec_key_high_bits, bad_ec_key_repeat
]

# Two EC keys where the difference between the private key is small i.e. smaller
# than 2^16.
bad_ec_key_diff1 = paranoid_pb2.ECKey()
bad_ec_key_diff1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ec_key_diff1.ec_info.x = util.Hex2Bytes(
    '87e33a340af1166c743c8d119c09bf9cd4e0b394a043cf4db75a7fbecafdb833')
bad_ec_key_diff1.ec_info.y = util.Hex2Bytes(
    '729e3fab5eb4315f58cb0b5f1a78e420df00598b4d34356323dfc3223cd46091')

bad_ec_key_diff2 = paranoid_pb2.ECKey()
bad_ec_key_diff2.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ec_key_diff2.ec_info.x = util.Hex2Bytes(
    'd7dfd8fac680bf1c731c3c06da335e8e4ff88e77d5becf77fb7f8c9d729a5642')
bad_ec_key_diff2.ec_info.y = util.Hex2Bytes(
    '179b95854f6303219426f78ceee1819cb254a678b82b271fe9928719aec1ed47')

ec_keys_small_difference = [bad_ec_key_diff1, bad_ec_key_diff2]

good_ec_key_secp256r1_2 = paranoid_pb2.ECKey()
good_ec_key_secp256r1_2.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
good_ec_key_secp256r1_2.ec_info.x = util.Hex2Bytes(
    'a20114784470a43deb937c5b4c400c27ede413017b0afebf28c259efb01bc324')
good_ec_key_secp256r1_2.ec_info.y = util.Hex2Bytes(
    '971b6d3ad75954d739a89fca59e91b5a2b0e834449b821e15d8cc070883dfbce')

good_ec_secp256r1_keys = [good_ec_key_secp256r1, good_ec_key_secp256r1_2]
good_and_bad_ec_keys = [good_ec_key_secp256r1, bad_ec_key_invalid]

# Trick to replace CheckECKeySmallDifference default max_diff (tests run faster)
ec_aggregate_checks.CheckECKeySmallDifference.__init__.__defaults__ = (2**8,)


class ParanoidECTest(paranoid_base_test.ParanoidBaseTest):

  def testCheckValidECKey(self):
    check = ec_single_checks.CheckValidECKey()
    self.assertTrue(check.Check([bad_ec_key_invalid]))
    self.assertResults([bad_ec_key_invalid], check.check_name, True)

  def testCheckWeakCurve(self):
    check = ec_single_checks.CheckWeakCurve()
    self.assertTrue(check.Check([bad_ec_key_weak_curve]))
    self.assertResults([bad_ec_key_weak_curve], check.check_name, True)

  def testCheckWeakECPrivateKey(self):
    check = ec_single_checks.CheckWeakECPrivateKey()
    self.assertTrue(check.Check(ec_keys_weak_private))
    self.assertResults(ec_keys_weak_private, check.check_name, True)
    # TODO(pedroysb): Create assertDLogs method and call it here.

  def testCheckECKeySmallDifference(self):
    # Weak keys.
    check = ec_aggregate_checks.CheckECKeySmallDifference(max_diff=2**12)
    self.assertTrue(check.Check(ec_keys_small_difference))
    self.assertResults(ec_keys_small_difference, check.check_name, True)
    # Repeated keys does not flag.
    check = ec_aggregate_checks.CheckECKeySmallDifference(max_diff=2**12)
    self.assertFalse(check.Check([bad_ec_key_diff1, bad_ec_key_diff1]))
    self.assertTrue(check.Check(ec_keys_small_difference))

  def testCheckAllEC(self):
    self.assertFalse(paranoid.CheckAllEC(good_ec_keys))
    for ec_check_name in paranoid.GetECAllChecks():
      self.assertResults(good_ec_keys, ec_check_name, False)


if __name__ == '__main__':
  absltest.main()
