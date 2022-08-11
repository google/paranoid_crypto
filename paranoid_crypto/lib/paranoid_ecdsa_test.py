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
"""ECDSA Tests for paranoid_crypto.lib.paranoid."""

import copy
from absl.testing import absltest
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import paranoid
from paranoid_crypto.lib import paranoid_base_test
from paranoid_crypto.lib import util
from paranoid_crypto.lib.paranoid import ec_aggregate_checks
from paranoid_crypto.lib.paranoid import ecdsa_sig_checks

# Good ECDSA signatures.
good_ecdsa_secp256r1 = paranoid_pb2.ECDSASignature()
good_ecdsa_secp256r1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
good_ecdsa_secp256r1.ecdsa_sig_info.r = util.Hex2Bytes(
    'f888377e53ce3a94565661f84f560c539ffce99d1cd29eab88d049fa669de225')
good_ecdsa_secp256r1.ecdsa_sig_info.s = util.Hex2Bytes(
    '3ba37c33c3e8e0a3520691270e4889c1a1896440c3f05252cc49ab4531677a81')
good_ecdsa_secp256r1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'e36abb3b87505b0ba5067c9221a58a5c81513f060202a6e3da0833cd80e977b2')
good_ecdsa_secp256r1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
good_ecdsa_secp256r1.issuer_key_info.x = util.Hex2Bytes(
    '52840bcc3ddef170b9611001534613c03b52838db81f307865133ff727129b2')
good_ecdsa_secp256r1.issuer_key_info.y = util.Hex2Bytes(
    '34b5de1badddf0d6155b006b40fa6ace3b2c5bae704f1f720f508c48cddc3744')

good_ecdsa_secp521r1 = paranoid_pb2.ECDSASignature()
good_ecdsa_secp521r1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
good_ecdsa_secp521r1.ecdsa_sig_info.r = util.Hex2Bytes(
    '11a9c550ae5cf63ff0ff125fd454f97fc702ff648d0743aff68eb0bae6aeb2821a854d1000a5068d21602f5d6fca01bb5e0623a7135b6c8ade5bc709825f537fae8'
)
good_ecdsa_secp521r1.ecdsa_sig_info.s = util.Hex2Bytes(
    '1988b69f2d5b58278e897854f14b369bbe7f34d25bd6bb8404975ad063cbf38ebbed802f6215a0962612e5a87e8c345efe00d09a2bdaf8a95b161124900e7597d75'
)
good_ecdsa_secp521r1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'e36abb3b87505b0ba5067c9221a58a5c81513f060202a6e3da0833cd80e977b2')
good_ecdsa_secp521r1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP521R1
good_ecdsa_secp521r1.issuer_key_info.x = util.Hex2Bytes(
    '6bba7265c6efe40fb20a6d1c22756483ac590b11dcf2532ab6705f48612895a13d8a7b3503442c8a7eb60adb60e46edf827465f422199c1850626839b095fa4912'
)
good_ecdsa_secp521r1.issuer_key_info.y = util.Hex2Bytes(
    '1b471f02088804f0a9e9bf9b33c7e2081897fa25e10877eb8a4d365e4f6ece77aa4933a89b33cb80187f017e2b08a61e080973bd3e03bd05c6e8ce51cfa0b4e2473'
)

good_ecdsa_sigs = [
    good_ecdsa_secp256r1,
    good_ecdsa_secp521r1,
    # Make sure good deterministic ECDSA are not flagged:
    copy.deepcopy(good_ecdsa_secp256r1),
]

# An issuer EC key where the words in the private key repeat.
# The private key is
# 0xe899250fe899250fe899250fe899250fe899250fe899250fe899250fe899250f
bad_ecdsa_secp256r1_repeat = paranoid_pb2.ECDSASignature()
bad_ecdsa_secp256r1_repeat.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA512
bad_ecdsa_secp256r1_repeat.ecdsa_sig_info.r = util.Hex2Bytes(
    'a579c98160c2e4066f8defcc2a8510f027531287ee4b593fd9a2b17f6a9d86d9')
bad_ecdsa_secp256r1_repeat.ecdsa_sig_info.s = util.Hex2Bytes(
    '6082cf8f763ab383ca1be56dd04aa64bb0b0f862dba922821e902dd0da6c6bb0')
bad_ecdsa_secp256r1_repeat.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '25ffca8499df94d5725334521f18302f4aace2acf31f50659400cfb7d59e21338974f16127330ae6d371850cfa88c967000e373370068757409050405c5fe31e'
)
bad_ecdsa_secp256r1_repeat.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_secp256r1_repeat.issuer_key_info.x = util.Hex2Bytes(
    '7139faa536fc4b313b77fa7c2c8dd737a7a66bac756593867f797d6fb3bec5a5')
bad_ecdsa_secp256r1_repeat.issuer_key_info.y = util.Hex2Bytes(
    '1a75275829d4ca8353f3706cc584f019da41ec3eb093c0996990a6e0929be9fd')

# Two issuer EC keys where the difference between the private key is small i.e.
# smaller than 2^16.
bad_ecdsa_secp256k1_diff1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_secp256k1_diff1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA512
bad_ecdsa_secp256k1_diff1.ecdsa_sig_info.r = util.Hex2Bytes(
    'f13d8a617750045bd26f3fd05828e596d9b6e4d2855893b6b48cdfcf276e31f5')
bad_ecdsa_secp256k1_diff1.ecdsa_sig_info.s = util.Hex2Bytes(
    '39ba8c4080aa9bda6223dde0fe65ef7535f570f4473c45c3e19630664a6c50b7')
bad_ecdsa_secp256k1_diff1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '25ffca8499df94d5725334521f18302f4aace2acf31f50659400cfb7d59e21338974f16127330ae6d371850cfa88c967000e373370068757409050405c5fe31e'
)
bad_ecdsa_secp256k1_diff1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256K1
bad_ecdsa_secp256k1_diff1.issuer_key_info.x = util.Hex2Bytes(
    'dc93ef54134fceaafb7ea0b59be0dd272986b66ee4905d8dff57e056087ffbfe')
bad_ecdsa_secp256k1_diff1.issuer_key_info.y = util.Hex2Bytes(
    '5ae191bc21804648851489cbb7ad2a00bd955733bbe3faa3969308161353c94b')

bad_ecdsa_secp256k1_diff2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_secp256k1_diff2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA512
bad_ecdsa_secp256k1_diff2.ecdsa_sig_info.r = util.Hex2Bytes(
    'c96bc87224f1200754b0cf6b1d287e238cf23d3b12f37570646555b14d44332b')
bad_ecdsa_secp256k1_diff2.ecdsa_sig_info.s = util.Hex2Bytes(
    '2cb7b8ead9d6f8a1b5ed724db16a867736b2728ce77edf58daee59605ce3495a')
bad_ecdsa_secp256k1_diff2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '25ffca8499df94d5725334521f18302f4aace2acf31f50659400cfb7d59e21338974f16127330ae6d371850cfa88c967000e373370068757409050405c5fe31e'
)
bad_ecdsa_secp256k1_diff2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256K1
bad_ecdsa_secp256k1_diff2.issuer_key_info.x = util.Hex2Bytes(
    'c5989f00691851430e62bb903e7cd368b1b4754f281d4bddf2b13bc638cabe66')
bad_ecdsa_secp256k1_diff2.issuer_key_info.y = util.Hex2Bytes(
    'd886c6701ac48c1baae4a647282bd5126b6d1ede0795c07922f813fbadd76693')

bad_ecdsa_sigs = [
    bad_ecdsa_secp256r1_repeat, bad_ecdsa_secp256k1_diff1,
    bad_ecdsa_secp256k1_diff2
]

# Signatures vulnerable to Cr50 U2F.
# Only one signature vulnerable to Cr50 U2F, but private key also weak:
bad_ecdsa_cr50u2f_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_cr50u2f_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_cr50u2f_1.ecdsa_sig_info.r = util.Hex2Bytes(
    '5ca7141be13da0837eb8cd51ca37da75d16fed96baaa85cc9b13e76e0c509a84')
bad_ecdsa_cr50u2f_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'dd3b20d56a95b4261c334e0f114031e7a2a8e561f666e478398000e3347994b7')
bad_ecdsa_cr50u2f_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25')
bad_ecdsa_cr50u2f_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_cr50u2f_1.issuer_key_info.x = util.Hex2Bytes(
    '6c45b2166cd815d15c59183e25f35a040ae2e5552ac73f04f7cabcbad416ed18')
bad_ecdsa_cr50u2f_1.issuer_key_info.y = util.Hex2Bytes(
    'e926a54e84941b840e27a43c4f3eb9d420bc514f13be9891ea0b4703e1d32c7f')

# Two signatures vulnerable to Cr50 U2F and not weak private key:
bad_ecdsa_cr50u2f_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_cr50u2f_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_cr50u2f_2.ecdsa_sig_info.r = util.Hex2Bytes(
    'a6e80644b57c7317643585d50b41cb953df438afc142cb59ba710f19ca638525')
bad_ecdsa_cr50u2f_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '9321c03820e6f26a00085f58049754afddc38fa2d9487af06cf4dad9806c7454')
bad_ecdsa_cr50u2f_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25')
bad_ecdsa_cr50u2f_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_cr50u2f_2.issuer_key_info.x = util.Hex2Bytes(
    '483f84884a9d14785b7baccb260572cab055548f3b717ce674188077361fc562')
bad_ecdsa_cr50u2f_2.issuer_key_info.y = util.Hex2Bytes(
    'a8fe08b031ef8716cbe858d17be56fe4c2891af824ed595c89d42e8a04adab2a')

bad_ecdsa_cr50u2f_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_cr50u2f_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_cr50u2f_3.ecdsa_sig_info.r = util.Hex2Bytes(
    'fd686c417357e743451d27b40032c95084dadeff96c5b1c8a94479731f87bf8c')
bad_ecdsa_cr50u2f_3.ecdsa_sig_info.s = util.Hex2Bytes(
    'bf8bfd0be715b3869c5c843744cc4a85828ab7e63f82a94aed53fc61e188e4cc')
bad_ecdsa_cr50u2f_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25')
bad_ecdsa_cr50u2f_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_cr50u2f_3.issuer_key_info.x = util.Hex2Bytes(
    '483f84884a9d14785b7baccb260572cab055548f3b717ce674188077361fc562')
bad_ecdsa_cr50u2f_3.issuer_key_info.y = util.Hex2Bytes(
    'a8fe08b031ef8716cbe858d17be56fe4c2891af824ed595c89d42e8a04adab2a')

bad_ecdsa_cr50u2f = [
    bad_ecdsa_cr50u2f_1,
    bad_ecdsa_cr50u2f_2,
    bad_ecdsa_cr50u2f_3,
    # Make sure bad deterministic ECDSA are also flagged:
    copy.deepcopy(bad_ecdsa_cr50u2f_1),
]

# Three signatures with nonces generated using GMP LCG.
bad_ecdsa_lcg_gmp_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_gmp_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_gmp_1.ecdsa_sig_info.r = util.Hex2Bytes(
    '535aaff5af8a8ef37a6ee5d0f16d10a37a67be097994c514201e377ff47e0cdb')
bad_ecdsa_lcg_gmp_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'a3ec962f1654f94293c290c66c8d8a329c9a97e7c7b52d52a29e587776f5b35f')
bad_ecdsa_lcg_gmp_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937')
bad_ecdsa_lcg_gmp_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_gmp_1.issuer_key_info.x = util.Hex2Bytes(
    '797e0130410125e55b89154dbf90e5af10bf598699b1ea4f362c9da67f5ffe66')
bad_ecdsa_lcg_gmp_1.issuer_key_info.y = util.Hex2Bytes(
    'f0b047a184a7b3a7d1164cedd34afce21ba3c82b063bcbbf7aec847ec7d47ffc')

bad_ecdsa_lcg_gmp_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_gmp_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_gmp_2.ecdsa_sig_info.r = util.Hex2Bytes(
    'b4dd3d032329e61c52c68f9b47e40126350fb3032f8aa4d1d0fda6556d33c902')
bad_ecdsa_lcg_gmp_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '0b91e152f7192d2c40e4300e45a3854ef27055847f0b80d0a162538169e20cfa')
bad_ecdsa_lcg_gmp_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '221f8af2372a95064f2ef7d7712216a9ab46e7ef98482fd237e106f83eaa7569')
bad_ecdsa_lcg_gmp_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_gmp_2.issuer_key_info.x = util.Hex2Bytes(
    '797e0130410125e55b89154dbf90e5af10bf598699b1ea4f362c9da67f5ffe66')
bad_ecdsa_lcg_gmp_2.issuer_key_info.y = util.Hex2Bytes(
    'f0b047a184a7b3a7d1164cedd34afce21ba3c82b063bcbbf7aec847ec7d47ffc')

bad_ecdsa_lcg_gmp_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_gmp_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_gmp_3.ecdsa_sig_info.r = util.Hex2Bytes(
    '2be359a5bb40508945a8cb1c0c1ee19b431882114d048aac4598dc2ee259b763')
bad_ecdsa_lcg_gmp_3.ecdsa_sig_info.s = util.Hex2Bytes(
    'a984343511eef74d335924aec1840868161ae7bc32986d01349c0b87e626c427')
bad_ecdsa_lcg_gmp_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'b253668f6b59f1ff28522831931e4d3c5a3de533965af22e961735437c0172cb')
bad_ecdsa_lcg_gmp_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_gmp_3.issuer_key_info.x = util.Hex2Bytes(
    '797e0130410125e55b89154dbf90e5af10bf598699b1ea4f362c9da67f5ffe66')
bad_ecdsa_lcg_gmp_3.issuer_key_info.y = util.Hex2Bytes(
    'f0b047a184a7b3a7d1164cedd34afce21ba3c82b063bcbbf7aec847ec7d47ffc')

bad_ecdsa_lcg_gmp = [
    bad_ecdsa_lcg_gmp_1, bad_ecdsa_lcg_gmp_2, bad_ecdsa_lcg_gmp_3
]

# Three signatures with nonces generated using Java Util Random LCG.
bad_ecdsa_lcg_java_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_java_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_java_1.ecdsa_sig_info.r = util.Hex2Bytes(
    'b6a5ee458eaaf322d37117744fe2f422c30268192270cadb6a1bbcadd63b223f')
bad_ecdsa_lcg_java_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'ab218e3a45929bb6ee9e12d1ecdf17cf52b7812e8499def0d75d904915dfda14')
bad_ecdsa_lcg_java_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3')
bad_ecdsa_lcg_java_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_java_1.issuer_key_info.x = util.Hex2Bytes(
    '82056f3bf133f052b2f3ec301ac57e5b68565e51a62fdf1983591714b3b89569')
bad_ecdsa_lcg_java_1.issuer_key_info.y = util.Hex2Bytes(
    '5610988596a7585440315ab7e72453bfcded480d1861caa2ea4988ccf507c710')

bad_ecdsa_lcg_java_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_java_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_java_2.ecdsa_sig_info.r = util.Hex2Bytes(
    '1fbac2cccfbe1fa5a0bb8c9090dcfdee5c0c5b9f4258fbee0ac57638b59c419e')
bad_ecdsa_lcg_java_2.ecdsa_sig_info.s = util.Hex2Bytes(
    'ae22afa10de7c86918731055ca6149ecef32ec5f1c53c1e737f6c4db38dd3d6e')
bad_ecdsa_lcg_java_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937')
bad_ecdsa_lcg_java_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_java_2.issuer_key_info.x = util.Hex2Bytes(
    '82056f3bf133f052b2f3ec301ac57e5b68565e51a62fdf1983591714b3b89569')
bad_ecdsa_lcg_java_2.issuer_key_info.y = util.Hex2Bytes(
    '5610988596a7585440315ab7e72453bfcded480d1861caa2ea4988ccf507c710')

bad_ecdsa_lcg_java_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_java_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_java_3.ecdsa_sig_info.r = util.Hex2Bytes(
    'f06791ad83a55bd11329a1c846b34848c45973a4463e782f20ef5a3b529fd918')
bad_ecdsa_lcg_java_3.ecdsa_sig_info.s = util.Hex2Bytes(
    'c26955f6e295eea96ce5e4b9695da10464abc1f0e107523cade43738d7019cd3')
bad_ecdsa_lcg_java_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '221f8af2372a95064f2ef7d7712216a9ab46e7ef98482fd237e106f83eaa7569')
bad_ecdsa_lcg_java_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_java_3.issuer_key_info.x = util.Hex2Bytes(
    '82056f3bf133f052b2f3ec301ac57e5b68565e51a62fdf1983591714b3b89569')
bad_ecdsa_lcg_java_3.issuer_key_info.y = util.Hex2Bytes(
    '5610988596a7585440315ab7e72453bfcded480d1861caa2ea4988ccf507c710')

bad_ecdsa_lcg_java = [
    bad_ecdsa_lcg_java_1, bad_ecdsa_lcg_java_2, bad_ecdsa_lcg_java_3
]

# Three signatures with nonces under 2^160 taken from cryptohack.org
# "No Random, No Bias" challenge. Bias.MSB is able to solve it.
bad_ecdsa_msb_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_msb_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_msb_1.ecdsa_sig_info.r = util.Hex2Bytes(
    '91f66ac7557233b41b3044ab9daf0ad891a8ffcaf99820c3cd8a44fc709ed3ae')
bad_ecdsa_msb_1.ecdsa_sig_info.s = util.Hex2Bytes(
    '1dd0a378454692eb4ad68c86732404af3e73c6bf23a8ecc5449500fcab05208d')
bad_ecdsa_msb_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'd94a29716364d9e8b67c411ee9357dd876370192')
bad_ecdsa_msb_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_msb_1.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_msb_1.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_msb_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_msb_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_msb_2.ecdsa_sig_info.r = util.Hex2Bytes(
    'e8875e56b79956d446d24f06604b7705905edac466d5469f815547dea7a3171c')
bad_ecdsa_msb_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '582ecf967e0e3acf5e3853dbe65a84ba59c3ec8a43951bcff08c64cb614023f8')
bad_ecdsa_msb_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '154004551a71cf1b3516d15fe385a7fcd02cbf44')
bad_ecdsa_msb_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_msb_2.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_msb_2.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_msb_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_msb_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_msb_3.ecdsa_sig_info.r = util.Hex2Bytes(
    '566ce1db407edae4f32a20defc381f7efb63f712493c3106cf8e85f464351ca6')
bad_ecdsa_msb_3.ecdsa_sig_info.s = util.Hex2Bytes(
    '9e4304a36d2c83ef94e19a60fb98f659fa874bfb999712ceb58382e2ccda26ba')
bad_ecdsa_msb_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '8e30d6aac813417d581bd798bb4422107881ac34')
bad_ecdsa_msb_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_msb_3.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_msb_3.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_msb = [bad_ecdsa_msb_1, bad_ecdsa_msb_2, bad_ecdsa_msb_3]

# Bias.COMMON_PREFIX needs two more signatures.
bad_ecdsa_common_prefix_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_prefix_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_common_prefix_1.ecdsa_sig_info.r = util.Hex2Bytes(
    'd15473271f9caebc8c7a4a9d57e35ab5d852ae57939ef55768a27c2eb3ff1c28')
bad_ecdsa_common_prefix_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'b32d96b7ff5ab009979836a0442b94f4c4cc0cbab7618d3b8d9df6a5b8660b55')
bad_ecdsa_common_prefix_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0')
bad_ecdsa_common_prefix_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_prefix_1.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_prefix_1.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_prefix_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_prefix_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_common_prefix_2.ecdsa_sig_info.r = util.Hex2Bytes(
    '3b2e11aa616736aa99782b4dc1df7d4fe9d97c78d925b29efb6b9c1fcc9e250e')
bad_ecdsa_common_prefix_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '22679be92f008d2d76ae06a3d46802be6108bfc7e955256cd786b2d54f59c1ae')
bad_ecdsa_common_prefix_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0')
bad_ecdsa_common_prefix_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_prefix_2.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_prefix_2.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_prefix = [
    bad_ecdsa_common_prefix_1, bad_ecdsa_common_prefix_2
] + bad_ecdsa_msb

# Five signatures in which only the 160 most significant bits of the nonces are
# set. The 96 least significant bits are 0.
bad_ecdsa_common_postfix_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_1.ecdsa_sig_info.r = util.Hex2Bytes(
    'bb2924c21aa5d7c683c0c7809f8d378e519fd67a55e8bfe612ac17072bb3e62b')
bad_ecdsa_common_postfix_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'e8bea721d4e68a2b4063d4c4175718807dd520fb8f61791dce9a632743bd012b')
bad_ecdsa_common_postfix_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_1.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_1.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_2.ecdsa_sig_info.r = util.Hex2Bytes(
    'eadf63e84ef38d69be0524355b6e7de025081b0de18c6db95f583c6133873946')
bad_ecdsa_common_postfix_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '5c3145f4f8c438e26a55c7011a17fa6126c89d18504afac863f560305d8f56c1')
bad_ecdsa_common_postfix_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_2.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_2.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_3.ecdsa_sig_info.r = util.Hex2Bytes(
    '8f9fecb4d780d97813431fd75551bca15c6d891904d8df2ccbe1b665264317e2')
bad_ecdsa_common_postfix_3.ecdsa_sig_info.s = util.Hex2Bytes(
    '74551e947c523d1f482caf86a3e6f048654c03e285a1bf9d05a4e6bc4ebc7458')
bad_ecdsa_common_postfix_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_3.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_3.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix_4 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_4.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_4.ecdsa_sig_info.r = util.Hex2Bytes(
    '11b717242f3b597bb8fbd89d4eb6d6dae5d096055569f242f8d5bc37bb070b98')
bad_ecdsa_common_postfix_4.ecdsa_sig_info.s = util.Hex2Bytes(
    '1babb0143b1ec8738b0bc333b8aa97221da68b914fff3752d5009fc98135c77a')
bad_ecdsa_common_postfix_4.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_4.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_4.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_4.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix_5 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_5.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_5.ecdsa_sig_info.r = util.Hex2Bytes(
    'db5ca2cb8362d231c120e8b370942d1d9d193bba5d1c33374b74bc230e52b7a9')
bad_ecdsa_common_postfix_5.ecdsa_sig_info.s = util.Hex2Bytes(
    'cdf5818a45fd641048b3cc1a175c33dadff504c4067eb046b3de3a8b93a94dca')
bad_ecdsa_common_postfix_5.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_5.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_5.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_5.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix = [
    bad_ecdsa_common_postfix_1, bad_ecdsa_common_postfix_2,
    bad_ecdsa_common_postfix_3, bad_ecdsa_common_postfix_4,
    bad_ecdsa_common_postfix_5
]

# Six signatures in which only the 16 most and 16 least significant bits are
# set. The 224 bits in the middle are 0.
bad_ecdsa_generalized_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_1.ecdsa_sig_info.r = util.Hex2Bytes(
    '3a0483f59d861f7d9afd3e8920adf2a85430328c667aadb6925863111783df78')
bad_ecdsa_generalized_1.ecdsa_sig_info.s = util.Hex2Bytes(
    '6cff07783722b3eea2a677868cf10568729f3907ccaaf5fced065141e5b43a83')
bad_ecdsa_generalized_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_1.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_1.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_2.ecdsa_sig_info.r = util.Hex2Bytes(
    '35b9c68ae198390cfacd630e324d2b28cfecb430a322dfde8ead3ff0d39304e3')
bad_ecdsa_generalized_2.ecdsa_sig_info.s = util.Hex2Bytes(
    'b774d673125c78aeb1cdac1bcbdef7e8f9f1cf936db8b5c0ed539f56c61a1e2c')
bad_ecdsa_generalized_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_2.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_2.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_3.ecdsa_sig_info.r = util.Hex2Bytes(
    '55d30183bef6973072673ba51fed05a6390887d85080c75bf533b11c70f6cc25')
bad_ecdsa_generalized_3.ecdsa_sig_info.s = util.Hex2Bytes(
    'e89f6671bc0710df60f6a36ee02f864eb2bf0744ca0a91df94c661780d7f0827')
bad_ecdsa_generalized_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_3.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_3.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_4 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_4.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_4.ecdsa_sig_info.r = util.Hex2Bytes(
    '1b829d3c8832095946d91ee8ef489f0e1d298a3390beb7368ea59df08de3ce05')
bad_ecdsa_generalized_4.ecdsa_sig_info.s = util.Hex2Bytes(
    '7050d267a0a893e3e3fb2b3ee6fbab706f53167acdade061feb8ea8f1cfa9672')
bad_ecdsa_generalized_4.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_4.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_4.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_4.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_5 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_5.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_5.ecdsa_sig_info.r = util.Hex2Bytes(
    'bc4849992ba5459a1e54cbc6c7cb23de488100b86643f630b74afba5b3d6399')
bad_ecdsa_generalized_5.ecdsa_sig_info.s = util.Hex2Bytes(
    '723aa14c7e9b3ef6619d41fa67cde2d936a098484053b04b3356aeeec4dfd9a7')
bad_ecdsa_generalized_5.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_5.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_5.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_5.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_6 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_6.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_6.ecdsa_sig_info.r = util.Hex2Bytes(
    'cd354e94ba3e33d2a5af655ae4784ea4d5e5907eacb86e7f25b753b065ae96b2')
bad_ecdsa_generalized_6.ecdsa_sig_info.s = util.Hex2Bytes(
    'c84e185b7986543f8d1bed40bb6264ff781211239a7bfdf295eb91c84cfca123')
bad_ecdsa_generalized_6.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_6.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_6.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_6.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized = [
    bad_ecdsa_generalized_1,
    bad_ecdsa_generalized_2,
    bad_ecdsa_generalized_3,
    bad_ecdsa_generalized_4,
    bad_ecdsa_generalized_5,
    bad_ecdsa_generalized_6,
    # Make sure bad deterministic ECDSA are also flagged:
    copy.deepcopy(bad_ecdsa_generalized_1),
]

# Trick to replace CheckECKeySmallDifference default max_diff (tests run faster)
ec_aggregate_checks.CheckECKeySmallDifference.__init__.__defaults__ = (2**8,)


class ParanoidECDSATest(paranoid_base_test.ParanoidBaseTest):

  def testCheckIssuerKey(self):
    check = ecdsa_sig_checks.CheckIssuerKey()
    self.assertTrue(check.Check(bad_ecdsa_sigs))
    self.assertResults(bad_ecdsa_sigs, check.check_name, True)

    # Assert severities now are the same of the failed key checks
    self.assertSeverities([bad_ecdsa_secp256r1_repeat], check.check_name,
                          paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    self.assertSeverities(
        [bad_ecdsa_secp256k1_diff1, bad_ecdsa_secp256k1_diff2],
        check.check_name, paranoid_pb2.SeverityType.SEVERITY_HIGH)

  def testCheckCr50U2f(self):
    check = ecdsa_sig_checks.CheckCr50U2f()
    self.assertTrue(check.Check(bad_ecdsa_cr50u2f))
    self.assertResults(bad_ecdsa_cr50u2f, check.check_name, True)

  def testCheckLCGNonceGMP(self):
    check = ecdsa_sig_checks.CheckLCGNonceGMP()
    self.assertTrue(check.Check(bad_ecdsa_lcg_gmp))
    self.assertResults(bad_ecdsa_lcg_gmp, check.check_name, True)

  def testCheckLCGNonceJavaUtilRandom(self):
    check = ecdsa_sig_checks.CheckLCGNonceJavaUtilRandom()
    self.assertTrue(check.Check(bad_ecdsa_lcg_java))
    self.assertResults(bad_ecdsa_lcg_java, check.check_name, True)

  def testCheckNonceMSB(self):
    check = ecdsa_sig_checks.CheckNonceMSB()
    self.assertTrue(check.Check(bad_ecdsa_msb))
    self.assertResults(bad_ecdsa_msb, check.check_name, True)

  def testCheckNonceCommonPrefix(self):
    check = ecdsa_sig_checks.CheckNonceCommonPrefix()
    self.assertTrue(check.Check(bad_ecdsa_common_prefix))
    self.assertResults(bad_ecdsa_common_prefix, check.check_name, True)

  def testCheckNonceCommonPostfix(self):
    check = ecdsa_sig_checks.CheckNonceCommonPostfix()
    self.assertTrue(check.Check(bad_ecdsa_common_postfix))
    self.assertResults(bad_ecdsa_common_postfix, check.check_name, True)

  def testCheckNonceGeneralized(self):
    check = ecdsa_sig_checks.CheckNonceGeneralized()
    self.assertTrue(check.Check(bad_ecdsa_generalized))
    self.assertResults(bad_ecdsa_generalized, check.check_name, True)

  def testCheckAllECDSASigs(self):
    self.assertFalse(paranoid.CheckAllECDSASigs(good_ecdsa_sigs))
    for ecdsa_check_name in paranoid.GetECDSAAllChecks():
      self.assertResults(good_ecdsa_sigs, ecdsa_check_name, False)


if __name__ == '__main__':
  absltest.main()
