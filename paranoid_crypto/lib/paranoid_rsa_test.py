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
"""RSA Tests for paranoid_crypto.lib.paranoid."""

from absl.testing import absltest
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import paranoid
from paranoid_crypto.lib import paranoid_base_test
from paranoid_crypto.lib import util
from paranoid_crypto.lib.paranoid import rsa_aggregate_checks
from paranoid_crypto.lib.paranoid import rsa_single_checks

# Good RSA keys.
good_rsa1 = paranoid_pb2.RSAKey()
good_rsa1.rsa_info.e = util.Hex2Bytes('010001')
good_rsa1.rsa_info.n = util.Hex2Bytes(
    'e9b862b859d9e045506454a00d605bb259892538a137ce65a8a2954bf40ce63d89ee30c796648e5fe4c80f514bf34fec7a7eb70d3189b826215551f0640d3db176c6d955124f8bdcb532c86fd216f8c9ac6f9d1ee772b1e8e2dd40b7c9b0e35ccf8756826782248e6ecc034ad7292957288a40bb529fbbcb227aaeca3db456cb2ce8168ba68f09524ee7972984aff194230adfb490ac623809da50a0a6bcb66f19471ead12755c7743b1c92d73303d6f7808f144097bcd586cd93c7a6ce7f4998b738c8d2b234d6bbb062fda4b6d2a76686862e2d3e964f819fa6b3c3498e4559b76720b54da2e941563aaa82ec296c48ffba1882ee88a3ebffb4731a7e9d899'
)
good_rsa2 = paranoid_pb2.RSAKey()
good_rsa2.rsa_info.e = util.Hex2Bytes('010001')
good_rsa2.rsa_info.n = util.Hex2Bytes(
    'b0e934a77594d3b00131d02181a2d74fb1af33b633a0ff36203aafd81b676f1abd0b1aaa9e608a366cebec5d3afba0b065392f19b62a10763694c7d65856d468177929c2f514b68a686485803cba2147a54336f64a1f04ca1c6899545a117b2d7f08b9850b3f6fc844e99682b6159ba877573e3e6441c16b241b7ea54464d639bc792c8f1c0dc70eef39e4e6a4a324d4cab2146fd88acbe5bc4967efc6f1a75dae1648d531ed20b645027b9458c3be8eb1f7ac0b50cc0f7bcc38dd00c1c91d2d690bc8a74832745830f6f59d495948eaecf9a61face441efe3df965e794b8a2851d02ac6c23ff3effccd8d21bd8be673b1fc18cdf479e464a041e44edadfacb3'
)
good_rsa_keys = [good_rsa1, good_rsa2]

# Has a key with small modulus and non-standard exponent:
bad_rsa_size_exp = paranoid_pb2.RSAKey()
bad_rsa_size_exp.rsa_info.e = util.Hex2Bytes('03')
bad_rsa_size_exp.rsa_info.n = util.Hex2Bytes(
    '011e60c8db2552c7cc86ce5742b77f0fc70ce839ada533c536efd853fe9c08e1fa69c6bb7be2e4baa0a8d7d986dc884f72a69968ebcdd722498c050f5ed9f4027f'
)
bad_rsa_keys_size_exp = [bad_rsa_size_exp]

# Has keys with shared primes and vulnerable to ROCA:
bad_rsa_gcd1 = paranoid_pb2.RSAKey()
bad_rsa_gcd1.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_gcd1.rsa_info.n = util.Hex2Bytes(
    'c2bda848502305ac2a6420f7ac2a8dc6829da3d981daa1a3e738c9059b7fc8a7059cdc740b9baa6392476030b801ef9518d15744a0f63c49e28df680f0c809bb552473e65c449c6acfbc83c657989017345e3b1bd5dff2ba22b197a347e66ea663fde7c68481da0cb5459d4ad749de5e37507d826a2f5b8648abcefa6f92fe4c671a6a1b3d4a5dd0621dbf5d68bf3c50a064389fe213eea5e7c94978308878d297947fe7614db86a83b413cbb2f0495191bdbbfb4a635865575d67b8ecafb69aaac2fe356e571c23aa3e4493aff9a50d98dd49b6ce1ffa284ff7b433aefcbba67b832c767eef5ab50d5c5920a6802ffa06bd53808937820a85f2b7f483fb6e01'
)
bad_rsa_gcd2 = paranoid_pb2.RSAKey()
bad_rsa_gcd2.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_gcd2.rsa_info.n = util.Hex2Bytes(
    '988487d384880336ce459bd6d6e3744ba8e536dd03d3ac7f764afe8e4d44303a97429a142ed0649e7c3095c3048363cc06b1ee1012de216ea60f79b9a123616b456fe4659f9369a5c70e7a2c4982efbcd3e467970b269167541d64d853746f55ba8786b82b6313f4a64fd14d3565b06450f61c45f1a64b4c0e0707fef9e5776c529a659303ec88058235181ec00e461e50845fdfba1054a06e9882d36a2e125e16cf5d91bdaa04f7282dfbb01ed2797885be5706a9ff746637fecf17b87a8ef14c0688c629cf060c4f78228167a9780389617359fac0884d19f81dc324282c33c414cc9f13a86558201838b61d78de475ad87a224c1f4b67dd3d233767cea531'
)
bad_rsa_keys_gcd = [bad_rsa_gcd1, bad_rsa_gcd2]

# Has key vulnerable to ROCA:
bad_rsa_keys_roca = [bad_rsa_gcd1]

# Has a key generated similar to a ROCA key, but with a different base.
bad_rsa_roca_variant = paranoid_pb2.RSAKey()
bad_rsa_roca_variant.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_roca_variant.rsa_info.n = util.Hex2Bytes(
    'c8b3b437c3a3ef522677c796abec5e10eec5151c816ed161f889cab9ec8a99dc6fd8d77237e27d8ccccfeef0d0adaf76e3c73b6752bf1f8b81611c5b36d3cdfef31df051c9ac2a0d8afbedbf06b821a5843ae4241bf0b9c4dce26be912aabd2113a0c3c9a69422375b1d383b4c8ced45702b3b075ac1fc9363b5cf0ebdba1989c54d553702fdd63213631fae5829ab3322449b2193e625b27dd8775f560f360499adbe8c3c08b2e48f757718cdf51e1725ff60b5ced44b9e9ea0e8b5d2c179cf053f5b1dab93a6f85b2193074f994e966e1f8549183213a2220866ddc4b0931fa8f65a7da90de2c8875cbb2ae61cbe23c00a7eb6fa84ebfaa2ba1fe8e05d1121'
)
bad_rsa_keys_roca_variant = [bad_rsa_roca_variant]

# Has keys where p-1, q-1 have the same fixed 512-bit divisor.
bad_rsa_shared_subprime1 = paranoid_pb2.RSAKey()
bad_rsa_shared_subprime1.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_shared_subprime1.rsa_info.n = util.Hex2Bytes(
    '9682d769fa56431a16d6ac8fdf2a2fe16fb1b097e0e59019e85705786f00ae7183066402b83c15ef9e67bbc2fb809e979ed80a46fe245a2634f29a7d6691136aa53f2097f9bff5f209d2471eb5a90ce121e4de4a83bd579fc9be7dbfbd1226d412a10c004a4e72deb5f6dd6dbc13a504cbc495187219f9198efaf008d53014ed17552b05101c720d457f2cc0df95541337fc568b021b14570e7676db58af4026d881278b0c9f55720b65263df5fec4c1d8d3e4c0168596d0bef93799f39f3e39c023895d801a0a78f9fdfdf256094ccff6e323f42c51a337e9276efff25a1dc202a65215022f67bfbf46f7a12f43decdd787c985019630fa065a84ca548ae595'
)
bad_rsa_shared_subprime2 = paranoid_pb2.RSAKey()
bad_rsa_shared_subprime2.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_shared_subprime2.rsa_info.n = util.Hex2Bytes(
    '8931fbf4a4194f05029cc2adf05640fed7485b77b13cfc22036e3ad551348fd08a1374b3f32260df160f78933f462bfe7bab0e51c8b8aec00653befdcb766dc7c30082d2848a195e6ded71cbcb7a7f73bb86cf0e2a13b6dcbcd1d03ad2575da346471d3becc5feff9510c8a3bb0d56a840cc910fec8e47044919fbc5116053622af768e43af3fd29199d3088d0ccbd8090e608af0974713417944cc1832a29e6926eb3f065affad283edb7ba42016acaef539a71702d16f606561291d1d2e655f4652edd21603fbb347cd70835992fd04a0650526b70b179f7b2226c4650ee8243c8f4dca8319e5ef0c8286f92db0bb4f1a8f33d70065ec30e6c643f7981c3e1'
)
bad_rsa_keys_shared_subprime = [
    bad_rsa_shared_subprime1, bad_rsa_shared_subprime2
]

# Has key with small difference between p and q (abs(p-q) < 2**100):
bad_rsa_fermat = paranoid_pb2.RSAKey()
bad_rsa_fermat.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_fermat.rsa_info.n = util.Hex2Bytes(
    'b3a13a8082351d9b01174ec171a9d3c75e6214109a9fa42819c4672d17886bcd687e9a49356d040eec7b1e3b6ce23496ec88f3c558bffc69731c7f8b5cd0e48c209adc502b1ee70eb7bdf6e8b0f00f388748a5df9231bf34389b4d01f64333eb1f3afd70b441799e8b05fc963392f50134dfac33854b6cc99973f94bb357df2293ccb43248181ba5b275e7ae08c8cd6bb8d4dc3a1338c50f8e20dbad1231eefcbfe8ffe4b2481eb8011357367361c558d6edbedfdac0d15f858f75d86adbc64e88ceb131f66bcf09fce1b6751112845c161df9f0e6fe29839457ca02a68e21b82f1e9ee1288e4453dfbca3381fa8d335ed247292d6602258f55c9106ad4b2b1f'
)
bad_rsa_keys_fermat = [bad_rsa_fermat]

# Has a key where the lower half of p and q are equal:
bad_rsa_low_bits_equal = paranoid_pb2.RSAKey()
bad_rsa_low_bits_equal.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_low_bits_equal.rsa_info.n = util.Hex2Bytes(
    'c98630565f334cf66827c3a33259eb3dc239a3c9be315a2f448d7c1faad6954b24486f2471b0eba9d0532db76058a40fbccefdf4257a97456521827ba778f99bce8b0a0683e26dbcfc9f6352e7201ab59e01a934904aafa1911b7ad2877b44c1f6b3d83cf05c0d669bdaf2ea0778d9da6854c1268df4f49bf2288223518a48c6fcefad36a5cfb0de57423ee373a21b302f61712c3ac1f51921099fd358574a780ab95958b2c9eb60e166ee8cf8fa49df767d0742a3b4744933cbc5c3a2a02e0e4b20f29efde1d0e4983dca8b50763f85a6a4a8823010d2538cfd27df656008dc0d016dee6cc24633b3aaa8cd08eb9bfd4a861f12969aabc2ce79e5568e216a29'
)

# Has a key where the 1/4 of the high bits and 1/4 of the low bits of p and q
# are equal:
bad_rsa_high_and_low_bits_equal = paranoid_pb2.RSAKey()
bad_rsa_high_and_low_bits_equal.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_high_and_low_bits_equal.rsa_info.n = util.Hex2Bytes(
    'afdafadf3f3859cec16f1dd68ebeb2ca371302fb919c07b8f130d01da4aa95f692e2848e3e663df9eab71664f21c205c27deab8c2dd3e36b45391b08cc296a8238d03315f41290675b0af87800c0e2a7e3c80a19cad02953c3f8dcebf2609deb2bebf836a4063e966e259043ba94670774fd4006e32d3407bfdcb4944007b4df0ec680df41b4bbf96b69fdefe4cdb21f2ef3311e3302c724bd43785ced3bab595f54e188e8febd2e2fc452d33057148ef30f7240e0c8f9bac4d5851dbbf86d5bfa0ce33625ea7e57f85b043002a8a97e32d3fc7142d2b5a0dec76a103284a726c89095a137b44fc5ef9ad87e4c3c84c0ac2047c74aa24fe2ed97b3c35b8e21e9'
)
bad_rsa_keys_high_and_low_bits_equal = [
    bad_rsa_low_bits_equal, bad_rsa_high_and_low_bits_equal
]

# Has a key vulnerable to Debian OpenSSL Predictable PRNG:
bad_rsa_debian_pprng = paranoid_pb2.RSAKey()
bad_rsa_debian_pprng.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_debian_pprng.rsa_info.n = util.Hex2Bytes(
    'd33c5d6e98b0ea4eab76a60d6a0a7b9c5983c58c0aa1d3c3796958169f27027bac81253fa579c482e884a2e1cef0ca813ec8359e9610d29473ca36d63c1e81a0101a481a3cff58610e8ea72a2a158267d66f4da2866928a23d46e021c5442fdf9e4add6bc5367d3f7722610929511310836e7a77d608b7f191f82419be1187eca184f06651c448ea90478813eb6dc9be53fc6669d31cab638a3f3063d13ccada5b4afa231dcef95486ed5d2d718c30e0ce4ada2ffde1816003f09d183a25ccb2874a57039500e4b6500bab7cd435dc301d19f2c256ae4f837dd2de630e88a652a87c1f2a444224503da97dc3eebbc793e6e5beec631c1ed2788fcb1da10e0af7'
)
bad_rsa_keys_debian_pprng = [bad_rsa_debian_pprng]

# Has a key which is the product of two weak primes:
# Both primes have a small repetitive bit-pattern.
bad_rsa_continued_fractions = paranoid_pb2.RSAKey()
bad_rsa_continued_fractions.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_continued_fractions.rsa_info.n = util.Hex2Bytes(
    'c343ef052c688687dcbbe87d16342db7414eef0554e5414d89246c69563485394f59a3435774eb32843b5dbfe9c029af00e138e46b74ed44d18532b5c746a68a0a5ebd3714ce0e72817a979a357854b99ca4b5a20e8a58e82091ec3c23c8a5c913dab5a4d2ca1a3afc72185290cd6f4dd4293498ae29b1cc644ab0f52c5e1053'
)
bad_rsa_keys_continued_fractions = [bad_rsa_continued_fractions]

# Contains keys where one of the factors is a weak prime.
# The weak primes have a repetitive bit pattern of size, 31 and 63.
bad_rsa_bit_pattern1 = paranoid_pb2.RSAKey()
bad_rsa_bit_pattern1.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_bit_pattern1.rsa_info.n = util.Hex2Bytes(
    'aab71ad63b72f5f4f80931b0b05a03b1b2e9611a781587028d11bd0224cff0b35370d0a081f6c3889aa5c8c150cdc3fe8b0c2c3fe746e1a8eca076031e35d5dd2de27c0f577d64af57349591a3626102dbd834ecd6b9beea9848cc2cfe8a508783446f252a0c8bdb5e367db92d7403805b751a6029573258d4ba9d9494556421'
)
bad_rsa_bit_pattern2 = paranoid_pb2.RSAKey()
bad_rsa_bit_pattern2.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_bit_pattern2.rsa_info.n = util.Hex2Bytes(
    'ca25bf459797f9f43b34727f636e38aff53d4a28e4235681f187f6ca70747b8d50450cdfccbf9d888a4dcaa4297cd7635449e56c0181118c6e474131ccf991fefb56d9f5fe2fd71d8ebc5c1ccfd3e9fe101011c930f49cea62e58b6cef8c6f2af3eb8d3ae953405d1c0aaeb6e1993fb3e1ee911f980651dab7a0b446b2be9857'
)
bad_rsa_keys_bit_pattern = [bad_rsa_bit_pattern1, bad_rsa_bit_pattern2]

# Has a key vulnerable to Pollard's p-1 algorithm:
bad_rsa_pollard_pm1 = paranoid_pb2.RSAKey()
bad_rsa_pollard_pm1.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_pollard_pm1.rsa_info.n = util.Hex2Bytes(
    '05f5de000583d0d3b40c8159954783b696c8f944bbd35dc2864907f21ed8c03f856c3887c3ec32933b3e2b81d504f04f78371ce1ee3087ac156e83c2baab0a5e5097f07a2fca5513733e79c4b661cbe79a74313a27819fed8d49a934e05de6eb0e6bbd881f77bf0ecef4c6682641d00ebb93cca9b6805f06e14d6561853660efa95a506cc42056c929555530f9abb3e4aa28f0c2c395195b172fa51ed732a1899fe896e44bcef66030767409593f6a8733bceca8c813bf173f6641e3512c43cc2503ce39a82d9784f02eaf4bd1a61147c994909b43cfa7dff6db5245d23b93e4230292ee1d6f52a0756d3f21ec5a9944ec554910a2804b800c4ed5cd758cf7d3'
)
bad_rsa_keys_pollard_pm1 = [bad_rsa_pollard_pm1]

# Has keys containing primes generated using PRNGs with faulty seeds:
bad_rsa_unseeded1 = paranoid_pb2.RSAKey()
bad_rsa_unseeded1.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_unseeded1.rsa_info.n = util.Hex2Bytes(
    'b4d680d6b3e1b97f79dc7fdb5abaf32f3e756dc17a5961da11e3fe56a3144bc59864143111cd3d54c19ade89841c6f96a6fb60f27996a04e082af3a3f7fb0534f70d455ee22c820364fdba07950004526641b7af892b5636fad53a19c6806ada005f15ed9aadeb16d78f3a321f39ea8c49bdd1a85472347075d66336f7cb46c923865d9c92af3abb64fd3e067ab0f3594fe435199173c23b751a1b6ce2eb1aca50219f8d613ba4e5b73b2b5e0ee2b66c3301513a2e930d24ec5fb1b86d420cca4742bd6c80330088fde49bfb15bf9fc1f3d6d467ec7f7243a60f7d47d3582d3ab579330e8f7e3f260e983a9f8568ea32e359e677c8943330565ae34aefb59539'
)
bad_rsa_unseeded2 = paranoid_pb2.RSAKey()
bad_rsa_unseeded2.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_unseeded2.rsa_info.n = util.Hex2Bytes(
    'b4556af2d409e80c29023d43872f2bc9fbeada7893bc33e9d50fae4b598e76e668f3c7d57d34ff03976f789e5c15e31be82928ba765419b3c7835870548081b6ad366029475fed7580f6acb26dacf54632b93ff0c99a595a433b1d9341ffbd77ac11634134469e849d91646ca9e112d670d0e3e3791bc6acc2ce3fc04879d13891727acf4e3d946ea0a26e83c090bd3d67d396428433ae53509a255587ee77b8b9757ccfc9ee309daafd9879121a21302e6aba167ab2177333674dde9470a1f1666927292764fa2c7438e4c984fccea2762eff1c7320ec0642240a76d5f3353c4424c173d92c6a2bee151ffb76ab565c7aa900dee3d28925627e9f979743356cfb7fa91f2abd65506f4a7582809d6c2ee65e481fd117739bf8804515905e0a5795966e2e54c52dfdf99fe0c9e0aa71bb991f3db0a28c4321582d02816e28ff4feaf9ca5f1c0a36778d0df6cc50b542a844b1ce8ade9e20ba4ba75c528f723334d528b9b1303697676bc99c94e4f132423883f0ded27c9cb0be6ded802567bc89374b547bacff23237ff810879a357e1807e9876797db128712308a7543093e86ecfde9cf27eaac340b6075ac4ae0581304b8cab13d5c4b09ba64736d3388a786a1b31ef7512877879c99753c5e7d8255ab152c35e8ae18fdae9b3784bb2d9f69a83f617893832a3aabe6ffb2235e14d0b6b954e3478593b8e17140115a7c7511'
)

bad_rsa_keys_unseeded = [bad_rsa_unseeded1, bad_rsa_unseeded2]

# Has a key where one prime factor contains a 7 bit pattern, but with adjacent
# 16-bit words swapped, the other prime is random.
bad_rsa_swaped_pattern = paranoid_pb2.RSAKey()
bad_rsa_swaped_pattern.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_swaped_pattern.rsa_info.n = util.Hex2Bytes(
    'bbebdef198ba2e6a42bec704ba258337121372b62cd8fafd518477b8c08b6491a819e9e53c03b32cd115e9e70ffc918b1c9bd5fd0e511da1c53ce404946fa18ce606c78eef7255b133a08dd25819f1628da9fa552fcc59b1ed091a9d0133194845d4fa10736f05fd8c41d0ce48920f7d2d0f8d9c68298bc2a3be6c7e6de9c553'
)
bad_rsa_keys_swaped_pattern = [bad_rsa_swaped_pattern]

# Has a key where p - q is close to minimum in FIPS PUB 186-4
# That is 2**924 <= q-p <= 2**924 + 2**256
bad_rsa_pq_diff_nist = paranoid_pb2.RSAKey()
bad_rsa_pq_diff_nist.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_pq_diff_nist.rsa_info.n = util.Hex2Bytes(
    'e61c9294ceaecfd491c5287f428ce2b242e72f27510f2c449c7d5cdb498dd3c179f7649e2f7bd0ce0222c3b3bad0f92fba73c55d4f27ec937b722d4da387360025f799686175744868b42a38cad55c254eb1a11b6dba2decaea3c6a407e269c816b90c4c5536021adcea6db65063c0a642abf3b4a2e19cc3bb1c8dd3188d4682c2d906d1bf44af84fe67be3a92d4a8cece8f3eb44b0dab99e74d4dc9db30b927ad348409f71b61733df07dc9959b1d14e573a2c19f511305e522a0715f60cd700e4fea129074abc5c6b689a899d4985ae62362adc5ae335c225e93a8f75a3e017bb4446ab9c0ef9d07d4f896f146c013955890fe97e6cc757d4af9e830536947'
)
bad_rsa_keys_pq_differences = [bad_rsa_pq_diff_nist]

# Has a key where p and q have a Hamming weight of 64.
bad_rsa_low_hamming_weight = paranoid_pb2.RSAKey()
bad_rsa_low_hamming_weight.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_low_hamming_weight.rsa_info.n = util.Hex2Bytes(
    '903300181184c80198d2ab3e01cc5c8efb11b7682db0887315d32fbfad37a9d48cec930aede6995ade5268ee9382c074d36adc4b0582cdce3c20079699ba0aefca3a5d814215a8dcc8b06bcf07e300b82c1f221d50f7de0c2d792b1bd5050f144659ba4621f0180a27ff6d8a2a207f4004a8b81828af29bb3f934ac2fc3ff7a84b8db86be61eaf52fc1ce5375d0092a2a8499e304edd5d2ca2b2748e4469c912c05e2c1eea15d0618f4842c7f1491ada4717a568e6f74d879a9d0d17b339524832a7845e673406fa0758a53049ceffdf5eecba6d9af4ad1087bc82327afcc0d852888a8d5c5bf520b0f6469dde354b7e16d63da82611cf360c18400830482041'
)
bad_rsa_keys_low_hamming_weight = [bad_rsa_low_hamming_weight]

# Has a key where the upper 768 bits of p and q have a Hamming weight of 48.
# The lower 256 bits are unbiased.
bad_rsa_low_hamming_weight_upper = paranoid_pb2.RSAKey()
bad_rsa_low_hamming_weight_upper.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_low_hamming_weight_upper.rsa_info.n = util.Hex2Bytes(
    'a9f70c860001c402007d0be21803024642387997478a5243dd6ad2c1260c7438bf6ca0c64501afb72af0af89518a5d494ad5bef3b95059037e47474519ee38212991bf9c86b099e40b4eb16c86f42d0c95f5f9b79e6b402ca8d73eab4605e1240a3c9f4a05c1c3e10d0ee1de7870aaf084b4b171a1364f990e58ada367e67f8a9720d217fcc538298bebe3a0bf195cd02f32761e165163e7bee651bc7959b3151e013222fb8762dc780328a2cbd87c7e2de65744925d225d3c36f27635fa312381b0499f28fd6e239ec51cbd43f27caa6ec853b5ddcbf01687d047333a6f9aa722ed69e5fb82e924dd852ce209bc74a66de9b38ebe9e653c886a02689e3c2eb7'
)
bad_rsa_keys_low_hamming_weight_upper = [bad_rsa_low_hamming_weight_upper]

# Has keys of sizes 2048, 3072 and 4096, vulnerable to CVE-2021-41117
bad_rsa_keypair1 = paranoid_pb2.RSAKey()
bad_rsa_keypair1.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_keypair1.rsa_info.n = util.Hex2Bytes(
    '9a4a9ecdac4fee003418957246b64e7e945e5af7478cd15091d69ae7602bb2e446eeafa48eaa2861c5ce099b667206b3aa2719f20bd6c7b24c3ff87a1a33474ed03ecbbd2a6eb28d62027148f2c663243afa5069c1a1ab6701b07c667bb49ba1efdf226fa55f0d8150d37499d162e54a8ff7fd970c6c0a0eee7ca37c6835c3a2df4e210e0a683bedca5622f5819ab33220cbc082d0ac3a4e9308941aa05c30725cc1f99a5fa1eb0e2bd10fb2e0387b458aeca2f3cdd0d9d8764bcdf93cbf4b2a33b58d9dd586be9bdde78d2c0abecd9eb45c78c0fae31bac4ad290a0b79acabd6fe34439fbf21d661ea56a04ff49a901db736ae1ac0eae21dbe379914582f8cb'
)
bad_rsa_keypair2 = paranoid_pb2.RSAKey()
bad_rsa_keypair2.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_keypair2.rsa_info.n = util.Hex2Bytes(
    'cce8c62860c8cb3107b1a73403b1b952c006335d7d622ae83f90851c1fc2407491a38c6fe1944100b2d326852f6c647ece651b643a0e2efa632d98d387d6f00f97eda26f300b2edd2ec04254f7f2221edb40953b34784a5d69e9b02568e4a4493506ebd6ddd45cae21f03172381c1166c5d1dcb965c710767fa63289d61eba231df08a9714db1a8ecfd4795caffbdc599205f8c2764e37cacd6348cbbf37bdd49139a89c6708d594409a54307ca6d799b1636210d64bb6c193b711966170b4f23d010e1e70af3a1194a9486f137400dfe4443e988481ff6f158e33751cf710219f39c3ad59807178fd28150f52b9412f5dfae1475779d92701f7767b3fffb6818588cfd08bdfa45ebbf5316f1add2d433cbde7973c0935ffb534d06cd42b676d52e092dfb709730c5eb6703d14c5cfbe7d54334240faed65483394d45d75f197ac5f2784eadcabd975bf1be58de467bf5753aba0438e1e3f9cb76a08b50f72c800403351e9c0bcd60d3180e0811369ea967def8aedc96f66db2e9a1454bcda1f'
)
bad_rsa_keypair3 = paranoid_pb2.RSAKey()
bad_rsa_keypair3.rsa_info.e = util.Hex2Bytes('010001')
bad_rsa_keypair3.rsa_info.n = util.Hex2Bytes(
    'b79f877538f727734b9da0a8febd6b34d8418896d9e94f256dab94a5e8eb5993e71330d582c242763ff243e7592cc964afe67c35df7b583d07b3a8a1d252bcf97da267a11e30d8e882452f3705b934a05a8744f03082ae4d059ca9176470f3eb0c59fa21fc4aea78a4f48a94939a9835f4f878c270df97d94db563421f3fb9bb8dbc28fbaf616b2c4278ac5c9d5906e7ea40f3f6dce778dfdac6b6aa8859fbb9d839a349093b064c6ab95a6cc938d5246c751343b5baea0268204648d419dcaddaa1fe73a5f1134257062e39a870846119c1adf08ff09f3265d8bd056ad4560036b22f7475fb1bb4e18507189b9368781fa5469ba10bfdf3d2fda79c0b36644110011184ad51c9bf314bc7ae3c2eed8c5ccb470796a7696d4edbe35c647987f427314fb0d98e79a43c62af4c03009b05903b39b175b80665a6fef9a4a14bc53bc630de8541a8da40b704721f5247c3409de1b82178970f37fc927e27a4d53b2e6f7377ad569da90f74ab8a67e8cadd18af06023452069e9b5a209992d2eca68ba802f02aec1ebb1e69b33c009f161831b240783c5b90b7bba5b8d6df2e3d655d59f4f737639b384627dafbadce6b618f7146359ca46756e528151b0725a6d862d55e7b03f817f18104fb1327cbb1ad42a34f76111a0d2f5d39423f625d79510145fcdfe3b92d4d78f1ee13cf5dd617489cd6b58b6d6aeb0c34a9115d2adde89b'
)
bad_rsa_keys_keypair = [bad_rsa_keypair1, bad_rsa_keypair2, bad_rsa_keypair3]

good_and_bad_rsa_keys = good_rsa_keys + bad_rsa_keys_size_exp


class ParanoidRSATest(paranoid_base_test.ParanoidBaseTest):

  def testCheckSizes(self):
    check = rsa_single_checks.CheckSizes()
    self.assertTrue(check.Check(bad_rsa_keys_size_exp))
    self.assertResults(bad_rsa_keys_size_exp, check.check_name, True)

  def testCheckExponents(self):
    check = rsa_single_checks.CheckExponents()
    self.assertTrue(check.Check(bad_rsa_keys_size_exp))
    self.assertResults(bad_rsa_keys_size_exp, check.check_name, True)

  def testCheckGCD(self):
    # Weak keys.
    check = rsa_aggregate_checks.CheckGCD()
    self.assertTrue(check.Check(bad_rsa_keys_gcd))
    self.assertResults(bad_rsa_keys_gcd, check.check_name, True)
    self.assertFactors(bad_rsa_keys_gcd)

    # Repeated keys does not flag.
    check = rsa_aggregate_checks.CheckGCD()
    self.assertFalse(check.Check([bad_rsa_gcd1, bad_rsa_gcd1]))
    self.assertTrue(check.Check(bad_rsa_keys_gcd))

  def testCheckGCDN1(self):
    # Weak keys.
    check = rsa_aggregate_checks.CheckGCDN1()
    self.assertTrue(check.Check(bad_rsa_keys_shared_subprime))
    self.assertResults(bad_rsa_keys_shared_subprime, check.check_name, True)
    self.assertFactors(bad_rsa_keys_shared_subprime, delta=-1)
    # Repeated keys does not flag.
    check = rsa_aggregate_checks.CheckGCDN1()
    self.assertFalse(
        check.Check([bad_rsa_shared_subprime1, bad_rsa_shared_subprime1]))
    self.assertTrue(check.Check(bad_rsa_keys_shared_subprime))

  def testCheckROCA(self):
    check = rsa_single_checks.CheckROCA()
    self.assertTrue(check.Check(bad_rsa_keys_roca))
    self.assertResults(bad_rsa_keys_roca, check.check_name, True)

  def testCheckROCAVariant(self):
    check = rsa_single_checks.CheckROCAVariant()
    self.assertTrue(check.Check(bad_rsa_keys_roca_variant))
    self.assertResults(bad_rsa_keys_roca_variant, check.check_name, True)

  def testCheckFermat(self):
    check = rsa_single_checks.CheckFermat()
    self.assertTrue(check.Check(bad_rsa_keys_fermat))
    self.assertResults(bad_rsa_keys_fermat, check.check_name, True)
    self.assertFactors(bad_rsa_keys_fermat)

  def testCheckHighAndLowBitsEqual(self):
    check = rsa_single_checks.CheckHighAndLowBitsEqual()
    self.assertTrue(check.Check(bad_rsa_keys_high_and_low_bits_equal))
    self.assertResults(bad_rsa_keys_high_and_low_bits_equal, check.check_name,
                       True)
    self.assertFactors(bad_rsa_keys_high_and_low_bits_equal)

  def testCheckOpensslDenylist(self):
    check = rsa_single_checks.CheckOpensslDenylist()
    self.assertTrue(check.Check(bad_rsa_keys_debian_pprng))
    self.assertResults(bad_rsa_keys_debian_pprng, check.check_name, True)

  def testCheckContinuedFractions(self):
    check = rsa_single_checks.CheckContinuedFractions()
    self.assertTrue(check.Check(bad_rsa_keys_continued_fractions))
    self.assertResults(bad_rsa_keys_continued_fractions, check.check_name, True)
    self.assertFactors(bad_rsa_keys_continued_fractions)

  def testCheckBitPatterns(self):
    check = rsa_single_checks.CheckBitPatterns()
    self.assertTrue(check.Check(bad_rsa_keys_bit_pattern))
    self.assertResults(bad_rsa_keys_bit_pattern, check.check_name, True)
    self.assertFactors(bad_rsa_keys_bit_pattern)

  def testCheckPollardpm1(self):
    # Using bound instead of estimated m:
    check = rsa_single_checks.CheckPollardpm1(bound=2**20)
    self.assertFalse(check.Check(bad_rsa_keys_pollard_pm1))
    # Using estimated m:
    check = rsa_single_checks.CheckPollardpm1()
    self.assertTrue(check.Check(bad_rsa_keys_pollard_pm1))
    self.assertResults(bad_rsa_keys_pollard_pm1, check.check_name, True)
    self.assertFactors(bad_rsa_keys_pollard_pm1)

  def testCheckPermutedBitPatterns(self):
    check = rsa_single_checks.CheckPermutedBitPatterns()
    self.assertTrue(check.Check(bad_rsa_keys_swaped_pattern))
    self.assertResults(bad_rsa_keys_swaped_pattern, check.check_name, True)
    self.assertFactors(bad_rsa_keys_swaped_pattern)

  def testCheckUnseededRand(self):
    check = rsa_single_checks.CheckUnseededRand()
    self.assertTrue(check.Check(bad_rsa_keys_unseeded))
    self.assertResults(bad_rsa_keys_unseeded, check.check_name, True)
    self.assertFactors(bad_rsa_keys_unseeded)

    # As we can't generated unseeded PRNs for every possible size, we also
    # label keys with uncommon sizes as tested.
    check = rsa_single_checks.CheckUnseededRand()
    self.assertFalse(check.Check(bad_rsa_keys_size_exp))
    self.assertResults(bad_rsa_keys_size_exp, check.check_name, False)

  def testCheckSmallUpperDifferences(self):
    check = rsa_single_checks.CheckSmallUpperDifferences()
    self.assertTrue(check.Check(bad_rsa_keys_pq_differences))
    self.assertResults(bad_rsa_keys_pq_differences, check.check_name, True)
    self.assertFactors(bad_rsa_keys_pq_differences)

  def testCheckLowHammingWeight(self):
    check = rsa_single_checks.CheckLowHammingWeight()
    self.assertTrue(check.Check(bad_rsa_keys_low_hamming_weight))
    self.assertResults(bad_rsa_keys_low_hamming_weight, check.check_name, True)
    self.assertFactors(bad_rsa_keys_low_hamming_weight)

  def testCheckLowHammingWeightUpper(self):
    """Tests keys where the most significant bits have a low Hamming weight.

    CheckLowHammingWeight can detect such keys but cannot factor them.
    Such keys could nonetheless be weak. Such keys could be breakable, e.g.,
    by extending the current search method with Coppersmith in order to find
    the least significant bits.
    """
    check = rsa_single_checks.CheckLowHammingWeight()
    self.assertTrue(check.Check(bad_rsa_keys_low_hamming_weight_upper))
    self.assertResults(bad_rsa_keys_low_hamming_weight_upper, check.check_name,
                       True)
    self.assertSeverities(bad_rsa_keys_low_hamming_weight_upper,
                          check.check_name,
                          paranoid_pb2.SeverityType.SEVERITY_UNKNOWN)

  def testCheckKeypairDenylist(self):
    check = rsa_single_checks.CheckKeypairDenylist()
    self.assertTrue(check.Check(bad_rsa_keys_keypair))
    self.assertResults(bad_rsa_keys_keypair, check.check_name, True)
    self.assertFactors(bad_rsa_keys_keypair)

  def testCheckAllRSA(self):
    self.assertFalse(paranoid.CheckAllRSA(good_rsa_keys))
    for rsa_check_name in paranoid.GetRSAAllChecks():
      self.assertResults(good_rsa_keys, rsa_check_name, False)
    self.assertTrue(paranoid.CheckAllRSA(good_and_bad_rsa_keys))


if __name__ == '__main__':
  absltest.main()
