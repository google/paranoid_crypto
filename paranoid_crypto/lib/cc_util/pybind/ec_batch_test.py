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

from typing import Any
from absl.testing import absltest
from paranoid_crypto.lib.cc_util.pybind import ec_batch


class EcBatchPybindTest(absltest.TestCase):
  """Tests the pybind11 binding for EcBatchEngine."""

  def _make_p256_engine(self):
    mod = 2**256 - 2**224 + 2**192 + 2**96 - 1
    a = mod - 3
    gx = int(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16
    )
    gy = int(
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16
    )
    eng = ec_batch.EcBatchEngine.Create(
        mod.to_bytes(32, "little"),
        a.to_bytes(32, "little"),
        gx.to_bytes(32, "little"),
        gy.to_bytes(32, "little"),
    )
    self.assertIsNotNone(eng)
    return eng, gx, gy

  def testConstantsAndBasicSolve(self):
    self.assertGreater(ec_batch.MAX_DL_TABLE_SIZE, 0)
    self.assertGreater(ec_batch.DEFAULT_MAX_DIFF_BABY_ENTRIES, 0)
    eng, gx, gy = self._make_p256_engine()
    self.assertEqual(eng.coord_bytes(), 32)
    self.assertEqual(eng.table_size(), 0)

    x2 = int(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978", 16
    )
    y2 = int(
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1", 16
    )
    p1 = b"\x01" + gx.to_bytes(32, "little") + gy.to_bytes(32, "little")
    p2 = b"\x01" + x2.to_bytes(32, "little") + y2.to_bytes(32, "little")

    hits = eng.BatchDL(p1 + p2, 16, 2)
    self.assertEqual(hits, [(0, 1), (1, 2)])
    self.assertGreater(eng.table_size(), 0)

    diff_hits = eng.DiffBatchDL(p1 + p2, b"", 16, 1024)
    self.assertLen(diff_hits, 1)
    self.assertEqual(abs(diff_hits[0][2]), 1)

  def testInvalidCreateReturnsNone(self):
    self.assertIsNone(ec_batch.EcBatchEngine.Create(b"", b"", b"", b""))
    # Even modulus.
    self.assertIsNone(
        ec_batch.EcBatchEngine.Create(
            (1008).to_bytes(2, "little"),
            (0).to_bytes(2, "little"),
            (0).to_bytes(2, "little"),
            (2).to_bytes(2, "little"),
        )
    )

  def testInvalidArgumentsRaise(self):
    eng, _, _ = self._make_p256_engine()
    with self.assertRaises(ValueError):
      eng.BatchDL(b"\x01\x02", 16, 1)
    bad_arg: Any = 12345
    with self.assertRaises(TypeError):
      eng.BatchDL(bad_arg, 16, 1)


if __name__ == "__main__":
  absltest.main()
