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

from absl.testing import absltest
from paranoid_crypto.lib.cc_util.pybind import rsa_batch


def _int_to_be(v: int) -> bytes:
  if v == 0:
    return b""
  return v.to_bytes((v.bit_length() + 7) // 8, "big")


def _be_to_int(b: bytes) -> int:
  return int.from_bytes(b, "big")


class RsaBatchPybindTest(absltest.TestCase):
  """Tests the pybind11 binding for RsaBatchAccumulator."""

  def testSignedBatchAndOtherProd(self):
    acc = rsa_batch.RsaBatchAccumulator(
        chunk_target_bytes=16, chunks_per_superchunk=2, num_threads=2
    )
    vals = [6, 35, 55, 6, -35, 1]
    acc.Reserve(len(vals))
    acc.AddSignedBatch([(v < 0, _int_to_be(abs(v))) for v in vals])
    self.assertEqual(acc.num_inputs(), 6)
    self.assertEqual(acc.num_unique_leaves(), 4)

    gcds = [_be_to_int(b) for b in acc.ComputeAllGcds()]
    self.assertEqual(gcds, [1, 35, 5, 1, 35, 1])

    acc2 = rsa_batch.RsaBatchAccumulator()
    acc2.AddSignedBatch([(False, _int_to_be(v)) for v in range(2, 10)])
    gcds_other = [_be_to_int(b) for b in acc2.ComputeAllGcds(_int_to_be(77))]
    self.assertEqual(gcds_other, [2, 3, 4, 1, 6, 7, 8, 9])

  def testModulusBatchAndFilteredGcds(self):
    acc = rsa_batch.RsaBatchAccumulator()
    acc.AddModulusBatch([
        _int_to_be(101 * 103),
        _int_to_be(101 * 107),
        _int_to_be(109 * 113),
        _int_to_be(109 * 113),
    ])
    hits = acc.ComputeFilteredGcds(b"\x02")
    self.assertEqual(hits, [(0, _int_to_be(101)), (1, _int_to_be(101))])


if __name__ == "__main__":
  absltest.main()
