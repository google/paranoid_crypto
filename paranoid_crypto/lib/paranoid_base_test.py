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
"""Test base class for paranoid_crypto.lib.paranoid_*_test."""
from absl.testing import absltest
from paranoid_crypto.lib import consts
from paranoid_crypto.lib import util


class ParanoidBaseTest(absltest.TestCase):

  def assertFactors(self, keys, delta=0):
    if delta == -1:
      info_name = consts.INFO_NAME_NM1_FACTORS
      # Can be expanded to other values, not only for factors of N and N-1.
    else:
      delta = 0
      info_name = consts.INFO_NAME_N_FACTORS

    for key in keys:
      composed = util.Bytes2Int(key.rsa_info.n) + delta
      factors = util.GetAttachedFactors(key.test_info, info_name)
      self.assertNotEmpty(factors)
      for f in factors:
        self.assertEqual(composed % f, 0)

  def assertResults(self, protos, check_name, weak):
    for proto in protos:
      if weak:
        self.assertTrue(proto.test_info.weak)
      res_entry = util.GetTestResult(proto.test_info, check_name)
      if res_entry is None:
        self.fail('None test result.')
      self.assertEqual(res_entry.result, weak)
      self.assertRegex(
          proto.test_info.paranoid_lib_version,
          r'^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'
      )

  def assertSeverities(self, protos, check_name, severity):
    for proto in protos:
      res_entry = util.GetTestResult(proto.test_info, check_name)
      if res_entry is None:
        self.fail('None test result.')
      self.assertEqual(res_entry.severity, severity)
