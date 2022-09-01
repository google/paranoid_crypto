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
"""Module containing Paranoid checks on group of EC keys by aggregation."""

from absl import logging
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import base_check
from paranoid_crypto.lib import consts
from paranoid_crypto.lib import ec_util
from paranoid_crypto.lib import util


class CheckECKeySmallDifference(base_check.ECKeyCheck):
  """Checks if the difference of two private keys is small.

  This check does not find discrete logarithms. It merely finds relations
  between key pairs. However, finding such a relation indicates that the key
  generation, that generated the keys is badly broken.
  """

  def __init__(self, max_diff: int = 2**24):
    """CheckECKeySmallDifference check constructor.

    Args:
      max_diff: an upper bound on the difference between two private keys.
    """
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_HIGH)
    self._max_diff = max_diff

  def Check(self, artifacts: list[paranoid_pb2.ECKey]) -> bool:
    any_weak = False
    for curve_id, curve in ec_util.CURVE_FACTORY.items():
      if curve is None:
        continue
      # Generate a batch of keys using the same curve, since this check is
      # significantly faster when keys are checked in batches, rather than
      # individually.
      keys = [key for key in artifacts if key.ec_info.curve_type == curve_id]
      points = [ec_util.PublicPoint(key.ec_info) for key in keys]
      result = curve.BatchDLOfDifferences(points, max_diff=self._max_diff)
      for i, key in enumerate(keys):
        test_result = self._CreateTestResult()
        if result[i] is not None:
          logging.warning("Keys with small difference found: %s %s", result[i],
                          key.ec_info)
          util.AttachInfo(key.test_info, consts.INFO_NAME_DISCRETE_LOG_DIFF,
                          result[i])
          any_weak = True
          test_result.result = True
        util.SetTestResult(key.test_info, test_result)
    return any_weak
