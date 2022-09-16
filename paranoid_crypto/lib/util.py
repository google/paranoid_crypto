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
"""Set of functions that are useful for paranoid library or its callers."""
import ast
from collections.abc import Iterable
from typing import Optional
from paranoid_crypto import paranoid_pb2
from paranoid_crypto import version


def Hex2Bytes(hexstr_val: str) -> bytes:
  if len(hexstr_val) % 2 != 0:
    return bytes.fromhex('0' + hexstr_val)
  return bytes.fromhex(hexstr_val)


def Bytes2Int(bytes_val: bytes) -> int:
  return int.from_bytes(bytes_val, 'big')


def Int2Bytes(int_val: int) -> bytes:
  return int.to_bytes(int(int_val), (int_val.bit_length() + 7) // 8, 'big')


def GetHighestSeverity(test_info: paranoid_pb2.TestInfo) -> Optional[int]:
  """Returns the highest severity from all failed tests stored in test_info.

  Args:
    test_info: An instance of paranoid_pb2.TestInfo protobuf, where the highest
      severity will be pulled out.

  Returns:
    An instance of paranoid_pb2.SeverityType if a failed test test exists, None
    otherwise.
  """
  highest_severity = -1
  for test_result in test_info.test_results:
    if test_result.result and test_result.severity > highest_severity:
      highest_severity = test_result.severity
  return highest_severity if highest_severity != -1 else None


def GetTestResult(test_info: paranoid_pb2.TestInfo,
                  test_name: str) -> Optional[paranoid_pb2.TestResultsEntry]:
  """Resturns a test result stored in test_info with name test_name.

  Args:
    test_info: An instance of paranoid_pb2.TestInfo protobuf, where a test
      result will be pulled out.
    test_name: A string containing the test name to be pulled out.

  Returns:
    An instance of paranoid_pb2.TestResultsEntry if a test with test_name
    exists, None
    otherwise.
  """
  for test_result in test_info.test_results:
    if test_result.test_name == test_name:
      return test_result
  return None


def SetTestResult(test_info: paranoid_pb2.TestInfo,
                  test_result: paranoid_pb2.TestResultsEntry):
  """Adds or updates test results in a paranoid_pb2.TestInfo protobuf.

  Args:
    test_info: An instance of paranoid_pb2.TestInfo protobuf, where test_results
      attribute will be modified to store a test_result and paranoid_lib_version
      attribute will reflect the current library version that ran the tests.
    test_result: An instance of paranoid_pb2.TestResultsEntry, to be
      stored/updated in test_info.
  """
  if not test_info.paranoid_lib_version:
    # Stores version value in test_info. As checks can be updated and become
    # stronger, this attribute can be useful to know when it makes sense to
    # re-execute a check against a crypto artifact.
    test_info.paranoid_lib_version = version.__version__

  if test_result.result:
    # When a key/signature is vulnerable to at least one test,
    # paranoid_pb2.TestInfo.weak should reflect that. We never set it to False,
    # as unknown weaknesses may exist.
    test_info.weak = True

  old_test_result = GetTestResult(test_info, test_result.test_name)
  if old_test_result:
    old_test_result.result |= test_result.result  # update
    old_test_result.severity = max(old_test_result.severity,
                                   test_result.severity)
  else:
    test_info.test_results.append(test_result)  # add new


def GetAttachedInfo(test_info: paranoid_pb2.TestInfo,
                    info_name: str) -> Optional[paranoid_pb2.AttachedInfoEntry]:
  """Resturns an info stored in test_info.attached_info with info_name.

  Args:
    test_info: An instance of paranoid_pb2.TestInfo protobuf, where an attached
      info will be pulled out.
    info_name: A string containing the name of the info to be pulled out.

  Returns:
    An instance of paranoid_pb2.AttachedInfoEntry if an info with info_name
      exists, None otherwise.
  """
  for attached_info in test_info.attached_info:
    if attached_info.info_name == info_name:
      return attached_info
  return None


def AttachInfo(test_info: paranoid_pb2.TestInfo, info_name: str, value: str):
  """Attachs a test result information in a paranoid_pb2.TestInfo protobuf.

  Args:
    test_info: An instance of paranoid_pb2.TestInfo protobuf, where
      attached_info attribute will be modified to store the passed info.
    info_name: The value to be stored in
      paranoid_pb2.AttachedInfoEntry.info_name.
    value: The value to be stored in paranoid_pb2.AttachedInfoEntry.value.
  """
  old_attached_info = GetAttachedInfo(test_info, info_name)
  if old_attached_info:
    old_attached_info.value = value  # update
  else:
    attached_info = test_info.attached_info.add()  # add new
    attached_info.info_name = info_name
    attached_info.value = value


def GetAttachedFactors(test_info: paranoid_pb2.TestInfo,
                       info_name: str) -> Optional[set[int]]:
  """Resturns a set of factors stored in test_info.attached_info with info_name.

  Args:
    test_info: An instance of paranoid_pb2.TestInfo protobuf, where a set of
      factors is stored.
    info_name: A string containing the name of the set of factors to be pulled
      out.

  Returns:
    A set of factors if an entry with info_name exists, None otherwise.
  """
  attached_info = GetAttachedInfo(test_info, info_name)
  if attached_info:
    factors_hex = ast.literal_eval(attached_info.value)
    return {int(f_hex, 16) for f_hex in factors_hex}
  return None


def AttachFactors(test_info: paranoid_pb2.TestInfo, info_name: str,
                  factors: Iterable[int]):
  """Attachs a set of factors in test_info.attached_info with info_name.

  If the set factors does not exist yet, it creates a new one. If the set
  exists, it is updated (e.g., new factors are added). Consistency is not
  critical and it does not contain any logic. If one first attachs {2, 3} and
  {6} later, the final set will be {2, 3, 6}, i.e., it does not recognize that
  they are the same. Also, it does not store repeated values. E.g., factors of
  12 may be stored as {2, 3}, not [2, 2, 3].

  Args:
    test_info: An instance of paranoid_pb2.TestInfo protobuf, where
      attached_info attribute will be modified to store the set of factors.
    info_name: The info name to store the set of factors.
    factors: A set of factors to be stored.
  """
  factors = set(factors)
  old_set = GetAttachedFactors(test_info, info_name)
  if old_set:
    factors = factors.union(old_set)  # update
  new_set = {format(int(f), 'x') for f in factors}
  AttachInfo(test_info, info_name, str(new_set))
