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
"""This module contains an interface to encapsulates paranoid storage.

A storage contains information that might be useful for running the tests.
"""
import abc
from collections.abc import Set
from absl import flags
from paranoid_crypto.lib.data import data_pb2

FLAGS = flags.FLAGS


class Storage(metaclass=abc.ABCMeta):
  """Abstract class for building a paranoid storage.

  This class contains an interface to access information that might help the
  tests ran by Paranoid library.
  """

  def _FlagIsSetAndTrue(self, flag_name):
    return flag_name in FLAGS and FLAGS[flag_name].value

  @abc.abstractmethod
  def GetUnseededRands(self, size: int) -> Set[int]:
    """Returns size-bit numbers generated with unseeded PRNGs."""

  @abc.abstractmethod
  def GetKeypairData(self) -> data_pb2.KeypairData:
    """Returns a protobuf with a table field used on CVE-2021-41117 detection.

    The table field maps the 64 most significant bits of a modulus into metadata
    with enough information for reconstructing the weak primes. The metadata is
    a sequence of bytes of the form b0|i1|b1|i2|b2...in|bn, where b0 is the
    first byte of the seed (always a value in the range [0-255]) and bn is the
    in-th byte of the seed (always a value in the range [0-9]). The other bytes
    of the seed are assumed to be zero. For example, the seed
    1e00000008000000000000000000000000000000000000000000000002000000 is
    represented by the metadata 1e04081c02.

    Thus, the general formula for computing the probability of detection is:
      pr(n) = sum(comb(31, i)*(prnz**i*prz**(31 - i)) for i in range(n))
    where n is the number of bytes brute forced, prnz is the probability of
    having a non-zero byte (9/256) and prz is the probability of having a zero
    byte (1 - 9/256) on any byte position excluding the first.
    """

  @abc.abstractmethod
  def GetOpensslDenylist(self) -> Set[str]:
    """Returns a set of data used on CVE-2008-0166 detection.

    Each element of the set is a string of the format <keytype>:<h> where h
    is the first 10 bytes of the RSA modulus (as a string) in hex format.
    """
