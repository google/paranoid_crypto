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
"""Utils for loading resources (data files) from paranoid_crypto source tree.

The resources must be data dependencies of the relevant target.

Example usage:

from paranoid_crypto.lib import resources

data_blob = resources.GetParanoidResource(
    'lib/data/weak_keylist.RSA-2048')
"""

import os
from typing import IO, Union

# Absolute path to the root directory holding paranoid_crypto. Resource paths
# are interpreted relative to this path.
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def GetParanoidResourceAsFile(path: str,
                              mode: str = 'r') -> IO[Union[bytes, str]]:
  """Returns a resource as an opened read-only file.

  Args:
    path: Relative path to the resource.
    mode: File open mode.

  Returns:
    Opened read-only file pointing to resource data.

  Raises:
    IOError: If the resource cannot be loaded.
  """
  path = os.path.join(_ROOT_DIR, path)
  if os.path.isdir(path):
    raise IOError('Resource "{}" is not a file'.format(path))
  if not os.path.isfile(path):
    raise IOError(
        'Resource "{}" not found; is it a data dependency?'.format(path))
  return open(path, mode)


def GetParanoidResource(path: str) -> bytes:
  """Returns the content of a resource.

  Args:
    path: Relative path to the resource.

  Returns:
    Raw content of the resource as bytes.

  Raises:
    IOError: If the resource cannot be loaded.
  """
  with GetParanoidResourceAsFile(path, 'rb') as resource_file:
    return resource_file.read()


