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
"""This module contains an example of testing EC public keys.

The individual checks are implemented in paranoid_crypto/lib. This module is
essentially just one way to call these checks. The unit tests at
paranoid_crypto/lib/paranoid_ec_test.py contains more detailed examples
including how to call checks individually (this module assumes one wants to run
all checks against a collection of public keys).
"""

import cProfile
from absl import app
from absl import flags
from absl import logging
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import paranoid
from paranoid_crypto.lib import util

_PROF = flags.DEFINE_bool("prof", None,
                          "generates a simple profile using cProfile")

# Below are examples of public numbers of EC keys. There are multiple ways of
# extracting such numbers. For example, given a file containing a PEM encoded
# x.509 certificate, one can extract the public key numbers using Python
# cryptography module:
#
# >>> from cryptography import x509
# >>> cert = x509.load_pem_x509_certificate(open('cert.pem', 'rb').read())
# >>> print(cert.public_key().public_numbers())
#
# Libraries in other languages or openssl command have similar methods.

# A good EC key:
ec_key1 = paranoid_pb2.ECKey()
ec_key1.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
ec_key1.ec_info.x = util.Int2Bytes(
    68376341805794046444782496341758399409197661936828402059185855351508654361155
)
ec_key1.ec_info.y = util.Int2Bytes(
    109717552634937791513516143050802739596889366187105089664689495129806564693793
)

# An EC key with small private key (CheckWeakECPrivateKey detects it).
ec_key2 = paranoid_pb2.ECKey()
ec_key2.ec_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
ec_key2.ec_info.x = util.Int2Bytes(
    13040496420351431967353806248946694530757375752783261229448551880409253428398
)
ec_key2.ec_info.y = util.Int2Bytes(
    85012676448399380707053036413383820341960369760555239618278331775810266338409
)

ec_keys = [ec_key1, ec_key2]

# Sample output
# ------------------------
# $ python3 ec_public_keys.py
#
# -------- Testing 2 EC keys --------
# CheckValidECKey                passed                    (0.00s)
# CheckWeakCurve                 passed                    (0.00s)
# CheckWeakECPrivateKey          failed                    (1.55s)
# CheckECKeySmallDifference      passed                    (33.93s)
# final state: failed
# total time: 35.48s
# -------- Testing 2 EC keys --------
# CheckValidECKey                passed                    (0.00s)
# CheckWeakCurve                 passed                    (0.00s)
# CheckWeakECPrivateKey          failed                    (0.67s)
# CheckECKeySmallDifference      passed                    (0.00s)
# final state: failed
# total time: 0.67s
# Found first key to be potentially weak? False
# Found second key to be potentially weak? True
# Second key is weak to CheckWeakECPrivateKey? True


def main(argv: list[str]) -> None:
  """Examples of testing EC public keys.

  Args:
    argv: command line arguments.
  """
  if len(argv) > 1:
    raise app.UsageError("Too many commandline arguments.")

  # The paranoid_crypto/lib/ec_util.py module computes some large tables for
  # some of the tests. In a first execution these tables take a while to be
  # created. On following executions (e.g., with different or more keys) a cache
  # mechanism is used and the checks are much faster.
  for _ in range(2):
    if _PROF.value:
      with cProfile.Profile() as profile:
        paranoid.CheckAllEC(ec_keys, log_level=1)
      profile.print_stats(sort=1)
    else:
      paranoid.CheckAllEC(ec_keys, log_level=1)

  logging.info("Found first key to be potentially weak? %s",
               ec_key1.test_info.weak)
  logging.info("Found second key to be potentially weak? %s",
               ec_key2.test_info.weak)
  test_res = util.GetTestResult(ec_key2.test_info, "CheckWeakECPrivateKey")
  res = test_res and test_res.result
  logging.info("Second key is weak to CheckWeakECPrivateKey? %s", res)


if __name__ == "__main__":
  app.run(main)
