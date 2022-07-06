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
"""This module contains an example of testing RSA public keys.

The individual checks are implemented in paranoid_crypto/lib. This module is
essentially just one way to call these checks. The unit tests at
paranoid_crypto/lib/paranoid_rsa_test.py contains more detailed examples
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

# Below are examples of public numbers of RSA keys. There are multiple ways of
# extracting such numbers. For example, given a file containing a PEM encoded
# x.509 certificate, one can extract the public key numbers using Python
# cryptography module:
#
# >>> from cryptography import x509
# >>> cert = x509.load_pem_x509_certificate(open('cert.pem', 'rb').read())
# >>> print(cert.public_key().public_numbers())
#
# Libraries in other languages or openssl command have similar methods.

# A good RSA key:
rsa_key1 = paranoid_pb2.RSAKey()
rsa_key1.rsa_info.e = util.Int2Bytes(65537)
rsa_key1.rsa_info.n = util.Int2Bytes(
    29504448997793939629650343267048226035024169803323039856984235143164436377116405585648242893953812854628794784493938998266544625823872934881578719649233060310179425047533108850149523399670885279559084852221003149954769682275504034343043080718685513543881933824539161270145222360915798052827766661367285253480733700285914386841786892590810887106609229089549748539692849449361877254908596044737781529875943958991485773465466111192353343334268469374159716729007439455865060413733452300797645997495419076862247889614333059148236838648895065833376545701094202539822796576082461340703157630893990987421644177019273044678809
)
# A key with small difference between p and q (i.e., weak to CheckFermat):
rsa_key2 = paranoid_pb2.RSAKey()
rsa_key2.rsa_info.e = util.Int2Bytes(65537)
rsa_key2.rsa_info.n = util.Int2Bytes(
    22676161336988655466868945443622502475425608574270738577565082573354793490680411027237198297763856248015612578555726962396114753367995210045231074682128746367058287562699215973445915753672964527368516277163951108138151792646602850138552931121470928807685496652942607180784643475828988826216438732222553317332847027388922192673323268496390001296327254129912624600576885833401909779191141427484710624193414039980157162811613595508814540712546119238342092691366163082661292802952169415410417753147690551106777629530469889448176067465550568846771804267298122038871177728941161394198665855259972725178390038493430895291167
)

rsa_keys = [rsa_key1, rsa_key2]

# Sample output
# ------------------------
# $ python3 rsa_public_keys.py
#
# -------- Testing 2 RSA keys --------
# CheckSizes                     passed                    (0.00s)
# CheckExponents                 passed                    (0.00s)
# CheckROCA                      passed                    (0.00s)
# CheckROCAVariant               passed                    (0.00s)
# CheckFermat                    failed                    (0.02s)
# CheckHighAndLowBitsEqual       passed                    (0.01s)
# CheckOpensslDenylist           passed                    (0.00s)
# CheckContinuedFractions        passed                    (0.05s)
# CheckBitPatterns               passed                    (0.01s)
# CheckPermutedBitPatterns       passed                    (0.01s)
# CheckPollardpm1                passed                    (0.00s)
# CheckLowHammingWeight          passed                    (0.06s)
# CheckUnseededRand              passed                    (0.12s)
# CheckSmallUpperDifferences     passed                    (0.00s)
# CheckKeypairDenylist           passed                    (0.00s)
# CheckGCD                       passed                    (0.00s)
# CheckGCDN1                     passed                    (0.00s)
# final state: failed
# total time: 0.28s
# Found first key to be potentially weak? False
# Found second key to be potentially weak? True
# Second key is weak to CheckFermat? True


def main(argv: list[str]) -> None:
  """Examples of testing RSA public keys.

  Args:
    argv: command line arguments.
  """
  if len(argv) > 1:
    raise app.UsageError("Too many commandline arguments.")
  if _PROF.value:
    with cProfile.Profile() as profile:
      paranoid.CheckAllRSA(rsa_keys, log_level=1)
    profile.print_stats(sort=1)
  else:
    paranoid.CheckAllRSA(rsa_keys, log_level=1)

  logging.info("Found first key to be potentially weak? %s",
               rsa_key1.test_info.weak)
  logging.info("Found second key to be potentially weak? %s",
               rsa_key2.test_info.weak)
  test_res = util.GetTestResult(rsa_key2.test_info, "CheckFermat")
  res = test_res and test_res.result
  logging.info("Second key is weak to CheckFermat? %s", res)


if __name__ == "__main__":
  app.run(main)
