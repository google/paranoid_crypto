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
"""This module contains an example of testing ECDSA signatures.

The individual checks are implemented in paranoid_crypto/lib. This module is
essentially just one way to call these checks. The unit tests at
paranoid_crypto/lib/paranoid_ecdsa_test.py contains more detailed examples
including how to call checks individually (this module assumes one wants to run
all checks against a collection of signatures).
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

# Below are examples of numbers of ECDSA signatures and issuer EC keys.
# There are multiple ways of extracting such numbers. For example,
# given a file containing a PEM encoded x.509 signed certificate, one can
# extract the signature numbers using Python cryptography module:
#
# >>> from cryptography import x509
# >>> from cryptography.hazmat.primitives import asymmetric
# >>> cert = x509.load_pem_x509_certificate(open('cert.pem', 'rb').read())
# >>> print(asymmetric.utils.decode_dss_signature(cert.signature))
#
# And given the issuer's certificate, one can extract the EC public key numbers:
#
# >>> issuer = x509.load_pem_x509_certificate(open('issuer.pem', 'rb').read())
# >>> print(issuer.public_key().public_numbers())
#
# Libraries in other languages or openssl command have similar methods.

# A good ECDSA signature:
ecdsa_sig1 = paranoid_pb2.ECDSASignature()
ecdsa_sig1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
ecdsa_sig1.ecdsa_sig_info.r = util.Int2Bytes(
    112414260651288035954123543375324296233571360212726664197041611198309255209509
)
ecdsa_sig1.ecdsa_sig_info.s = util.Int2Bytes(
    26975311350107572733334515763441274280169675702297770534611527834908043475585
)
ecdsa_sig1.ecdsa_sig_info.message_hash = util.Int2Bytes(
    102863594648721897867854612586575036082303272594355081587032712712117027436466
)
ecdsa_sig1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
ecdsa_sig1.issuer_key_info.x = util.Int2Bytes(
    2332684926370830540463288496711460799485964974383071573462948413603769821618
)
ecdsa_sig1.issuer_key_info.y = util.Int2Bytes(
    23841600378972614871701936339190975245021508864574103148433237147727387440964
)

# Three signatures with nonces generated using Java Util Random LCG
# (CheckLCGNonceJavaUtilRandom detects it).
ecdsa_sig2 = paranoid_pb2.ECDSASignature()
ecdsa_sig2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
ecdsa_sig2.ecdsa_sig_info.r = util.Int2Bytes(
    82614112698734442351073819222868460936660619796082259015390908145664444277311
)
ecdsa_sig2.ecdsa_sig_info.s = util.Int2Bytes(
    77404784679861249314662533377118483362502565683413418212277472779394330122772
)
ecdsa_sig2.ecdsa_sig_info.message_hash = util.Int2Bytes(
    61557594099480231296031895070342170174568848506472346036591303584473916504019
)
ecdsa_sig2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
ecdsa_sig2.issuer_key_info.x = util.Int2Bytes(
    58810272261031498184117212730893108663033185625528862884492349846008672851305
)
ecdsa_sig2.issuer_key_info.y = util.Int2Bytes(
    38928227198180667951060174873757842094604530644576397676642423924927058396944
)

ecdsa_sig3 = paranoid_pb2.ECDSASignature()
ecdsa_sig3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
ecdsa_sig3.ecdsa_sig_info.r = util.Int2Bytes(
    14351676320628291689587228274467090505014875236223139701907362111297744028062
)
ecdsa_sig3.ecdsa_sig_info.s = util.Int2Bytes(
    78763720601317328131260620312533327839625346289194175271507466656343918460270
)
ecdsa_sig3.ecdsa_sig_info.message_hash = util.Int2Bytes(
    12561957490148219382615240214200431879688468105337153400218894563773994699063
)
ecdsa_sig3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
ecdsa_sig3.issuer_key_info.x = util.Int2Bytes(
    58810272261031498184117212730893108663033185625528862884492349846008672851305
)
ecdsa_sig3.issuer_key_info.y = util.Int2Bytes(
    38928227198180667951060174873757842094604530644576397676642423924927058396944
)

ecdsa_sig4 = paranoid_pb2.ECDSASignature()
ecdsa_sig4.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
ecdsa_sig4.ecdsa_sig_info.r = util.Int2Bytes(
    108738074338811099659671388270014720742239120738440370165693843418124329670936
)
ecdsa_sig4.ecdsa_sig_info.s = util.Int2Bytes(
    87934804871404023492619492508594493146696811531889461956049234172256054254803
)
ecdsa_sig4.ecdsa_sig_info.message_hash = util.Int2Bytes(
    15434368081951830980162895925290030396277057170031374293115737747195765093737
)
ecdsa_sig4.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
ecdsa_sig4.issuer_key_info.x = util.Int2Bytes(
    58810272261031498184117212730893108663033185625528862884492349846008672851305
)
ecdsa_sig4.issuer_key_info.y = util.Int2Bytes(
    38928227198180667951060174873757842094604530644576397676642423924927058396944
)

ecdsa_signatures = [ecdsa_sig1, ecdsa_sig2, ecdsa_sig3, ecdsa_sig4]

# Sample output
# ------------------------
# $ python3 ecdsa_signatures.py
# -------- Testing 4 ECDSA signatures --------
# CheckLCGNonceGMP               passed                    (0.26s)
# CheckLCGNonceJavaUtilRandom    failed                    (5.86s)
# CheckNonceMSB                  passed                    (0.00s)
# CheckNonceCommonPrefix         passed                    (0.00s)
# CheckNonceCommonPostfix        passed                    (0.00s)
# CheckNonceGeneralized          passed                    (0.01s)
# CheckIssuerKey                 passed                    (35.01s)
# CheckCr50U2f                   passed                    (0.02s)
# final state: failed
# total time: 41.16s
# -------- Testing 4 ECDSA signatures --------
# CheckLCGNonceGMP               passed                    (0.20s)
# CheckLCGNonceJavaUtilRandom    failed                    (6.86s)
# CheckNonceMSB                  passed                    (0.00s)
# CheckNonceCommonPrefix         passed                    (0.00s)
# CheckNonceCommonPostfix        passed                    (0.00s)
# CheckNonceGeneralized          passed                    (0.00s)
# CheckIssuerKey                 passed                    (0.64s)
# CheckCr50U2f                   passed                    (0.02s)
# final state: failed
# total time: 7.72s
# Found first signature to be potentially weak? False
# Found second signature to be potentially weak? True
# Second signature is weak to CheckLCGNonceJavaUtilRandom? True


def main(argv: list[str]) -> None:
  """Examples of testing ECDSA signatures.

  Args:
    argv: command line arguments.
  """
  if len(argv) > 1:
    raise app.UsageError("Too many commandline arguments.")

  # The paranoid_crypto/lib/ec_util.py module computes some large tables for
  # some of the tests. In a first execution these tables take a while to be
  # created. On following executions (e.g., with different or more signatures)
  # a cache mechanism is used and the checks are much faster.
  for _ in range(2):
    if _PROF.value:
      with cProfile.Profile() as profile:
        paranoid.CheckAllECDSASigs(ecdsa_signatures, log_level=1)
      profile.print_stats(sort=1)
    else:
      paranoid.CheckAllECDSASigs(ecdsa_signatures, log_level=1)

  logging.info("Found first signature to be potentially weak? %s",
               ecdsa_sig1.test_info.weak)
  logging.info("Found second signature to be potentially weak? %s",
               ecdsa_sig2.test_info.weak)
  test_res = util.GetTestResult(ecdsa_sig2.test_info,
                                "CheckLCGNonceJavaUtilRandom")
  res = test_res and test_res.result
  logging.info("Second signature is weak to CheckLCGNonceJavaUtilRandom? %s",
               res)  # Same for ecdsa_sig3 and ecdsa_sig4...


if __name__ == "__main__":
  app.run(main)
