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
"""Shared constants for paranoid library."""
from paranoid_crypto import paranoid_pb2

INFO_NAME_N_FACTORS = "N_FACTORS"
INFO_NAME_NM1_FACTORS = "N-1_FACTORS"
INFO_NAME_DISCRETE_LOG = "DISCRETE_LOG"
INFO_NAME_DISCRETE_LOG_DIFF = "DISCRETE_LOG_DIFF"

SIGNATURE_HASH_LENGTHS = {
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_MD5: 128,
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA1: 160,
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA224: 224,
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA256: 256,
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA384: 384,
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA512: 512,
    paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1: 160,
    paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA224: 224,
    paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256: 256,
    paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA384: 384,
    paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA512: 512,
}
