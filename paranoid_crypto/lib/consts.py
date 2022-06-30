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
