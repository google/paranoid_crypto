#ifndef PARANOID_CRYPTO_LIB_RANDOMNESS_TESTS_CC_UTIL_BERLEKAMP_MASSEY_H_
#define PARANOID_CRYPTO_LIB_RANDOMNESS_TESTS_CC_UTIL_BERLEKAMP_MASSEY_H_
#include <string>
#include <vector>

namespace paranoid_crypto::lib::randomness_tests::cc_util {

// Computes the linear complexity of a binary sequence of length n.
// The sequence is represented using little endian byte ordering.
// Hence bit j of the sequence is (seq[j / 8] >> (j % 8)) & 1.
bool LfsrLength(const std::vector<uint8_t>& seq, int n, int* length);

// Same as above. This function has been added, since pybind converts the
// Python type bytes into a std::string and using output arguments is tricky.
// The sequence is represented using little endian byte ordering.
// Hence bit j of the sequence is (seq[j / 8] >> (j % 8)) & 1.
int LfsrLengthStr(const std::string& seq, int n);

}  // namespace paranoid_crypto::lib::randomness_tests::cc_util

#endif  // PARANOID_CRYPTO_LIB_RANDOMNESS_TESTS_CC_UTIL_BERLEKAMP_MASSEY_H_
