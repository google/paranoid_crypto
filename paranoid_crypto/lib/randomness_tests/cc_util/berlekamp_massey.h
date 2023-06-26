// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
