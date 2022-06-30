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

#include "paranoid_crypto/lib/randomness_tests/cc_util/berlekamp_massey.h"

#include <string>
#include <vector>

#include "testing/base/public/benchmark.h"
#include "testing/base/public/googletest.h"
#include "testing/base/public/gunit.h"

namespace {
void FillVectorWithPRand(std::vector<uint8_t>* seq) {
  for (int j = 0; j < seq->size(); j++) {
    (*seq)[j] = ((j * j * 57641) % 67723) & 255;
  }
}
}  // namespace

namespace paranoid_crypto::lib::randomness_tests::cc_util {
namespace {

int LfsrLengthRef(const std::vector<uint8_t>& seq, int n) {
  std::vector<uint8_t> sb(seq);
  std::vector<uint8_t> sc(seq);
  int L = 0;
  for (int i = 0; i < n; i++) {
    int disc = sc[0] & 1;
    for (int j = 0; j < sc.size() - 1; j++) {
      sc[j] = (sc[j] >> 1) | (sc[j + 1] << 7);
    }
    sc[sc.size() - 1] >>= 1;
    if (disc == 1) {
      if (2 * L <= i) {
        L = i + 1 - L;
        sb.swap(sc);
      }
      for (int j = 0; j < sc.size(); j++) {
        sc[j] ^= sb[j];
      }
    }
  }
  return L;
}

// Short list of test vectors.
static struct TestVector {
  int s;
  int size;
  int expected_length;
} test_vector[] = {
    {356, 9, 4},
    {482676245, 34, 18},
};

TEST(BerlekampMassey, Tv) {
  for (int i = 0; i < arraysize(test_vector); i++) {
    std::vector<uint8_t> seq((test_vector[i].size + 7) / 8);
    for (int j = 0; j < seq.size(); j++) {
      seq[j] = (test_vector[i].s >> (8 * j)) & 255;
    }
    int L;
    ASSERT_TRUE(LfsrLength(seq, test_vector[i].size, &L));
    EXPECT_EQ(test_vector[i].expected_length, L) << i;
  }
}

TEST(BerlekampMassey, Compare) {
  for (int i = 1; i < 1024; i++) {
    std::vector<uint8_t> seq(i);
    FillVectorWithPRand(&seq);
    int L1;
    ASSERT_TRUE(LfsrLength(seq, 8 * i, &L1));
    int L2 = LfsrLengthRef(seq, 8 * i);
    EXPECT_EQ(L1, L2) << i;
  }
}

TEST(BerlekampMassey, EdgeCases) {
  // Edge cases are sequences starting with lots of 0 bits.
  for (int size = 16; size < 300; size++) {
    int bytes = (size + 7) / 8;
    std::vector<uint8_t> seq(bytes);
    for (int last_byte = 0; last_byte < 256; last_byte++) {
      int bits_in_last_byte = ((size - 1) % 8) + 1;
      seq[bytes - 1] = last_byte & ((1 << bits_in_last_byte) - 1);
      seq[bytes - 2] = last_byte >> bits_in_last_byte;
      int L1;
      ASSERT_TRUE(LfsrLength(seq, size, &L1));
      int L2 = LfsrLengthRef(seq, size);
      EXPECT_EQ(L1, L2) << size << " " << last_byte;
    }
  }
}

}  // namespace
}  // namespace paranoid_crypto::lib::randomness_tests::cc_util

void BM_LFSR_LENGTH(benchmark::State& state) {
  int size = state.range(0);
  std::vector<uint8_t> seq(size);
  FillVectorWithPRand(&seq);
  for (auto s : state) {
    int L;
    ASSERT_TRUE(paranoid_crypto::lib::randomness_tests::cc_util::LfsrLength(
        seq, 8 * size, &L));
    ASSERT_GT(L, 0);
  }
}

BENCHMARK(BM_LFSR_LENGTH)->Range(32, 1 << 15);
