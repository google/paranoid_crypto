// Copyright 2026 Google LLC
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

#include "paranoid_crypto/lib/cc_util/rsa_batch.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "testing/base/public/gunit.h"
#include <gmp.h>

namespace paranoid_crypto::lib::cc_util {
namespace {

std::string MpzToBe(const mpz_t z) {
  if (mpz_sgn(z) == 0) return {};
  size_t count = 0;
  void* raw = mpz_export(nullptr, &count, 1, 1, 1, 0, z);
  std::string out(static_cast<const char*>(raw), count);
  void (*free_fn)(void*, size_t) = nullptr;
  mp_get_memory_functions(nullptr, nullptr, &free_fn);
  free_fn(raw, count);
  return out;
}

std::string U64ToBe(uint64_t v) {
  if (v == 0) return {};
  std::string rev;
  while (v > 0) {
    rev.push_back(static_cast<char>(v & 0xFFu));
    v >>= 8;
  }
  return std::string(rev.rbegin(), rev.rend());
}

uint64_t BeToU64(std::string_view be) {
  uint64_t v = 0;
  for (unsigned char c : be) {
    v = (v << 8) | c;
  }
  return v;
}

// Exact O(N^2) reference matching Python BatchGCD(values, other_values_prod).
std::vector<std::string> ReferenceBatchGcd(
    const std::vector<std::pair<bool, std::string>>& signed_inputs,
    std::optional<std::string> other_prod_be = std::nullopt) {
  std::vector<std::pair<bool, std::string>> norm;
  norm.reserve(signed_inputs.size());
  std::set<std::pair<bool, std::string>> unique_set;
  for (const auto& [neg, be] : signed_inputs) {
    size_t nz = 0;
    while (nz < be.size() && be[nz] == '\0') ++nz;
    std::string stripped = be.substr(nz);
    bool real_neg = !stripped.empty() && neg;
    norm.emplace_back(real_neg, stripped);
    unique_set.emplace(real_neg, stripped);
  }

  std::vector<std::pair<bool, std::string>> unique_vals(unique_set.begin(),
                                                        unique_set.end());
  mpz_t other_z;
  mpz_init(other_z);
  if (other_prod_be.has_value()) {
    if (other_prod_be->empty()) {
      mpz_set_ui(other_z, 0);
    } else {
      mpz_import(other_z, other_prod_be->size(), 1, 1, 1, 0,
                 other_prod_be->data());
    }
  } else {
    mpz_set_ui(other_z, 1);
  }

  std::vector<std::string> out;
  out.reserve(norm.size());
  mpz_t prod, cur, elem, g;
  mpz_inits(prod, cur, elem, g, nullptr);

  for (const auto& target : norm) {
    mpz_set(prod, other_z);
    for (const auto& u : unique_vals) {
      if (u == target) continue;
      if (u.second.empty()) {
        mpz_set_ui(cur, 0);
      } else {
        mpz_import(cur, u.second.size(), 1, 1, 1, 0, u.second.data());
      }
      mpz_mul(prod, prod, cur);
    }
    if (target.second.empty()) {
      mpz_set_ui(elem, 0);
    } else {
      mpz_import(elem, target.second.size(), 1, 1, 1, 0, target.second.data());
    }
    mpz_gcd(g, elem, prod);
    out.push_back(MpzToBe(g));
  }

  mpz_clears(other_z, prod, cur, elem, g, nullptr);
  return out;
}

TEST(RsaBatchTest, EmptyAndTrivialEdgeCases) {
  {
    RsaBatchAccumulator acc;
    EXPECT_EQ(acc.num_inputs(), 0u);
    EXPECT_TRUE(acc.ComputeAllGcds().empty());
    EXPECT_TRUE(acc.ComputeFilteredGcds(U64ToBe(2)).empty());
  }

  // Single element without other_prod -> GCD is 1.
  {
    RsaBatchAccumulator acc;
    acc.AddSignedBigEndian(false, U64ToBe(35));
    auto gcds = acc.ComputeAllGcds();
    ASSERT_EQ(gcds.size(), 1u);
    EXPECT_EQ(BeToU64(gcds[0]), 1u);
  }

  // Single element with other_prod -> GCD(35, 15) == 5.
  {
    RsaBatchAccumulator acc;
    acc.AddSignedBigEndian(false, U64ToBe(35));
    auto gcds = acc.ComputeAllGcds(U64ToBe(15));
    ASSERT_EQ(gcds.size(), 1u);
    EXPECT_EQ(BeToU64(gcds[0]), 5u);
  }

  // Duplicate values must not flag each other, while opposite signs are
  // distinct in signed mode.
  {
    RsaBatchAccumulator acc;
    acc.AddSignedBigEndian(false, U64ToBe(6));
    acc.AddSignedBigEndian(false, U64ToBe(35));
    acc.AddSignedBigEndian(false, U64ToBe(55));
    acc.AddSignedBigEndian(false, U64ToBe(6));
    auto gcds = acc.ComputeAllGcds();
    ASSERT_EQ(gcds.size(), 4u);
    EXPECT_EQ(BeToU64(gcds[0]), 1u);
    EXPECT_EQ(BeToU64(gcds[1]), 5u);
    EXPECT_EQ(BeToU64(gcds[2]), 5u);
    EXPECT_EQ(BeToU64(gcds[3]), 1u);
  }

  {
    RsaBatchAccumulator acc;
    acc.AddSignedBigEndian(true, U64ToBe(6));
    acc.AddSignedBigEndian(false, U64ToBe(6));
    auto gcds = acc.ComputeAllGcds();
    ASSERT_EQ(gcds.size(), 2u);
    EXPECT_EQ(BeToU64(gcds[0]), 6u);
    EXPECT_EQ(BeToU64(gcds[1]), 6u);
  }

  // Zero and +-1 edge cases in general signed BatchGCD.
  {
    std::vector<std::pair<bool, std::string>> inputs = {
        {false, ""},          // 0
        {false, U64ToBe(1)},  // 1
        {true, U64ToBe(1)},   // -1
        {false, U64ToBe(6)},  // 6
        {false, U64ToBe(6)},  // duplicate 6
        {false, U64ToBe(5)},  // 5
    };
    RsaBatchAccumulator acc;
    for (const auto& [neg, be] : inputs) {
      acc.AddSignedBigEndian(neg, be);
    }
    EXPECT_EQ(acc.ComputeAllGcds(), ReferenceBatchGcd(inputs));

    RsaBatchAccumulator acc_zero_other;
    for (const auto& [neg, be] : inputs) {
      acc_zero_other.AddSignedBigEndian(neg, be);
    }
    EXPECT_EQ(acc_zero_other.ComputeAllGcds(std::string("")),
              ReferenceBatchGcd(inputs, std::string("")));
  }
}

TEST(RsaBatchTest, DifferentialAcrossAllThreeTiersAndThreadCounts) {
  std::mt19937_64 rng(0x5EED1234ULL);

  auto make_random_be = [&](size_t num_bytes) {
    std::string s(num_bytes, '\0');
    s[0] = static_cast<char>((rng() % 255) + 1);
    for (size_t i = 1; i < num_bytes; ++i) {
      s[i] = static_cast<char>(rng() & 0xFFu);
    }
    s.back() |= 1;
    return s;
  };

  constexpr size_t kNumSharedPrimes = 6;
  mpz_t shared_primes[kNumSharedPrimes];
  for (size_t i = 0; i < kNumSharedPrimes; ++i) {
    mpz_init(shared_primes[i]);
    std::string seed = make_random_be(16);
    mpz_import(shared_primes[i], seed.size(), 1, 1, 1, 0, seed.data());
    mpz_nextprime(shared_primes[i], shared_primes[i]);
  }

  std::vector<std::pair<bool, std::string>> inputs;
  mpz_t p, q, n;
  mpz_inits(p, q, n, nullptr);
  const size_t kNumItems = 155;  // Odd count to exercise odd-tail tree paths.
  for (size_t i = 0; i < kNumItems; ++i) {
    if (i == 17 && !inputs.empty()) {
      inputs.push_back(inputs[0]);
      continue;
    }
    const size_t half_bytes = 16 + (i % 7) * 16;  // 128-bit .. 896-bit primes.
    if (i % 19 == 0) {
      mpz_set(p, shared_primes[(i / 19) % kNumSharedPrimes]);
    } else {
      std::string sb = make_random_be(half_bytes);
      mpz_import(p, sb.size(), 1, 1, 1, 0, sb.data());
      mpz_nextprime(p, p);
    }
    std::string qb = make_random_be(half_bytes);
    mpz_import(q, qb.size(), 1, 1, 1, 0, qb.data());
    mpz_nextprime(q, q);
    mpz_mul(n, p, q);
    inputs.emplace_back(false, MpzToBe(n));
  }

  std::string other_prod_be = MpzToBe(shared_primes[5]);
  mpz_clears(p, q, n, nullptr);
  for (size_t i = 0; i < kNumSharedPrimes; ++i) {
    mpz_clear(shared_primes[i]);
  }

  const std::vector<std::string> expected_no_other = ReferenceBatchGcd(inputs);
  const std::vector<std::string> expected_with_other =
      ReferenceBatchGcd(inputs, other_prod_be);

  struct Config {
    size_t chunk_bytes;
    size_t super_group;
    int threads;
  };
  const std::vector<Config> configs = {
      {16ULL * 1024 * 1024, 64, 1},
      {16ULL * 1024 * 1024, 64, 4},
      {512, 64, 1},
      {512, 64, 4},
      {64, 3, 1},
      {64, 3, 4},
  };

  for (const Config& cfg : configs) {
    RsaBatchOptions opts;
    opts.chunk_target_bytes = cfg.chunk_bytes;
    opts.chunks_per_superchunk = cfg.super_group;
    opts.num_threads = cfg.threads;

    RsaBatchAccumulator acc1(opts);
    acc1.Reserve(inputs.size());
    for (const auto& [neg, be] : inputs) {
      acc1.AddSignedBigEndian(neg, be);
    }
    EXPECT_EQ(acc1.ComputeAllGcds(), expected_no_other);

    RsaBatchAccumulator acc2(opts);
    for (const auto& [neg, be] : inputs) {
      acc2.AddSignedBigEndian(neg, be);
    }
    EXPECT_EQ(acc2.ComputeAllGcds(other_prod_be), expected_with_other);
  }
}

TEST(RsaBatchTest, SubtractOneFilteredGcdsAndMalformedModulusSafety) {
  // Construct keys for CheckGCDN1 (`subtract_one = true`):
  //   n1 - 1 = 2 * 1000003 * 17
  //   n2 - 1 = 2 * 1000003 * 29   (shares 2 * 1000003 = 2000006 >= 1000000)
  //   n3 - 1 = 2 * 19 * 23        (gcd < 1000000)
  //   n0     = 0 (malformed zero modulus -> must not poison n1/n2/n3!)
  //   n_one  = 1 (malformed one modulus -> n - 1 == 0 -> must not poison!)
  const std::string n1_be =
      std::string("\x00\x00", 2) + U64ToBe(2ULL * 1000003ULL * 17ULL + 1ULL);
  const std::string n2_be = U64ToBe(2ULL * 1000003ULL * 29ULL + 1ULL);
  const std::string n3_be = U64ToBe(2ULL * 19ULL * 23ULL + 1ULL);
  const std::string n0_be(8, '\0');
  const std::string n_one_be = std::string(7, '\0') + std::string("\x01", 1);

  RsaBatchOptions opts;
  opts.chunk_target_bytes = 8;
  opts.chunks_per_superchunk = 2;
  opts.num_threads = 2;
  RsaBatchAccumulator acc(opts);
  acc.Reserve(5);

  acc.AddModulusBigEndian(n0_be, /*subtract_one=*/true);
  acc.AddModulusBigEndian(n1_be, /*subtract_one=*/true);
  acc.AddModulusBigEndian(n_one_be, /*subtract_one=*/true);
  acc.AddModulusBigEndian(n2_be, /*subtract_one=*/true);
  acc.AddModulusBigEndian(n3_be, /*subtract_one=*/true);

  const auto hits = acc.ComputeFilteredGcds(U64ToBe(1000000ULL));
  ASSERT_EQ(hits.size(), 2u);
  EXPECT_EQ(hits[0].first, 1);
  EXPECT_EQ(BeToU64(hits[0].second), 2000006ULL);
  EXPECT_EQ(hits[1].first, 3);
  EXPECT_EQ(BeToU64(hits[1].second), 2000006ULL);
  // Internal memory is released after ComputeFilteredGcds.
  EXPECT_EQ(acc.num_inputs(), 0u);
  EXPECT_EQ(acc.num_unique_leaves(), 0u);
}

TEST(RsaBatchTest, RepeatedMultithreadedAlternatingConcurrencyStress) {
  std::mt19937_64 rng(0xA17E24ULL);
  constexpr size_t kNumItems = 45;
  std::vector<std::pair<bool, std::string>> inputs;
  inputs.reserve(kNumItems);

  mpz_t shared_p, p, q, n;
  mpz_inits(shared_p, p, q, n, nullptr);
  mpz_set_ui(shared_p, 1000000007ULL);
  mpz_nextprime(shared_p, shared_p);

  for (size_t i = 0; i < kNumItems; ++i) {
    if (i % 11 == 0) {
      mpz_set(p, shared_p);
    } else {
      uint64_t seed_p = (rng() | (1ULL << 63)) | 1ULL;
      mpz_import(p, sizeof(seed_p), 1, 1, 0, 0, &seed_p);
      mpz_nextprime(p, p);
    }
    uint64_t seed_q = (rng() | (1ULL << 63)) | 1ULL;
    mpz_import(q, sizeof(seed_q), 1, 1, 0, 0, &seed_q);
    mpz_nextprime(q, q);
    mpz_mul(n, p, q);
    inputs.emplace_back(false, MpzToBe(n));
  }
  const std::string other_prod_be = MpzToBe(shared_p);
  mpz_clears(shared_p, p, q, n, nullptr);

  const std::vector<std::string> expected =
      ReferenceBatchGcd(inputs, other_prod_be);

  // Small chunk/superchunk thresholds with 8 worker threads force consecutive
  // ParallelFor dispatches to alternate between partial worker participation
  // (e.g., 2, 3, or 6 upper-tree pairs) and full 8-thread leaf passes.
  RsaBatchOptions opts;
  opts.chunk_target_bytes = 64;
  opts.chunks_per_superchunk = 3;
  opts.num_threads = 8;

  for (int iter = 0; iter < 64; ++iter) {
    RsaBatchAccumulator acc(opts);
    acc.Reserve(inputs.size());
    for (const auto& [neg, be] : inputs) {
      acc.AddSignedBigEndian(neg, be);
    }
    ASSERT_EQ(acc.ComputeAllGcds(other_prod_be), expected)
        << "at iteration " << iter;
  }
}

}  // namespace
}  // namespace paranoid_crypto::lib::cc_util
