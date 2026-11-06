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

#ifndef PARANOID_CRYPTO_LIB_CC_UTIL_RSA_BATCH_H_
#define PARANOID_CRYPTO_LIB_CC_UTIL_RSA_BATCH_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace paranoid_crypto::lib::cc_util {

// Configuration options for RsaBatchAccumulator.
struct RsaBatchOptions {
  // Target maximum leaf limb bytes per bottom-tier chunk (default 16 MiB).
  // Smaller values may be used in unit tests to exercise multi-chunk and
  // multi-superchunk checkpointing paths on small inputs.
  size_t chunk_target_bytes = 16ULL * 1024 * 1024;

  // Number of bottom-tier chunks grouped into each middle-tier super-chunk
  // when total chunks exceed this threshold (default 64 -> ~1 GiB).
  size_t chunks_per_superchunk = 64;

  // Worker thread count for tree construction and remainder descent.
  // 0 auto-selects min(hardware_concurrency, 8).
  int num_threads = 0;
};

// Memory-bounded, multithreaded GMP batch-GCD accumulator and solver.
//
// Stores unique leaf magnitudes (|v| >= 2) in a single flat limb arena with a
// compact 6-byte-per-slot open-addressing deduplication table, then solves all
// pairwise GCDs via a 3-tier checkpointed product/cross-remainder tree without
// materializing the full tree in memory or computing the root product.
class RsaBatchAccumulator {
 public:
  explicit RsaBatchAccumulator(RsaBatchOptions options = {});
  ~RsaBatchAccumulator();

  RsaBatchAccumulator(const RsaBatchAccumulator&) = delete;
  RsaBatchAccumulator& operator=(const RsaBatchAccumulator&) = delete;
  RsaBatchAccumulator(RsaBatchAccumulator&&) noexcept;
  RsaBatchAccumulator& operator=(RsaBatchAccumulator&&) noexcept;

  // Pre-allocates per-input metadata and optional limb arena capacity.
  void Reserve(size_t expected_inputs, size_t expected_limb_bytes = 0);

  // Total number of inputs added so far.
  size_t num_inputs() const;

  // Number of distinct leaves with |value| >= 2 stored in the limb arena.
  size_t num_unique_leaves() const;

  // Appends a general signed integer given its sign (`is_negative` ignored when
  // magnitude is zero) and big-endian unsigned magnitude bytes. Distinct signed
  // values are deduplicated identically to Python `set(values)`.
  void AddSignedBigEndian(bool is_negative, std::string_view magnitude_be);

  // Appends an unsigned RSA modulus from big-endian bytes. When `subtract_one`
  // is true, ingests `modulus - 1` (for CheckGCDN1). Values <= 1 (such as
  // malformed zero/one moduli) are clamped to 1 so they cannot poison or crash
  // valid keys in the batch.
  void AddModulusBigEndian(std::string_view modulus_be,
                           bool subtract_one = false);

  // Computes big-endian unsigned magnitude bytes of
  //   gcd(values[i], other_prod * prod_{w in unique(values), w != values[i]} w)
  // for every input index i in [0, num_inputs()). An integer 0 is encoded as
  // the empty byte string "".
  std::vector<std::string> ComputeAllGcds(
      std::optional<std::string_view> other_prod_magnitude_be = std::nullopt);

  // Computes pairwise GCDs and returns `(index, gcd_be)` pairs (sorted by
  // ascending `index`) ONLY for inputs whose GCD is >= `min_gcd_be` (big-endian
  // unsigned integer), releasing internal limb storage before returning.
  std::vector<std::pair<int64_t, std::string>> ComputeFilteredGcds(
      std::string_view min_gcd_be,
      std::optional<std::string_view> other_prod_magnitude_be = std::nullopt);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace paranoid_crypto::lib::cc_util

#endif  // PARANOID_CRYPTO_LIB_CC_UTIL_RSA_BATCH_H_
