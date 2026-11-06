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

#ifndef PARANOID_CRYPTO_LIB_CC_UTIL_EC_BATCH_H_
#define PARANOID_CRYPTO_LIB_CC_UTIL_EC_BATCH_H_

#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace paranoid_crypto::lib::cc_util {

// Match returned by ExtendedBatchDL:
//   key_index: index into the packed non-infinity input points [0, num_valid).
//   kind:
//     0 -> form (1)/(4) with m_idx == 0 (Q = P)
//     1 -> form (1)/(4) with m_idx == aux_index (Q = m_idx^(-1) * P)
//     2 -> form (3) (-P = u * G)
//     3 -> form (2) (C_{B, m_idx} - Q = u * G), where aux_index is the flat
//          slice index b_idx * num_window_mults + m_idx.
//   aux_index: multiplier or complement-slice index as described above.
//   signed_dl: signed discrete logarithm u in (-2^32, 2^32) satisfying
//              signed_dl * G == target_point.
struct ExtendedDlMatch {
  int64_t key_index;
  int32_t kind;
  int32_t aux_index;
  int64_t signed_dl;
};

// Match returned by DiffBatchDL:
//   point_index: index i in points [0, len(points)).
//   ref_index: index in other_points [0, M) if < M, else M + j for points[j].
//   dl: non-zero integer in (-max_diff, max_diff) with points[i] - Q == dl * G.
struct DiffDlMatch {
  int64_t point_index;
  int64_t ref_index;
  int64_t dl;
};

// GMP-backed batch elliptic-curve discrete-logarithm engine over short
// Weierstrass prime curves y^2 = x^3 + a*x + b (mod p) for odd primes p >= 5
// (up to 1024-byte coordinates).
class EcBatchEngine {
 public:
  // Upper bound on baby-step entries in EnsureTable / BatchDL (~27M entries in
  // 275 L2-resident slices of 2^17 6-byte slots = ~206 MiB flat table).
  static constexpr int64_t kMaxDlTableSize = 27000000;

  // Default upper bound on baby-step entries per tile in DiffBatchDL (~36M
  // entries in 353 L2-resident slices of 2^17 6-byte slots = ~265 MiB flat
  // temporary table).
  static constexpr int64_t kDefaultMaxDiffBabyEntries = 36000000;

  virtual ~EcBatchEngine() = default;

  // Creates an engine for an odd prime modulus `mod_le` (little-endian bytes,
  // 1..1024 bytes), curve parameter `a_le` (a mod p, same byte length), and
  // generator point `(gx_le, gy_le)` (same byte length). Returns nullptr if
  // inputs are out of range or `mod_le` is even / < 5.
  static std::unique_ptr<EcBatchEngine> Create(std::string_view mod_le,
                                               std::string_view a_le,
                                               std::string_view gx_le,
                                               std::string_view gy_le);

  // Number of bytes per serialized field coordinate (`len(mod_le)`).
  virtual int coord_bytes() const = 0;

  // Current number of baby-step points [0, table_size()) stored in the table.
  virtual int64_t table_size() const = 0;

  // Grows the internal baby-step table to cover [0, target_size).
  virtual void EnsureTable(int64_t target_size) = 0;

  // Finds discrete logarithms for packed points (each `1 + 2 * coord_bytes`
  // bytes: 0x00 for INFINITY or 0x01 followed by little-endian x, y) with bound
  // `n` (0 <= dl < n). Writes (point_index, signed_dl) pairs for solved points
  // into `*out`, where signed_dl * G == points[point_index]. Returns false if
  // `points_le` is malformed.
  virtual bool BatchDL(std::string_view points_le, int64_t n,
                       int64_t expected_points,
                       std::vector<std::pair<int64_t, int64_t>>* out) = 0;

  // Executes the full ExtendedBatchDL target generation and 32-bit BSGS search
  // in bounded chunks without materializing intermediate Python point lists.
  // `inverses_le` packs `num_mult` little-endian positive integers of length
  // `scalar_bytes`. `comp_points_le` packs `num_comp_slices * num_window_mults`
  // precomputed complement points. Returns false if packed inputs are invalid.
  virtual bool ExtendedBatchDL(std::string_view points_le,
                               std::string_view inverses_le, int scalar_bytes,
                               int num_byte_shifts, int num_window_mults,
                               std::string_view comp_points_le,
                               std::vector<ExtendedDlMatch>* out) = 0;

  // Finds all pairs with points[i] - Q = dl * G and 0 < |dl| < max_diff.
  // Returns false if `points_le` or `other_points_le` has invalid byte length.
  virtual bool DiffBatchDL(std::string_view points_le,
                           std::string_view other_points_le, int64_t max_diff,
                           int64_t max_baby_entries,
                           std::vector<DiffDlMatch>* out) = 0;
};

}  // namespace paranoid_crypto::lib::cc_util

#endif  // PARANOID_CRYPTO_LIB_CC_UTIL_EC_BATCH_H_
