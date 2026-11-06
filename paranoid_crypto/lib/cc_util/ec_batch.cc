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

#include "paranoid_crypto/lib/cc_util/ec_batch.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <gmp.h>
#include <gmpxx.h>

namespace paranoid_crypto::lib::cc_util {
namespace {

constexpr uint64_t kInfinityHash = 0x9E3779B97F4A7C15ULL;
constexpr size_t kPrefetchDist = 16;

// Extracts a non-zero 16-bit tag from bits 17..32 of `hv` (disjoint from
// bits 0..16 used for `local_pos` and bits 33..63 used for `SliceOf`).
inline uint16_t MakeTag16(uint64_t hv) {
  uint16_t t = static_cast<uint16_t>(hv >> 17);
  return t == 0U ? 1U : t;
}

// Compact 6-byte-per-slot L2-sliced open-addressed hash table storing parallel
// `uint16_t tags[]` (0 = empty, 1..65535 = occupied tag) and `uint32_t vals[]`.
//
// Two properties make large BSGS tables both memory-frugal and DRAM-stall-free:
//   1. Non-matching probes (~99.997% of occupied slots) reject on `tags[pos]`
//      without ever touching `vals[pos]` or running EC scalar verification.
//   2. When `needed_slots > 2^17`, the table is partitioned into `num_slices`
//      contiguous slices of 2^17 slots (each slice's `tags` is 256 KiB = 64
//      4-KiB pages, fitting comfortably in L2 cache and STLB), and batch
//      inserts/probes are radix-grouped by slice in bounded <= 8 MiB buffers.
struct SlicedHashTable48 {
  static constexpr int kSliceBits = 17;
  static constexpr uint32_t kSliceSlots = 1U << kSliceBits;  // 131,072 slots
  static constexpr uint32_t kMaxSlices = 512;
  static constexpr size_t kRadixFlushThreshold = 1ULL << 18;  // 262,144 items

  struct RadixInsert {
    uint32_t pos;
    uint32_t val;
    uint16_t slice;
    uint16_t tag;
  };

  struct RadixProbe {
    uint32_t pos;
    uint32_t pt_off;
    int32_t g_step;
    uint16_t slice;
    uint16_t tag;
  };

  std::vector<uint16_t> tags;
  std::vector<uint32_t> vals;
  size_t total_slots = 0;
  uint32_t num_slices = 0;
  int local_bits = 0;
  uint32_t local_mask = 0;
  bool sliced = false;

  static size_t ComputeNeededSlots(int64_t num_entries, int max_load_pct) {
    uint64_t entries = static_cast<uint64_t>(std::max<int64_t>(1, num_entries));
    uint64_t load = static_cast<uint64_t>(max_load_pct);
    uint64_t needed = (entries * 100ULL + load - 1ULL) / load;
    uint64_t max_total =
        static_cast<uint64_t>(kMaxSlices) * static_cast<uint64_t>(kSliceSlots);
    return static_cast<size_t>(std::min<uint64_t>(needed, max_total));
  }

  void ClearAndDeallocate() {
    std::vector<uint16_t>().swap(tags);
    std::vector<uint32_t>().swap(vals);
    total_slots = 0;
    num_slices = 0;
    local_bits = 0;
    local_mask = 0;
    sliced = false;
  }

  void InitForEntries(int64_t num_entries, int max_load_pct) {
    ClearAndDeallocate();
    size_t needed = ComputeNeededSlots(num_entries, max_load_pct);
    if (needed <= kSliceSlots) {
      sliced = false;
      num_slices = 1;
      local_bits = 10;
      while ((static_cast<size_t>(1U) << local_bits) < needed &&
             local_bits < kSliceBits) {
        ++local_bits;
      }
      local_mask = (1U << local_bits) - 1U;
      total_slots = static_cast<size_t>(1U) << local_bits;
    } else {
      sliced = true;
      local_bits = kSliceBits;
      local_mask = kSliceSlots - 1U;
      size_t ns = (needed + kSliceSlots - 1U) / kSliceSlots;
      num_slices = static_cast<uint32_t>(
          std::min<size_t>(kMaxSlices, std::max<size_t>(2U, ns)));
      total_slots = static_cast<size_t>(num_slices) << kSliceBits;
    }
    tags.assign(total_slots, 0U);
    vals.assign(total_slots, 0U);
  }

  inline uint32_t SliceOf(uint64_t hv) const {
    uint32_t hi31 = static_cast<uint32_t>(hv >> 33);
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(hi31) * static_cast<uint64_t>(num_slices)) >>
        31);
  }

  inline void InsertOneDirect(uint64_t hv, uint32_t val) {
    uint16_t tag = MakeTag16(hv);
    size_t slice_off =
        sliced ? (static_cast<size_t>(SliceOf(hv)) << kSliceBits) : 0U;
    uint16_t* stags = tags.data() + slice_off;
    uint32_t* svals = vals.data() + slice_off;
    uint32_t pos = static_cast<uint32_t>(hv) & local_mask;
    uint32_t limit = local_mask + 1U;
    for (uint32_t step = 0; step < limit; ++step) {
      uint16_t cur = stags[pos];
      if (cur == 0U) {
        stags[pos] = tag;
        svals[pos] = val;
        return;
      }
      if (cur == tag && svals[pos] == val) {
        return;
      }
      pos = (pos + 1U) & local_mask;
    }
  }

  inline void QueueInsert(uint64_t hv, uint32_t val,
                          std::vector<RadixInsert>* radix_buf,
                          std::vector<RadixInsert>* radix_tmp) {
    if (!sliced) {
      InsertOneDirect(hv, val);
      return;
    }
    radix_buf->push_back(RadixInsert{
        static_cast<uint32_t>(hv) & local_mask,
        val,
        static_cast<uint16_t>(SliceOf(hv)),
        MakeTag16(hv),
    });
    if (radix_buf->size() >= kRadixFlushThreshold) {
      FlushInserts(radix_buf, radix_tmp);
    }
  }

  void FlushInserts(std::vector<RadixInsert>* radix_buf,
                    std::vector<RadixInsert>* radix_tmp) {
    size_t n = radix_buf->size();
    if (n == 0) return;
    size_t counts[kMaxSlices];
    std::memset(counts, 0, static_cast<size_t>(num_slices) * sizeof(size_t));
    const RadixInsert* src = radix_buf->data();
    for (size_t i = 0; i < n; ++i) {
      ++counts[src[i].slice];
    }
    size_t offsets[kMaxSlices + 1];
    offsets[0] = 0;
    for (uint32_t s = 0; s < num_slices; ++s) {
      offsets[s + 1] = offsets[s] + counts[s];
    }
    size_t write_pos[kMaxSlices];
    std::memcpy(write_pos, offsets,
                static_cast<size_t>(num_slices) * sizeof(size_t));
    if (radix_tmp->size() < n) {
      radix_tmp->resize(n);
    }
    RadixInsert* dst = radix_tmp->data();
    for (size_t i = 0; i < n; ++i) {
      const RadixInsert& item = src[i];
      dst[write_pos[item.slice]++] = item;
    }
    uint32_t limit = local_mask + 1U;
    for (uint32_t s = 0; s < num_slices; ++s) {
      size_t beg = offsets[s];
      size_t end = offsets[s + 1];
      if (beg == end) continue;
      size_t slice_off = static_cast<size_t>(s) << kSliceBits;
      uint16_t* stags = tags.data() + slice_off;
      uint32_t* svals = vals.data() + slice_off;
      for (size_t k = beg; k < end; ++k) {
#if defined(__GNUC__) || defined(__clang__)
        if (k + kPrefetchDist < end) {
          uint32_t ppos = dst[k + kPrefetchDist].pos;
          __builtin_prefetch(&stags[ppos], 1, 1);
          __builtin_prefetch(&svals[ppos], 1, 1);
        }
#endif
        uint32_t pos = dst[k].pos;
        uint16_t tag = dst[k].tag;
        uint32_t val = dst[k].val;
        for (uint32_t step = 0; step < limit; ++step) {
          uint16_t cur = stags[pos];
          if (cur == 0U) {
            stags[pos] = tag;
            svals[pos] = val;
            break;
          }
          if (cur == tag && svals[pos] == val) {
            break;
          }
          pos = (pos + 1U) & local_mask;
        }
      }
    }
    radix_buf->clear();
  }

  template <typename MatchFn>
  inline void ProbeDirect(uint64_t hv, MatchFn&& on_match) const {
    size_t slice_off =
        sliced ? (static_cast<size_t>(SliceOf(hv)) << kSliceBits) : 0U;
    const uint16_t* stags = tags.data() + slice_off;
    uint32_t pos = static_cast<uint32_t>(hv) & local_mask;
    uint16_t cur = stags[pos];
    if (cur == 0U) return;
    const uint32_t* svals = vals.data() + slice_off;
    uint16_t tag = MakeTag16(hv);
    uint32_t limit = local_mask + 1U;
    for (uint32_t step = 0; step < limit && cur != 0U; ++step) {
      if (cur == tag) {
        on_match(svals[pos]);
      }
      pos = (pos + 1U) & local_mask;
      cur = stags[pos];
    }
  }

  template <typename MatchFn>
  inline void QueueProbe(uint64_t hv, uint32_t pt_off, int32_t g_step,
                         std::vector<RadixProbe>* probe_buf,
                         std::vector<RadixProbe>* probe_tmp,
                         MatchFn&& on_match) const {
    probe_buf->push_back(RadixProbe{
        static_cast<uint32_t>(hv) & local_mask,
        pt_off,
        g_step,
        static_cast<uint16_t>(SliceOf(hv)),
        MakeTag16(hv),
    });
    if (probe_buf->size() >= kRadixFlushThreshold) {
      FlushProbes(probe_buf, probe_tmp, on_match);
    }
  }

  template <typename MatchFn>
  void FlushProbes(std::vector<RadixProbe>* probe_buf,
                   std::vector<RadixProbe>* probe_tmp,
                   MatchFn&& on_match) const {
    size_t n = probe_buf->size();
    if (n == 0) return;
    size_t counts[kMaxSlices];
    std::memset(counts, 0, static_cast<size_t>(num_slices) * sizeof(size_t));
    const RadixProbe* src = probe_buf->data();
    for (size_t i = 0; i < n; ++i) {
      ++counts[src[i].slice];
    }
    size_t offsets[kMaxSlices + 1];
    offsets[0] = 0;
    for (uint32_t s = 0; s < num_slices; ++s) {
      offsets[s + 1] = offsets[s] + counts[s];
    }
    size_t write_pos[kMaxSlices];
    std::memcpy(write_pos, offsets,
                static_cast<size_t>(num_slices) * sizeof(size_t));
    if (probe_tmp->size() < n) {
      probe_tmp->resize(n);
    }
    RadixProbe* dst = probe_tmp->data();
    for (size_t i = 0; i < n; ++i) {
      const RadixProbe& item = src[i];
      dst[write_pos[item.slice]++] = item;
    }
    uint32_t limit = local_mask + 1U;
    for (uint32_t s = 0; s < num_slices; ++s) {
      size_t beg = offsets[s];
      size_t end = offsets[s + 1];
      if (beg == end) continue;
      size_t slice_off = static_cast<size_t>(s) << kSliceBits;
      const uint16_t* stags = tags.data() + slice_off;
      const uint32_t* svals = vals.data() + slice_off;
      for (size_t k = beg; k < end; ++k) {
#if defined(__GNUC__) || defined(__clang__)
        if (k + kPrefetchDist < end) {
          __builtin_prefetch(&stags[dst[k + kPrefetchDist].pos], 0, 1);
        }
#endif
        uint32_t pos = dst[k].pos;
        uint16_t cur = stags[pos];
        if (cur == 0U) continue;
        uint16_t tag = dst[k].tag;
        for (uint32_t step = 0; step < limit && cur != 0U; ++step) {
          if (cur == tag) {
            on_match(dst[k].pt_off, dst[k].g_step, svals[pos]);
          }
          pos = (pos + 1U) & local_mask;
          cur = stags[pos];
        }
      }
    }
    probe_buf->clear();
  }
};

mpz_class ImportLE(const void* data, size_t len) {
  mpz_class out;
  mpz_import(out.get_mpz_t(), len, /*order=*/-1, /*size=*/1, /*endian=*/0,
             /*nails=*/0, data);
  return out;
}

struct NafChain {
  int mult_idx;
  std::vector<int> pos_bits;
  std::vector<int> neg_bits;
};

std::vector<NafChain> BuildNafChains(std::string_view inverses_le,
                                     int scalar_bytes, int num_mult,
                                     int num_byte_shifts, int* max_naf_bit) {
  *max_naf_bit = 0;
  std::vector<int> direct_indices;
  if (num_byte_shifts > 1) {
    direct_indices.push_back(num_byte_shifts - 1);
  }
  for (int idx = num_byte_shifts; idx < num_mult; ++idx) {
    direct_indices.push_back(idx);
  }
  std::vector<NafChain> chains;
  chains.reserve(direct_indices.size());
  for (int idx : direct_indices) {
    mpz_class k = ImportLE(
        inverses_le.data() + static_cast<size_t>(idx) * scalar_bytes,
        static_cast<size_t>(scalar_bytes));
    NafChain chain;
    chain.mult_idx = idx;
    for (int bit = 0; k > 0; ++bit, k >>= 1) {
      if (mpz_odd_p(k.get_mpz_t())) {
        if ((k.get_ui() & 3UL) == 3UL) {
          chain.neg_bits.push_back(bit);
          ++k;
        } else {
          chain.pos_bits.push_back(bit);
          --k;
        }
        *max_naf_bit = std::max(*max_naf_bit, bit);
      }
    }
    chains.push_back(std::move(chain));
  }
  return chains;
}

class GmpCurveEngine final : public EcBatchEngine {
 public:
  struct AffinePoint {
    mpz_class x;
    mpz_class y;
    bool inf = true;
  };

  struct JacobianPoint {
    mpz_class x;
    mpz_class y;
    mpz_class z;
  };

  GmpCurveEngine(int coord_bytes, mpz_class mod, mpz_class a, mpz_class gx,
                 mpz_class gy)
      : coord_bytes_(coord_bytes),
        mod_(std::move(mod)),
        a_(std::move(a)),
        a_is_minus_3_((a_ + 3) == mod_),
        g_{std::move(gx), std::move(gy), false},
        table_size_(0) {}

  int coord_bytes() const override { return coord_bytes_; }
  int64_t table_size() const override { return table_size_; }

  inline void AddMod(mpz_class& r, const mpz_class& a,
                     const mpz_class& b) const {
    mpz_add(r.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    if (r >= mod_) mpz_sub(r.get_mpz_t(), r.get_mpz_t(), mod_.get_mpz_t());
  }

  inline void SubMod(mpz_class& r, const mpz_class& a,
                     const mpz_class& b) const {
    mpz_sub(r.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    if (r < 0) mpz_add(r.get_mpz_t(), r.get_mpz_t(), mod_.get_mpz_t());
  }

  // Computes r = (a * b) mod mod_ using `prod` to hold the unreduced product.
  inline void MulMod(mpz_class& r, const mpz_class& a, const mpz_class& b,
                     mpz_class& prod) const {
    mpz_mul(prod.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    mpz_tdiv_r(r.get_mpz_t(), prod.get_mpz_t(), mod_.get_mpz_t());
  }

  mpz_class AddMod(const mpz_class& a, const mpz_class& b) const {
    mpz_class r;
    AddMod(r, a, b);
    return r;
  }

  mpz_class SubMod(const mpz_class& a, const mpz_class& b) const {
    mpz_class r;
    SubMod(r, a, b);
    return r;
  }

  mpz_class MulMod(const mpz_class& a, const mpz_class& b) const {
    mpz_class r, prod;
    MulMod(r, a, b, prod);
    return r;
  }

  mpz_class NegMod(const mpz_class& a) const {
    return a == 0 ? mpz_class(0) : mpz_class(mod_ - a);
  }

  mpz_class InvMod(const mpz_class& a) const {
    mpz_class r;
    if (mpz_invert(r.get_mpz_t(), a.get_mpz_t(), mod_.get_mpz_t()) == 0) {
      return mpz_class(0);
    }
    return r;
  }

  static inline uint64_t HashMpz(const mpz_class& x) {
    mpz_srcptr xz = x.get_mpz_t();
    size_t n = mpz_size(xz);
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    for (size_t i = 0; i < n; ++i) {
      uint64_t w = static_cast<uint64_t>(mpz_getlimbn(xz, i));
      h ^= w * 0xBF58476D1CE4E5B9ULL + (h << 6) + (h >> 2);
    }
    h ^= h >> 30;
    h *= 0xBF58476D1CE4E5B9ULL;
    h ^= h >> 27;
    h *= 0x94D049BB133111EBULL;
    return h ^ (h >> 31);
  }

  static inline uint64_t PointXHash(const AffinePoint& p) {
    return p.inf ? kInfinityHash : HashMpz(p.x);
  }

  static AffinePoint AffineInf() { return AffinePoint{0, 0, true}; }
  static JacobianPoint JacobianInf() { return JacobianPoint{1, 1, 0}; }

  static JacobianPoint AffineToJacobian(const AffinePoint& p) {
    if (p.inf) return JacobianInf();
    return JacobianPoint{p.x, p.y, 1};
  }

  AffinePoint Negate(const AffinePoint& p) const {
    if (p.inf) return p;
    return AffinePoint{p.x, NegMod(p.y), false};
  }

  AffinePoint DoubleAffine(const AffinePoint& p) const {
    if (p.inf || p.y == 0) return AffineInf();
    mpz_class xsqr = MulMod(p.x, p.x);
    mpz_class num = AddMod(AddMod(AddMod(xsqr, xsqr), xsqr), a_);
    mpz_class t = MulMod(num, InvMod(AddMod(p.y, p.y)));
    mpz_class x2 = SubMod(MulMod(t, t), AddMod(p.x, p.x));
    mpz_class y2 = SubMod(MulMod(t, SubMod(p.x, x2)), p.y);
    return AffinePoint{std::move(x2), std::move(y2), false};
  }

  AffinePoint AddAffine(const AffinePoint& p, const AffinePoint& q) const {
    if (p.inf) return q;
    if (q.inf) return p;
    if (p.x == q.x) {
      return (p.y == q.y) ? DoubleAffine(p) : AffineInf();
    }
    mpz_class t = MulMod(SubMod(p.y, q.y), InvMod(SubMod(p.x, q.x)));
    mpz_class x3 = SubMod(SubMod(MulMod(t, t), p.x), q.x);
    mpz_class y3 = SubMod(MulMod(t, SubMod(p.x, x3)), p.y);
    return AffinePoint{std::move(x3), std::move(y3), false};
  }

  AffinePoint SubtractAffine(const AffinePoint& p, const AffinePoint& q) const {
    return AddAffine(p, Negate(q));
  }

  static bool EqualAffine(const AffinePoint& p, const AffinePoint& q) {
    if (p.inf != q.inf) return false;
    return p.inf || (p.x == q.x && p.y == q.y);
  }

  JacobianPoint DoubleJacobian(const JacobianPoint& p) const {
    if (p.z == 0 || p.y == 0) return JacobianInf();
    mpz_class prod, ysqr, zsqr, s, m, x2, y2, z2, tmp;
    MulMod(ysqr, p.y, p.y, prod);
    MulMod(zsqr, p.z, p.z, prod);
    MulMod(s, p.x, ysqr, prod);
    AddMod(s, s, s);
    AddMod(s, s, s);
    if (a_is_minus_3_) {
      AddMod(m, p.x, zsqr);
      SubMod(tmp, p.x, zsqr);
      MulMod(m, m, tmp, prod);
      AddMod(tmp, m, m);
      AddMod(m, tmp, m);
    } else {
      MulMod(m, p.x, p.x, prod);
      AddMod(tmp, m, m);
      AddMod(m, tmp, m);
      MulMod(tmp, zsqr, zsqr, prod);
      MulMod(tmp, a_, tmp, prod);
      AddMod(m, m, tmp);
    }
    MulMod(x2, m, m, prod);
    AddMod(tmp, s, s);
    SubMod(x2, x2, tmp);
    MulMod(tmp, ysqr, ysqr, prod);
    AddMod(tmp, tmp, tmp);
    AddMod(tmp, tmp, tmp);
    AddMod(tmp, tmp, tmp);
    SubMod(y2, s, x2);
    MulMod(y2, m, y2, prod);
    SubMod(y2, y2, tmp);
    MulMod(z2, p.y, p.z, prod);
    AddMod(z2, z2, z2);
    return JacobianPoint{std::move(x2), std::move(y2), std::move(z2)};
  }

  JacobianPoint AddJacobianAffine(const JacobianPoint& p,
                                  const AffinePoint& q) const {
    if (q.inf) return p;
    if (p.z == 0) return AffineToJacobian(q);
    mpz_class prod, z1sqr, u2, s2;
    MulMod(z1sqr, p.z, p.z, prod);
    MulMod(u2, q.x, z1sqr, prod);
    MulMod(s2, p.z, z1sqr, prod);
    MulMod(s2, q.y, s2, prod);
    if (p.x == u2) {
      return (p.y == s2) ? DoubleJacobian(p) : JacobianInf();
    }
    mpz_class h, hsqr, hcube, r, t, x3, y3, z3, tmp;
    SubMod(h, u2, p.x);
    MulMod(hsqr, h, h, prod);
    MulMod(hcube, hsqr, h, prod);
    SubMod(r, s2, p.y);
    MulMod(t, p.x, hsqr, prod);
    MulMod(x3, r, r, prod);
    SubMod(x3, x3, hcube);
    AddMod(tmp, t, t);
    SubMod(x3, x3, tmp);
    SubMod(y3, t, x3);
    MulMod(y3, r, y3, prod);
    MulMod(tmp, p.y, hcube, prod);
    SubMod(y3, y3, tmp);
    MulMod(z3, p.z, h, prod);
    return JacobianPoint{std::move(x3), std::move(y3), std::move(z3)};
  }

  AffinePoint JacobianToAffine(const JacobianPoint& p) const {
    if (p.z == 0) return AffineInf();
    mpz_class w = InvMod(p.z);
    mpz_class wsqr = MulMod(w, w);
    mpz_class wcube = MulMod(wsqr, w);
    return AffinePoint{MulMod(p.x, wsqr), MulMod(p.y, wcube), false};
  }

  // Caller guarantees valid[i] != 0 implies vals[i] != 0.
  void BatchInverse(const mpz_class* vals, const uint8_t* valid, size_t n,
                    mpz_class* out) const {
    mpz_class acc = 1;
    mpz_class prod, v;
    for (size_t i = 0; i < n; ++i) {
      if (valid[i]) {
        out[i] = acc;
        MulMod(acc, acc, vals[i], prod);
      }
    }
    mpz_class inv;
    if (mpz_invert(inv.get_mpz_t(), acc.get_mpz_t(), mod_.get_mpz_t()) == 0) {
      for (size_t i = 0; i < n; ++i) out[i] = 0;
      return;
    }
    for (size_t i = n; i-- > 0;) {
      if (valid[i]) {
        v = vals[i];
        MulMod(out[i], out[i], inv, prod);
        MulMod(inv, inv, v, prod);
      } else {
        out[i] = 0;
      }
    }
  }

  std::vector<AffinePoint> BatchJacobianToAffine(
      const std::vector<JacobianPoint>& pts) const {
    size_t n = pts.size();
    std::vector<mpz_class> zs(n);
    std::vector<uint8_t> valid(n, 0);
    for (size_t i = 0; i < n; ++i) {
      zs[i] = pts[i].z;
      valid[i] = (pts[i].z == 0) ? 0 : 1;
    }
    std::vector<mpz_class> invs(n);
    BatchInverse(zs.data(), valid.data(), n, invs.data());
    std::vector<AffinePoint> out(n);
    mpz_class prod, wsqr, wcube;
    for (size_t i = 0; i < n; ++i) {
      if (!valid[i]) {
        out[i] = AffineInf();
      } else {
        const mpz_class& w = invs[i];
        MulMod(wsqr, w, w, prod);
        MulMod(wcube, wsqr, w, prod);
        out[i].inf = false;
        MulMod(out[i].x, pts[i].x, wsqr, prod);
        MulMod(out[i].y, pts[i].y, wcube, prod);
      }
    }
    return out;
  }

  AffinePoint MultiplyInt64(AffinePoint p, int64_t scalar) const {
    if (p.inf || scalar == 0) return AffineInf();
    uint64_t mag;
    if (scalar < 0) {
      p = Negate(p);
      mag = static_cast<uint64_t>(-(scalar + 1)) + 1ULL;
    } else {
      mag = static_cast<uint64_t>(scalar);
    }
    if (mag == 1ULL) return p;
    int top = 63;
    while (((mag >> top) & 1ULL) == 0ULL) --top;
    JacobianPoint res = AffineToJacobian(p);
    for (int b = top - 1; b >= 0; --b) {
      res = DoubleJacobian(res);
      if ((mag >> b) & 1ULL) {
        res = AddJacobianAffine(res, p);
      }
    }
    return JacobianToAffine(res);
  }

  std::vector<AffinePoint> PointSequencePos(const AffinePoint& base,
                                            int64_t count) const {
    if (count <= 0) return {};
    std::vector<JacobianPoint> jac(static_cast<size_t>(count));
    jac[0] = AffineToJacobian(base);
    for (int64_t i = 1; i < count; ++i) {
      jac[static_cast<size_t>(i)] =
          AddJacobianAffine(jac[static_cast<size_t>(i - 1)], base);
    }
    return BatchJacobianToAffine(jac);
  }

  std::vector<AffinePoint> BatchAdd(const AffinePoint& p,
                                    const AffinePoint* pts, size_t n) const {
    std::vector<AffinePoint> out(n);
    if (p.inf) {
      for (size_t i = 0; i < n; ++i) out[i] = pts[i];
      return out;
    }
    std::vector<mpz_class> dx(n);
    std::vector<uint8_t> valid(n, 0);
    for (size_t i = 0; i < n; ++i) {
      if (!pts[i].inf) {
        SubMod(dx[i], p.x, pts[i].x);
        if (dx[i] != 0) valid[i] = 1;
      }
    }
    std::vector<mpz_class> inv(n);
    BatchInverse(dx.data(), valid.data(), n, inv.data());
    mpz_class prod, t, tmp;
    for (size_t i = 0; i < n; ++i) {
      if (valid[i]) {
        SubMod(tmp, p.y, pts[i].y);
        MulMod(t, inv[i], tmp, prod);
        MulMod(out[i].x, t, t, prod);
        SubMod(out[i].x, out[i].x, p.x);
        SubMod(out[i].x, out[i].x, pts[i].x);
        SubMod(tmp, p.x, out[i].x);
        MulMod(out[i].y, t, tmp, prod);
        SubMod(out[i].y, out[i].y, p.y);
        out[i].inf = false;
      } else {
        out[i] = AddAffine(p, pts[i]);
      }
    }
    return out;
  }

  void BatchMultiAddSubtractHashes(const AffinePoint* pts, size_t n_pts,
                                   const AffinePoint* seq, size_t seq_len,
                                   std::vector<mpz_class>* dx_buf,
                                   std::vector<uint8_t>* valid_buf,
                                   std::vector<mpz_class>* inv_buf,
                                   uint64_t* sum_hashes,
                                   uint64_t* diff_hashes) const {
    size_t total = n_pts * seq_len;
    if (total == 0) return;
    if (dx_buf->size() < total) {
      dx_buf->resize(total);
      valid_buf->resize(total);
      inv_buf->resize(total);
    }
    mpz_class* dx = dx_buf->data();
    uint8_t* valid = valid_buf->data();
    mpz_class* inv = inv_buf->data();

    for (size_t i = 0; i < n_pts; ++i) {
      size_t base = i * seq_len;
      if (pts[i].inf) {
        std::memset(valid + base, 0, seq_len);
        continue;
      }
      const mpz_class& px = pts[i].x;
      for (size_t k = 0; k < seq_len; ++k) {
        if (seq[k].inf) {
          valid[base + k] = 0;
        } else {
          SubMod(dx[base + k], px, seq[k].x);
          valid[base + k] = (dx[base + k] == 0) ? 0 : 1;
        }
      }
    }

    BatchInverse(dx, valid, total, inv);

    mpz_class prod, sx, t, x_out;
    for (size_t i = 0; i < n_pts; ++i) {
      size_t base = i * seq_len;
      const AffinePoint& p = pts[i];
      if (p.inf) {
        for (size_t k = 0; k < seq_len; ++k) {
          uint64_t hq = PointXHash(seq[k]);
          sum_hashes[base + k] = hq;
          diff_hashes[base + k] = hq;
        }
        continue;
      }
      const mpz_class& px = p.x;
      const mpz_class& py = p.y;
      for (size_t k = 0; k < seq_len; ++k) {
        size_t idx = base + k;
        if (valid[idx]) {
          const mpz_class& qx = seq[k].x;
          const mpz_class& qy = seq[k].y;
          const mpz_class& v = inv[idx];
          AddMod(sx, px, qx);

          SubMod(t, py, qy);
          MulMod(t, v, t, prod);
          MulMod(x_out, t, t, prod);
          SubMod(x_out, x_out, sx);
          sum_hashes[idx] = HashMpz(x_out);

          AddMod(t, py, qy);
          MulMod(t, v, t, prod);
          MulMod(x_out, t, t, prod);
          SubMod(x_out, x_out, sx);
          diff_hashes[idx] = HashMpz(x_out);
        } else {
          sum_hashes[idx] = PointXHash(AddAffine(p, seq[k]));
          diff_hashes[idx] = PointXHash(SubtractAffine(p, seq[k]));
        }
      }
    }
  }

  bool UnpackPoints(std::string_view packed,
                    std::vector<AffinePoint>* pts) const {
    size_t stride = 1 + 2 * static_cast<size_t>(coord_bytes_);
    if (packed.size() % stride != 0) return false;
    size_t n = packed.size() / stride;
    pts->resize(n);
    const char* ptr = packed.data();
    size_t cb = static_cast<size_t>(coord_bytes_);
    for (size_t i = 0; i < n; ++i) {
      const char* rec = ptr + i * stride;
      if (rec[0] == 0) {
        (*pts)[i] = AffineInf();
      } else {
        (*pts)[i].x = ImportLE(rec + 1, cb);
        (*pts)[i].y = ImportLE(rec + 1 + cb, cb);
        (*pts)[i].inf = false;
      }
    }
    return true;
  }

  void EnsureTable(int64_t target_size) override {
    target_size = std::min<int64_t>(target_size, kMaxDlTableSize);
    if (target_size <= table_size_) return;

    int64_t start = table_size_;
    int64_t count = target_size - start;
    if (count <= 2 &&
        SlicedHashTable48::ComputeNeededSlots(target_size, 75) <=
            table_.total_slots) {
      for (int64_t i = 0; i < count; ++i) {
        AffinePoint pt = MultiplyInt64(g_, start + i);
        table_.InsertOneDirect(PointXHash(pt),
                               static_cast<uint32_t>(start + i));
      }
      table_size_ = target_size;
      return;
    }
    if (target_size <= 2) {
      table_.InitForEntries(target_size, /*max_load_pct=*/75);
      for (int64_t i = 0; i < target_size; ++i) {
        AffinePoint pt = MultiplyInt64(g_, i);
        table_.InsertOneDirect(PointXHash(pt), static_cast<uint32_t>(i));
      }
      table_size_ = target_size;
      return;
    }

    int64_t h =
        std::max<int64_t>(1, static_cast<int64_t>(std::sqrt(count / 2.0)));
    int64_t m = 2 * h + 1;
    int64_t r = (count + m - 1) / m;
    int64_t final_size = start + r * m;
    if (SlicedHashTable48::ComputeNeededSlots(final_size, 76) >
        table_.total_slots) {
      start = 0;
      count = target_size;
      h = std::max<int64_t>(1, static_cast<int64_t>(std::sqrt(count / 2.0)));
      m = 2 * h + 1;
      r = (count + m - 1) / m;
      final_size = r * m;
      table_.InitForEntries(final_size, /*max_load_pct=*/75);
      table_size_ = 0;
    }

    std::vector<AffinePoint> seq_low = PointSequencePos(g_, h);
    AffinePoint step_aff = MultiplyInt64(g_, m);
    std::vector<JacobianPoint> high_jac(static_cast<size_t>(r));
    high_jac[0] = (start == 0)
                      ? AffineToJacobian(seq_low[static_cast<size_t>(h - 1)])
                      : AffineToJacobian(MultiplyInt64(g_, start + h));
    for (int64_t i = 1; i < r; ++i) {
      high_jac[static_cast<size_t>(i)] =
          AddJacobianAffine(high_jac[static_cast<size_t>(i - 1)], step_aff);
    }
    std::vector<AffinePoint> seq_high = BatchJacobianToAffine(high_jac);
    std::vector<JacobianPoint>().swap(high_jac);

    size_t h_sz = static_cast<size_t>(h);
    size_t sub_size = std::max<size_t>(1, 4096 / std::max<size_t>(1, h_sz));
    std::vector<mpz_class> dx_buf, inv_buf;
    std::vector<uint8_t> valid_buf;
    std::vector<uint64_t> sum_hashes(sub_size * h_sz);
    std::vector<uint64_t> diff_hashes(sub_size * h_sz);
    std::vector<SlicedHashTable48::RadixInsert> radix_buf, radix_tmp;
    if (table_.sliced) {
      radix_buf.reserve(SlicedHashTable48::kRadixFlushThreshold);
    }

    size_t r_sz = static_cast<size_t>(r);
    for (size_t sub_start = 0; sub_start < r_sz; sub_start += sub_size) {
      size_t cur_n = std::min(sub_size, r_sz - sub_start);
      BatchMultiAddSubtractHashes(&seq_high[sub_start], cur_n, seq_low.data(),
                                  h_sz, &dx_buf, &valid_buf, &inv_buf,
                                  sum_hashes.data(), diff_hashes.data());
      for (size_t off = 0; off < cur_n; ++off) {
        int64_t center =
            start + static_cast<int64_t>(sub_start + off) * m + h;
        table_.QueueInsert(PointXHash(seq_high[sub_start + off]),
                           static_cast<uint32_t>(center), &radix_buf,
                           &radix_tmp);
        size_t base = off * h_sz;
        for (size_t j = 0; j < h_sz; ++j) {
          table_.QueueInsert(
              diff_hashes[base + j],
              static_cast<uint32_t>(center - static_cast<int64_t>(j) - 1),
              &radix_buf, &radix_tmp);
          table_.QueueInsert(
              sum_hashes[base + j],
              static_cast<uint32_t>(center + static_cast<int64_t>(j) + 1),
              &radix_buf, &radix_tmp);
        }
      }
    }
    table_.FlushInserts(&radix_buf, &radix_tmp);
    table_size_ = final_size;
  }

  std::vector<std::pair<int64_t, int64_t>> BatchDLPoints(
      const AffinePoint* pts, size_t n_pts, int64_t n,
      int64_t expected_points) {
    std::vector<std::pair<int64_t, int64_t>> matches;
    if (n_pts == 0 || n <= 0) return matches;
    int64_t target_count =
        expected_points > 0 ? expected_points : static_cast<int64_t>(n_pts);
    double prod =
        static_cast<double>(n) * static_cast<double>(target_count) / 2.0;
    int64_t desired_table = std::min<int64_t>(
        kMaxDlTableSize,
        std::max<int64_t>(1, static_cast<int64_t>(std::sqrt(prod))));
    if (desired_table > table_size_) {
      EnsureTable(desired_table);
    }
    int64_t t = 2 * table_size_ - 1;
    int64_t giant_steps = 2 + n / t;

    auto verify_candidate = [&](size_t pt_idx, int64_t j_step, uint32_t tb_x,
                                int64_t* solved_dl) -> bool {
      const AffinePoint& p = pts[pt_idx];
      int64_t cands[2] = {j_step * t + static_cast<int64_t>(tb_x),
                          j_step * t - static_cast<int64_t>(tb_x)};
      for (int c = 0; c < 2; ++c) {
        int64_t dl = cands[c];
        AffinePoint y = MultiplyInt64(g_, dl);
        if (!y.inf && y.x == p.x) {
          if (y.y == p.y) {
            *solved_dl = dl;
            return true;
          }
          if (y.y == NegMod(p.y)) {
            *solved_dl = -dl;
            return true;
          }
        }
      }
      return false;
    };

    if (giant_steps <= 2) {
      std::vector<AffinePoint> list_c = {AffineInf()};
      if (giant_steps == 2) list_c.push_back(MultiplyInt64(g_, -t));
      for (size_t i = 0; i < n_pts; ++i) {
        if (pts[i].inf) {
          matches.push_back({static_cast<int64_t>(i), 0});
          continue;
        }
        bool found = false;
        int64_t best_dl = 0;
        for (size_t j = 0; j < list_c.size(); ++j) {
          AffinePoint sum_pt = AddAffine(pts[i], list_c[j]);
          table_.ProbeDirect(PointXHash(sum_pt), [&](uint32_t tb_x) {
            int64_t solved = 0;
            if (verify_candidate(i, static_cast<int64_t>(j), tb_x, &solved)) {
              best_dl = solved;
              found = true;
            }
          });
        }
        if (found) matches.push_back({static_cast<int64_t>(i), best_dl});
      }
      return matches;
    }

    int64_t h = giant_steps / 2;
    size_t h_sz = static_cast<size_t>(h);
    AffinePoint shift_pt = MultiplyInt64(g_, -h * t);
    std::vector<AffinePoint> list_c = PointSequencePos(MultiplyInt64(g_, t), h);

    constexpr size_t kDlChunk = 4096;
    size_t sub_size = std::max<size_t>(1, 4096 / std::max<size_t>(1, h_sz));
    std::vector<mpz_class> dx_buf, inv_buf;
    std::vector<uint8_t> valid_buf;
    std::vector<uint64_t> sum_hashes(sub_size * h_sz);
    std::vector<uint64_t> diff_hashes(sub_size * h_sz);

    bool use_radix_probes = table_.sliced && (giant_steps <= 1000000000LL);
    std::vector<SlicedHashTable48::RadixProbe> probe_buf, probe_tmp;
    if (use_radix_probes) {
      probe_buf.reserve(std::min<size_t>(
          SlicedHashTable48::kRadixFlushThreshold,
          std::min(n_pts, kDlChunk) * (1 + 2 * h_sz)));
    }

    for (size_t start = 0; start < n_pts; start += kDlChunk) {
      size_t chunk_len = std::min(kDlChunk, n_pts - start);
      std::vector<AffinePoint> shifted =
          BatchAdd(shift_pt, pts + start, chunk_len);
      auto on_match = [&](uint32_t pt_off, int32_t j_step, uint32_t tb_x) {
        size_t global_idx = start + static_cast<size_t>(pt_off);
        int64_t solved = 0;
        if (verify_candidate(global_idx, j_step, tb_x, &solved)) {
          matches.push_back({static_cast<int64_t>(global_idx), solved});
        }
      };
      auto emit_probe = [&](uint64_t hv, uint32_t pt_off, int32_t j_step) {
        if (use_radix_probes) {
          table_.QueueProbe(hv, pt_off, j_step, &probe_buf, &probe_tmp,
                            on_match);
        } else {
          table_.ProbeDirect(hv, [&](uint32_t tb_x) {
            on_match(pt_off, j_step, tb_x);
          });
        }
      };

      for (size_t sub_start = 0; sub_start < chunk_len; sub_start += sub_size) {
        size_t cur_n = std::min(sub_size, chunk_len - sub_start);
        BatchMultiAddSubtractHashes(
            &shifted[sub_start], cur_n, list_c.data(), h_sz, &dx_buf,
            &valid_buf, &inv_buf, sum_hashes.data(), diff_hashes.data());
        for (size_t off = 0; off < cur_n; ++off) {
          size_t chunk_off = sub_start + off;
          size_t global_idx = start + chunk_off;
          if (pts[global_idx].inf) {
            matches.push_back({static_cast<int64_t>(global_idx), 0});
            continue;
          }
          uint32_t pt_off = static_cast<uint32_t>(chunk_off);
          emit_probe(PointXHash(shifted[chunk_off]), pt_off,
                     static_cast<int32_t>(h));
          size_t base = off * h_sz;
          for (size_t k = 0; k < h_sz; ++k) {
            emit_probe(sum_hashes[base + k], pt_off,
                       static_cast<int32_t>(h - static_cast<int64_t>(k) - 1));
            emit_probe(diff_hashes[base + k], pt_off,
                       static_cast<int32_t>(h + static_cast<int64_t>(k) + 1));
          }
        }
      }
      if (use_radix_probes) {
        table_.FlushProbes(&probe_buf, &probe_tmp, on_match);
      }
    }
    return matches;
  }

  bool BatchDL(std::string_view points_le, int64_t n, int64_t expected_points,
               std::vector<std::pair<int64_t, int64_t>>* out) override {
    std::vector<AffinePoint> pts;
    if (!UnpackPoints(points_le, &pts)) return false;
    *out = BatchDLPoints(pts.data(), pts.size(), n, expected_points);
    return true;
  }

  bool ExtendedBatchDL(std::string_view points_le,
                       std::string_view inverses_le, int scalar_bytes,
                       int num_byte_shifts, int num_window_mults,
                       std::string_view comp_points_le,
                       std::vector<ExtendedDlMatch>* out_ptr) override {
    std::vector<ExtendedDlMatch>& out = *out_ptr;
    out.clear();
    std::vector<AffinePoint> valid_pts, comp_pts;
    if (!UnpackPoints(points_le, &valid_pts) || scalar_bytes <= 0 ||
        inverses_le.size() % scalar_bytes != 0 ||
        !UnpackPoints(comp_points_le, &comp_pts)) {
      return false;
    }
    if (num_window_mults < 0 ||
        (num_window_mults == 0 && !comp_pts.empty()) ||
        (num_window_mults > 0 &&
         comp_pts.size() % static_cast<size_t>(num_window_mults) != 0)) {
      return false;
    }
    size_t num_valid = valid_pts.size();
    if (num_valid == 0) return true;

    int num_mult = static_cast<int>(inverses_le.size() / scalar_bytes);
    int num_extra = num_mult - 1;
    int num_comp_total = static_cast<int>(comp_pts.size());

    int max_naf_bit = 0;
    std::vector<NafChain> naf_chains = BuildNafChains(
        inverses_le, scalar_bytes, num_mult, num_byte_shifts, &max_naf_bit);

    int64_t targets_per_key = static_cast<int64_t>(num_mult) + 1 +
                              static_cast<int64_t>(num_comp_total);
    int64_t expected_total =
        targets_per_key * static_cast<int64_t>(num_valid);

    constexpr size_t kKeyChunk = 512;
    constexpr size_t kNafSubBatch = 32;
    size_t m_bits = static_cast<size_t>(max_naf_bit + 1);

    for (size_t v_start = 0; v_start < num_valid; v_start += kKeyChunk) {
      size_t c_len = std::min(kKeyChunk, num_valid - v_start);
      const AffinePoint* v_chunk = &valid_pts[v_start];

      std::vector<AffinePoint> affine_extra;
      if (num_extra > 0) {
        std::vector<JacobianPoint> jac_chunk(
            c_len * static_cast<size_t>(num_extra), JacobianInf());
        for (size_t sub_off = 0; sub_off < c_len; sub_off += kNafSubBatch) {
          size_t sub_c = std::min(kNafSubBatch, c_len - sub_off);
          std::vector<JacobianPoint> d_jac(sub_c * m_bits);
          for (size_t s_i = 0; s_i < sub_c; ++s_i) {
            JacobianPoint cur = AffineToJacobian(v_chunk[sub_off + s_i]);
            JacobianPoint* row = &d_jac[s_i * m_bits];
            for (size_t b = 0; b < m_bits; ++b) {
              row[b] = cur;
              if (b + 1 < m_bits) cur = DoubleJacobian(cur);
            }
          }
          std::vector<AffinePoint> d_aff = BatchJacobianToAffine(d_jac);
          for (size_t s_i = 0; s_i < sub_c; ++s_i) {
            size_t base_off =
                (sub_off + s_i) * static_cast<size_t>(num_extra);
            const AffinePoint* dp = &d_aff[s_i * m_bits];
            for (const NafChain& chain : naf_chains) {
              JacobianPoint acc = JacobianInf();
              size_t start_pos = 0;
              if (!chain.pos_bits.empty()) {
                acc = AffineToJacobian(
                    dp[static_cast<size_t>(chain.pos_bits[0])]);
                start_pos = 1;
              }
              for (size_t idx = start_pos; idx < chain.pos_bits.size(); ++idx) {
                acc = AddJacobianAffine(
                    acc, dp[static_cast<size_t>(chain.pos_bits[idx])]);
              }
              for (int nb : chain.neg_bits) {
                acc =
                    AddJacobianAffine(acc, Negate(dp[static_cast<size_t>(nb)]));
              }
              jac_chunk[base_off + static_cast<size_t>(chain.mult_idx - 1)] =
                  std::move(acc);
            }
            if (num_byte_shifts > 2) {
              size_t top_off =
                  base_off + static_cast<size_t>(num_byte_shifts - 2);
              JacobianPoint acc = jac_chunk[top_off];
              for (int j = num_byte_shifts - 2; j >= 1; --j) {
                for (int d = 0; d < 8; ++d) acc = DoubleJacobian(acc);
                jac_chunk[base_off + static_cast<size_t>(j - 1)] = acc;
              }
            }
          }
        }
        affine_extra = BatchJacobianToAffine(jac_chunk);
      }

      std::vector<std::vector<AffinePoint>> neg_windows(
          static_cast<size_t>(num_window_mults));
      if (num_window_mults > 0) {
        neg_windows[0].resize(c_len);
        for (size_t i = 0; i < c_len; ++i) {
          neg_windows[0][i] = Negate(v_chunk[i]);
        }
        for (int m_idx = 1; m_idx < num_window_mults; ++m_idx) {
          neg_windows[static_cast<size_t>(m_idx)].resize(c_len);
          size_t off = static_cast<size_t>(m_idx - 1);
          for (size_t i = 0; i < c_len; ++i) {
            neg_windows[static_cast<size_t>(m_idx)][i] =
                Negate(affine_extra[i * static_cast<size_t>(num_extra) + off]);
          }
        }
      }

      std::vector<AffinePoint> chunk_targets;
      chunk_targets.reserve(c_len * static_cast<size_t>(targets_per_key));
      chunk_targets.insert(chunk_targets.end(), v_chunk, v_chunk + c_len);
      chunk_targets.insert(chunk_targets.end(), affine_extra.begin(),
                           affine_extra.end());
      if (!neg_windows.empty()) {
        chunk_targets.insert(chunk_targets.end(), neg_windows[0].begin(),
                             neg_windows[0].end());
      } else {
        for (size_t i = 0; i < c_len; ++i) {
          chunk_targets.push_back(Negate(v_chunk[i]));
        }
      }
      for (int c_idx = 0; c_idx < num_comp_total; ++c_idx) {
        int m_idx = c_idx % num_window_mults;
        std::vector<AffinePoint> added =
            BatchAdd(comp_pts[static_cast<size_t>(c_idx)],
                     neg_windows[static_cast<size_t>(m_idx)].data(), c_len);
        chunk_targets.insert(chunk_targets.end(), added.begin(), added.end());
      }

      std::vector<std::pair<int64_t, int64_t>> dl_hits =
          BatchDLPoints(chunk_targets.data(), chunk_targets.size(), 1LL << 32,
                        expected_total);

      int64_t c_len_i64 = static_cast<int64_t>(c_len);
      int64_t extra_end = c_len_i64 * num_mult;
      int64_t neg_end = extra_end + c_len_i64;
      for (const auto& [k, dlog] : dl_hits) {
        ExtendedDlMatch match;
        match.signed_dl = dlog;
        if (k < c_len_i64) {
          match.key_index = static_cast<int64_t>(v_start) + k;
          match.kind = 0;
          match.aux_index = 0;
        } else if (k < extra_end) {
          int64_t rel = k - c_len_i64;
          match.key_index = static_cast<int64_t>(v_start) + (rel / num_extra);
          match.kind = 1;
          match.aux_index = static_cast<int32_t>((rel % num_extra) + 1);
        } else if (k < neg_end) {
          match.key_index = static_cast<int64_t>(v_start) + (k - extra_end);
          match.kind = 2;
          match.aux_index = 0;
        } else {
          int64_t rel = k - neg_end;
          match.key_index = static_cast<int64_t>(v_start) + (rel % c_len_i64);
          match.kind = 3;
          match.aux_index = static_cast<int32_t>(rel / c_len_i64);
        }
        out.push_back(match);
      }
    }
    return true;
  }

  bool DiffBatchDL(std::string_view points_le,
                   std::string_view other_points_le, int64_t max_diff,
                   int64_t max_baby_entries,
                   std::vector<DiffDlMatch>* out_ptr) override {
    std::vector<DiffDlMatch>& out = *out_ptr;
    out.clear();
    std::vector<AffinePoint> points, other_points;
    if (!UnpackPoints(points_le, &points) ||
        !UnpackPoints(other_points_le, &other_points)) {
      return false;
    }
    size_t n_pts_orig = points.size();
    size_t m_other_orig = other_points.size();
    if (n_pts_orig == 0 || n_pts_orig + m_other_orig < 2 || max_diff <= 1) {
      return true;
    }

    std::vector<int64_t> other_orig_idx;
    if (m_other_orig > 0) {
      other_orig_idx.reserve(m_other_orig);
      size_t cap = 16;
      while (cap * 3 < m_other_orig * 4) cap <<= 1;
      size_t mask = cap - 1;
      std::vector<uint32_t> seen(cap, 0U);
      size_t u_m = 0;
      for (size_t j = 0; j < m_other_orig; ++j) {
        const AffinePoint& pt = other_points[j];
        size_t pos = static_cast<size_t>(PointXHash(pt)) & mask;
        bool dup = false;
        while (seen[pos] != 0U) {
          uint32_t prev = seen[pos] - 1U;
          if (EqualAffine(other_points[prev], pt)) {
            other_orig_idx[prev] = static_cast<int64_t>(j);
            dup = true;
            break;
          }
          pos = (pos + 1) & mask;
        }
        if (!dup) {
          if (u_m != j) other_points[u_m] = pt;
          other_orig_idx.push_back(static_cast<int64_t>(j));
          seen[pos] = static_cast<uint32_t>(u_m + 1);
          ++u_m;
        }
      }
      other_points.resize(u_m);
    }

    std::vector<int32_t> u_head;
    std::vector<int32_t> orig_next(n_pts_orig, -1);
    {
      u_head.reserve(n_pts_orig);
      std::vector<int32_t> u_tail;
      u_tail.reserve(n_pts_orig);
      size_t cap = 16;
      while (cap * 3 < n_pts_orig * 4) cap <<= 1;
      size_t mask = cap - 1;
      std::vector<uint32_t> seen(cap, 0U);
      size_t u_n = 0;
      for (size_t i = 0; i < n_pts_orig; ++i) {
        const AffinePoint& pt = points[i];
        size_t pos = static_cast<size_t>(PointXHash(pt)) & mask;
        bool dup = false;
        while (seen[pos] != 0U) {
          uint32_t prev = seen[pos] - 1U;
          if (EqualAffine(points[prev], pt)) {
            orig_next[static_cast<size_t>(u_tail[prev])] =
                static_cast<int32_t>(i);
            u_tail[prev] = static_cast<int32_t>(i);
            dup = true;
            break;
          }
          pos = (pos + 1) & mask;
        }
        if (!dup) {
          if (u_n != i) points[u_n] = pt;
          u_head.push_back(static_cast<int32_t>(i));
          u_tail.push_back(static_cast<int32_t>(i));
          seen[pos] = static_cast<uint32_t>(u_n + 1);
          ++u_n;
        }
      }
      points.resize(u_n);
    }

    int64_t n_pts = static_cast<int64_t>(points.size());
    int64_t m_other = static_cast<int64_t>(other_points.size());
    int64_t m_other_orig_i64 = static_cast<int64_t>(m_other_orig);
    if (n_pts == 0 || n_pts + m_other < 2) return true;

    int64_t max_entries =
        std::min<int64_t>(kDefaultMaxDiffBabyEntries,
                          std::max<int64_t>(3, max_baby_entries));
    bool symmetric_pos_only = (m_other == 0);
    int64_t total_baby = symmetric_pos_only
                             ? n_pts
                             : (m_other + std::max<int64_t>(0, n_pts - 1));

    double opt_h_f = symmetric_pos_only
                         ? (std::sqrt(static_cast<double>(max_diff)) / 2.0)
                         : std::sqrt(static_cast<double>(max_diff) / 2.0);
    int64_t h_opt = std::max<int64_t>(1, static_cast<int64_t>(opt_h_f));
    int64_t h =
        (total_baby > 0 && max_entries / total_baby >= 3)
            ? std::max<int64_t>(
                  1, std::min(h_opt, (max_entries / total_baby - 1) / 2))
            : std::max<int64_t>(1, std::min(h_opt, (max_entries - 1) / 2));
    int64_t m = 2 * h + 1;
    int64_t g_max = (max_diff - 1 + h) / m;
    int64_t pts_per_tile = std::max<int64_t>(1, max_entries / m);

    std::vector<AffinePoint> seq_baby = PointSequencePos(g_, h);
    AffinePoint gm_pt = MultiplyInt64(g_, m);

    int64_t center_g = symmetric_pos_only ? ((g_max + 1) / 2) : 0;
    int64_t giant_seq_len = symmetric_pos_only ? center_g : g_max;
    std::vector<AffinePoint> seq_giant =
        giant_seq_len > 0 ? PointSequencePos(gm_pt, giant_seq_len)
                          : std::vector<AffinePoint>{};
    AffinePoint shift_pt = (symmetric_pos_only && center_g > 0)
                               ? MultiplyInt64(g_, -center_g * m)
                               : AffineInf();

    size_t h_sz = static_cast<size_t>(h);
    size_t g_sz = static_cast<size_t>(giant_seq_len);
    size_t b_chunk = std::max<size_t>(1, 4096 / std::max<size_t>(1, h_sz));
    size_t g_chunk = std::max<size_t>(1, 4096 / std::max<size_t>(1, g_sz));

    std::vector<mpz_class> dx_buf, inv_buf;
    std::vector<uint8_t> valid_buf;
    size_t max_pairs =
        std::max(b_chunk * h_sz, g_chunk * std::max<size_t>(1, g_sz));
    std::vector<uint64_t> sum_hashes(max_pairs), diff_hashes(max_pairs);

    auto get_baby_point = [&](int64_t global_baby_idx) -> const AffinePoint& {
      return (global_baby_idx < m_other)
                 ? other_points[static_cast<size_t>(global_baby_idx)]
                 : points[static_cast<size_t>(global_baby_idx - m_other)];
    };

    std::vector<uint8_t> matched(static_cast<size_t>(n_pts), 0);
    std::vector<AffinePoint> baby_sub_pts(b_chunk);
    uint32_t m_u32 = static_cast<uint32_t>(m);
    constexpr int64_t kOuterChunk = 4096;

    auto verify_hit = [&](int64_t u_i, int64_t ref_base, int32_t g_step,
                          uint32_t linear_id) {
      int64_t ref_idx = ref_base + static_cast<int64_t>(linear_id / m_u32);
      if (!symmetric_pos_only && ref_idx >= m_other + u_i) return;
      bool need_check = !matched[static_cast<size_t>(u_i)] ||
                        (ref_idx >= m_other &&
                         !matched[static_cast<size_t>(ref_idx - m_other)]);
      if (!need_check) return;
      int64_t b = static_cast<int64_t>(linear_id % m_u32) - h;
      int64_t dl = static_cast<int64_t>(g_step) * m + b;
      bool in_bounds = symmetric_pos_only
                           ? (dl > 0 && dl < max_diff)
                           : (dl != 0 && dl > -max_diff && dl < max_diff);
      if (!in_bounds) return;
      const AffinePoint& p = points[static_cast<size_t>(u_i)];
      const AffinePoint& q = get_baby_point(ref_idx);
      if (!EqualAffine(p, q) &&
          EqualAffine(SubtractAffine(p, q), MultiplyInt64(g_, dl))) {
        matched[static_cast<size_t>(u_i)] = 1;
        int32_t rep_i = u_head[static_cast<size_t>(u_i)];
        if (ref_idx < m_other) {
          int64_t orig_ref = other_orig_idx[static_cast<size_t>(ref_idx)];
          for (int32_t cur = rep_i; cur != -1;
               cur = orig_next[static_cast<size_t>(cur)]) {
            out.push_back(DiffDlMatch{static_cast<int64_t>(cur), orig_ref, dl});
          }
        } else {
          size_t u_j = static_cast<size_t>(ref_idx - m_other);
          matched[u_j] = 1;
          int32_t rep_j = u_head[u_j];
          for (int32_t cur = rep_i; cur != -1;
               cur = orig_next[static_cast<size_t>(cur)]) {
            out.push_back(DiffDlMatch{
                static_cast<int64_t>(cur),
                m_other_orig_i64 + static_cast<int64_t>(rep_j), dl});
          }
          for (int32_t cur = orig_next[static_cast<size_t>(rep_j)]; cur != -1;
               cur = orig_next[static_cast<size_t>(cur)]) {
            out.push_back(DiffDlMatch{
                static_cast<int64_t>(cur),
                m_other_orig_i64 + static_cast<int64_t>(rep_i), -dl});
          }
        }
      }
    };

    std::vector<SlicedHashTable48::RadixInsert> insert_buf, insert_tmp;
    std::vector<SlicedHashTable48::RadixProbe> probe_buf, probe_tmp;

    for (int64_t t_start = 0; t_start < total_baby; t_start += pts_per_tile) {
      int64_t t_end = std::min(total_baby, t_start + pts_per_tile);
      SlicedHashTable48 baby_table;
      baby_table.InitForEntries((t_end - t_start) * m, /*max_load_pct=*/78);
      bool use_radix_probes = baby_table.sliced && (g_max <= 1000000000LL);
      if (baby_table.sliced) {
        insert_buf.reserve(SlicedHashTable48::kRadixFlushThreshold);
        probe_buf.reserve(SlicedHashTable48::kRadixFlushThreshold);
      }

      for (int64_t b_pos = t_start; b_pos < t_end;
           b_pos += static_cast<int64_t>(b_chunk)) {
        size_t cur_n =
            static_cast<size_t>(std::min<int64_t>(b_chunk, t_end - b_pos));
        for (size_t off = 0; off < cur_n; ++off) {
          baby_sub_pts[off] = get_baby_point(b_pos + static_cast<int64_t>(off));
        }
        BatchMultiAddSubtractHashes(baby_sub_pts.data(), cur_n, seq_baby.data(),
                                    h_sz, &dx_buf, &valid_buf, &inv_buf,
                                    sum_hashes.data(), diff_hashes.data());
        for (size_t off = 0; off < cur_n; ++off) {
          uint32_t local_base = static_cast<uint32_t>(
              (b_pos - t_start + static_cast<int64_t>(off)) * m);
          baby_table.QueueInsert(PointXHash(baby_sub_pts[off]),
                                 local_base + static_cast<uint32_t>(h),
                                 &insert_buf, &insert_tmp);
          size_t base = off * h_sz;
          for (size_t k = 0; k < h_sz; ++k) {
            uint32_t b_step = static_cast<uint32_t>(k + 1);
            baby_table.QueueInsert(
                sum_hashes[base + k],
                local_base + static_cast<uint32_t>(h) + b_step, &insert_buf,
                &insert_tmp);
            baby_table.QueueInsert(
                diff_hashes[base + k],
                local_base + static_cast<uint32_t>(h) - b_step, &insert_buf,
                &insert_tmp);
          }
        }
      }
      baby_table.FlushInserts(&insert_buf, &insert_tmp);
      std::vector<SlicedHashTable48::RadixInsert>().swap(insert_buf);
      std::vector<SlicedHashTable48::RadixInsert>().swap(insert_tmp);

      int64_t p_start = (!symmetric_pos_only && t_start >= m_other)
                            ? (t_start - m_other + 1)
                            : 0;

      for (int64_t outer_start = p_start; outer_start < n_pts;
           outer_start += kOuterChunk) {
        size_t outer_len = static_cast<size_t>(
            std::min<int64_t>(kOuterChunk, n_pts - outer_start));
        std::vector<AffinePoint> outer_shifted;
        const AffinePoint* outer_pts =
            &points[static_cast<size_t>(outer_start)];
        if (symmetric_pos_only && center_g > 0) {
          outer_shifted = BatchAdd(shift_pt, outer_pts, outer_len);
          outer_pts = outer_shifted.data();
        }
        auto on_match = [&](uint32_t pt_off, int32_t g_step,
                            uint32_t linear_id) {
          verify_hit(outer_start + static_cast<int64_t>(pt_off), t_start,
                     g_step, linear_id);
        };
        auto emit_probe = [&](uint64_t hv, uint32_t pt_off, int32_t g_step) {
          if (use_radix_probes) {
            baby_table.QueueProbe(hv, pt_off, g_step, &probe_buf, &probe_tmp,
                                  on_match);
          } else {
            baby_table.ProbeDirect(hv, [&](uint32_t linear_id) {
              on_match(pt_off, g_step, linear_id);
            });
          }
        };

        for (size_t sub_off = 0; sub_off < outer_len; sub_off += g_chunk) {
          size_t cur_n = std::min(g_chunk, outer_len - sub_off);
          const AffinePoint* q_pts = outer_pts + sub_off;
          if (g_sz > 0) {
            BatchMultiAddSubtractHashes(q_pts, cur_n, seq_giant.data(), g_sz,
                                        &dx_buf, &valid_buf, &inv_buf,
                                        sum_hashes.data(), diff_hashes.data());
          }
          for (size_t off = 0; off < cur_n; ++off) {
            uint32_t pt_off = static_cast<uint32_t>(sub_off + off);
            emit_probe(PointXHash(q_pts[off]), pt_off,
                       static_cast<int32_t>(center_g));
            size_t base = off * g_sz;
            if (symmetric_pos_only) {
              for (size_t k = 0; k < g_sz; ++k) {
                int32_t step = static_cast<int32_t>(k + 1);
                emit_probe(sum_hashes[base + k], pt_off,
                           static_cast<int32_t>(center_g) - step);
                emit_probe(diff_hashes[base + k], pt_off,
                           static_cast<int32_t>(center_g) + step);
              }
            } else {
              for (size_t k = 0; k < g_sz; ++k) {
                int32_t step = static_cast<int32_t>(k + 1);
                emit_probe(diff_hashes[base + k], pt_off, step);
                emit_probe(sum_hashes[base + k], pt_off, -step);
              }
            }
          }
        }
        if (use_radix_probes) {
          baby_table.FlushProbes(&probe_buf, &probe_tmp, on_match);
        }
      }
      std::vector<SlicedHashTable48::RadixProbe>().swap(probe_buf);
      std::vector<SlicedHashTable48::RadixProbe>().swap(probe_tmp);
    }
    return true;
  }

 private:
  int coord_bytes_;
  mpz_class mod_;
  mpz_class a_;
  bool a_is_minus_3_;
  AffinePoint g_;

  SlicedHashTable48 table_;
  int64_t table_size_;
};

}  // namespace

std::unique_ptr<EcBatchEngine> EcBatchEngine::Create(std::string_view mod_le,
                                                     std::string_view a_le,
                                                     std::string_view gx_le,
                                                     std::string_view gy_le) {
  size_t cb = mod_le.size();
  if (cb == 0 || cb > 1024 || a_le.size() != cb || gx_le.size() != cb ||
      gy_le.size() != cb) {
    return nullptr;
  }
  mpz_class mod = ImportLE(mod_le.data(), cb);
  if (mod < 5 || mpz_even_p(mod.get_mpz_t())) {
    return nullptr;
  }
  mpz_class a = ImportLE(a_le.data(), cb);
  mpz_class gx = ImportLE(gx_le.data(), cb);
  mpz_class gy = ImportLE(gy_le.data(), cb);
  if (a >= mod || gx >= mod || gy >= mod) {
    return nullptr;
  }
  return std::make_unique<GmpCurveEngine>(static_cast<int>(cb), std::move(mod),
                                          std::move(a), std::move(gx),
                                          std::move(gy));
}

}  // namespace paranoid_crypto::lib::cc_util
