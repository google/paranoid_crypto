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

#include <algorithm>
#include <atomic>
#include <condition_variable>  // NOLINT(build/c++11)
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>  // NOLINT(build/c++11)
#include <optional>
#include <string>
#include <string_view>
#include <thread>  // NOLINT(build/c++11)
#include <unordered_map>
#include <utility>
#include <vector>

#include <gmp.h>

namespace paranoid_crypto::lib::cc_util {
namespace {

static_assert(GMP_NAIL_BITS == 0, "GMP nail bits are not supported.");

constexpr size_t kLimbBytes = sizeof(mp_limb_t);
constexpr uint32_t kUidZero = 0xFFFFFFFFu;
constexpr uint32_t kUidOne = 0xFFFFFFFEu;
constexpr uint32_t kEmptyHashSlot = 0xFFFFFFFFu;

// Bounds concurrent large multiplications/divisions so aggregate GMP FFT
// temporary scratch across active threads stays bounded (~32 GiB worst-case).
constexpr size_t kMaxConcurrentFftOutputBytes = 8ULL * 1024 * 1024 * 1024;

// Move-only RAII wrapper around mpz_t.
class Mpz {
 public:
  Mpz() { mpz_init(v_); }
  ~Mpz() { mpz_clear(v_); }

  Mpz(const Mpz&) = delete;
  Mpz& operator=(const Mpz&) = delete;

  Mpz(Mpz&& other) noexcept {
    mpz_init(v_);
    mpz_swap(v_, other.v_);
  }

  Mpz& operator=(Mpz&& other) noexcept {
    if (this != &other) {
      mpz_swap(v_, other.v_);
    }
    return *this;
  }

  mpz_ptr get() { return v_; }
  mpz_srcptr get() const { return v_; }

  void Clear() {
    Mpz empty;
    mpz_swap(v_, empty.v_);
  }

  size_t ByteSize() const { return mpz_size(v_) * kLimbBytes; }

 private:
  mpz_t v_;
};

// Lightweight non-reentrant worker pool created once per batch solve.
class ThreadPool {
 public:
  explicit ThreadPool(int requested_threads) {
    unsigned int hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 4;
    int target = requested_threads > 0
                     ? requested_threads
                     : static_cast<int>(std::min<unsigned int>(hw, 8u));
    num_threads_ = static_cast<size_t>(std::max(1, target));
    if (num_threads_ > 1) {
      workers_.reserve(num_threads_ - 1);
      for (size_t id = 1; id < num_threads_; ++id) {
        workers_.emplace_back([this, id]() { WorkerLoop(id); });
      }
    }
  }

  ~ThreadPool() {
    if (workers_.empty()) return;
    {
      std::lock_guard lock(mu_);
      stop_ = true;
    }
    cv_start_.notify_all();
    for (std::thread& t : workers_) {
      t.join();
    }
  }

  size_t num_threads() const { return num_threads_; }

  // Executes `fn(item_idx, worker_slot)` for `item_idx` in `[0, count)` using
  // up to `min(num_threads_, max_workers, count)` threads.
  void ParallelFor(size_t count, size_t max_workers,
                   const std::function<void(size_t, size_t)>& fn) {
    if (count == 0) return;
    size_t active =
        std::min({num_threads_, std::max<size_t>(1, max_workers), count});
    if (active <= 1) {
      for (size_t i = 0; i < count; ++i) {
        fn(i, 0);
      }
      return;
    }

    {
      std::lock_guard lock(mu_);
      next_index_.store(0, std::memory_order_relaxed);
      task_count_ = count;
      active_workers_ = active;
      task_fn_ = &fn;
      worker_error_ = nullptr;
      pending_workers_ = active - 1;
      ++generation_;
    }
    cv_start_.notify_all();

    RunItems(0);

    std::exception_ptr err;
    {
      std::unique_lock lock(mu_);
      cv_done_.wait(lock, [this]() { return pending_workers_ == 0; });
      task_fn_ = nullptr;
      err = worker_error_;
      worker_error_ = nullptr;
    }
    if (err) {
      std::rethrow_exception(err);
    }
  }

 private:
  void RunItems(size_t slot) {
    try {
      while (true) {
        size_t idx = next_index_.fetch_add(1, std::memory_order_relaxed);
        if (idx >= task_count_) break;
        (*task_fn_)(idx, slot);
      }
    } catch (...) {
      std::lock_guard lock(err_mu_);
      if (!worker_error_) {
        worker_error_ = std::current_exception();
      }
    }
  }

  void WorkerLoop(size_t slot) {
    uint64_t seen_gen = 0;
    while (true) {
      bool participate = false;
      {
        std::unique_lock lock(mu_);
        cv_start_.wait(lock, [this, &seen_gen]() {
          return stop_ || generation_ != seen_gen;
        });
        if (stop_) return;
        seen_gen = generation_;
        participate = (slot < active_workers_);
      }
      if (participate) {
        RunItems(slot);
        std::lock_guard lock(mu_);
        if (--pending_workers_ == 0) {
          cv_done_.notify_one();
        }
      }
    }
  }

  size_t num_threads_ = 1;
  std::vector<std::thread> workers_;
  std::mutex mu_;  // NOLINT(build/c++11)
  std::condition_variable cv_start_;
  std::condition_variable cv_done_;
  bool stop_ = false;
  uint64_t generation_ = 0;
  size_t active_workers_ = 0;
  size_t pending_workers_ = 0;
  size_t task_count_ = 0;
  std::atomic<size_t> next_index_{0};
  const std::function<void(size_t, size_t)>* task_fn_ = nullptr;
  std::mutex err_mu_;  // NOLINT(build/c++11)
  std::exception_ptr worker_error_;
};

inline uint64_t Mix64(uint64_t x) {
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9ULL;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebULL;
  x ^= x >> 31;
  return x;
}

uint64_t HashSignedLimbs(bool is_negative, const mp_limb_t* limbs,
                         size_t num_limbs) {
  uint64_t h = Mix64(static_cast<uint64_t>(num_limbs) ^
                     (is_negative ? 0x9e3779b97f4a7c15ULL : 0ULL));
  for (size_t i = 0; i < num_limbs; ++i) {
    h = Mix64(h ^ static_cast<uint64_t>(limbs[i]));
  }
  return h;
}

#pragma pack(push, 1)
struct DedupSlot {
  uint32_t uid;
  uint16_t tag;
};
#pragma pack(pop)
static_assert(sizeof(DedupSlot) == 6, "DedupSlot must be 6 bytes.");

// Parses big-endian unsigned bytes into normalized little-endian limbs
// (excluding leading zeros).
size_t ParseBigEndianToLimbs(std::string_view be, std::vector<mp_limb_t>* buf) {
  size_t first_nz = 0;
  while (first_nz < be.size() &&
         static_cast<unsigned char>(be[first_nz]) == 0) {
    ++first_nz;
  }
  std::string_view stripped = be.substr(first_nz);
  if (stripped.empty()) {
    buf->clear();
    return 0;
  }
  const size_t num_limbs = (stripped.size() + kLimbBytes - 1) / kLimbBytes;
  buf->resize(num_limbs);
  for (size_t idx = 0; idx < num_limbs; ++idx) {
    const size_t end = stripped.size() - idx * kLimbBytes;
    const size_t start = end >= kLimbBytes ? end - kLimbBytes : 0;
    mp_limb_t limb = 0;
    for (size_t b = start; b < end; ++b) {
      limb = (limb << 8) |
             static_cast<mp_limb_t>(static_cast<unsigned char>(stripped[b]));
    }
    (*buf)[idx] = limb;
  }
  return num_limbs;
}

void SubtractOneInPlace(std::vector<mp_limb_t>* limbs) {
  if (limbs->empty()) return;
  for (size_t i = 0; i < limbs->size(); ++i) {
    if ((*limbs)[i] > 0) {
      --(*limbs)[i];
      break;
    }
    (*limbs)[i] = ~static_cast<mp_limb_t>(0);
  }
  if (limbs->back() == 0) {
    limbs->pop_back();
  }
}

std::string LimbsToBigEndianBytes(const mp_limb_t* limbs, size_t num_limbs) {
  if (num_limbs == 0) return {};

  const mp_limb_t top = limbs[num_limbs - 1];
  size_t top_bytes = 0;
  for (mp_limb_t t = top; t != 0; t >>= 8) {
    ++top_bytes;
  }
  const size_t payload_bytes = (num_limbs - 1) * kLimbBytes + top_bytes;
  std::string out(payload_bytes, '\0');
  char* dst = out.data();

  for (size_t b = 0; b < top_bytes; ++b) {
    dst[top_bytes - 1 - b] = static_cast<char>((top >> (b * 8)) & 0xFFu);
  }
  dst += top_bytes;

  for (size_t idx = num_limbs - 1; idx-- > 0;) {
    const mp_limb_t limb = limbs[idx];
    for (size_t b = 0; b < kLimbBytes; ++b) {
      dst[kLimbBytes - 1 - b] = static_cast<char>((limb >> (b * 8)) & 0xFFu);
    }
    dst += kLimbBytes;
  }
  return out;
}

std::string MpzToBigEndianBytes(mpz_srcptr z) {
  const size_t n = mpz_size(z);
  if (n == 0) return {};
  return LimbsToBigEndianBytes(mpz_limbs_read(z), n);
}

Mpz BigEndianToMpz(std::string_view be) {
  std::vector<mp_limb_t> limbs;
  const size_t n = ParseBigEndianToLimbs(be, &limbs);
  Mpz out;
  if (n > 0) {
    mpz_t ro;
    mpz_roinit_n(ro, limbs.data(), static_cast<mp_size_t>(n));
    mpz_set(out.get(), ro);
  }
  return out;
}

// Computes `num mod den` (for `num >= 0`, `den > 0`) into a freshly initialized
// non-aliased Mpz so GMP's mpz_tdiv_r never allocates an extra copy of `num` or
// `den`.
Mpz ModNonAliased(mpz_srcptr num, mpz_srcptr den) {
  Mpz out;
  if (mpz_cmp(num, den) < 0) {
    mpz_set(out.get(), num);
    return out;
  }
  mpz_tdiv_r(out.get(), num, den);
  return out;
}

Mpz ModNonAliasedMove(Mpz&& num, mpz_srcptr den) {
  if (mpz_cmp(num.get(), den) < 0) {
    return std::move(num);
  }
  Mpz out;
  mpz_tdiv_r(out.get(), num.get(), den);
  num.Clear();
  return out;
}

// Computes child remainders:
//   *out_left  = (rem * right) mod left
//   *out_right = (rem * left)  mod right
// for `left > 0`, `right > 0`, `rem >= 0`, freeing `rem` as early as possible
// to minimize peak limb memory.
void CrossRemaindersPair(mpz_srcptr left, mpz_srcptr right, Mpz&& rem,
                         Mpz* out_left, Mpz* out_right) {
  if (mpz_sgn(rem.get()) == 0) {
    rem.Clear();
    out_left->Clear();
    out_right->Clear();
    return;
  }

  if (mpz_cmp_ui(rem.get(), 1) == 0) {
    rem.Clear();
    *out_left = ModNonAliased(right, left);
    *out_right = ModNonAliased(left, right);
    return;
  }

  Mpz t_left = ModNonAliased(rem.get(), left);
  Mpz t_right = ModNonAliased(rem.get(), right);
  rem.Clear();

  if (mpz_sgn(t_left.get()) == 0) {
    out_left->Clear();
  } else if (mpz_cmp_ui(t_left.get(), 1) == 0) {
    t_left.Clear();
    *out_left = ModNonAliased(right, left);
  } else if (mpz_cmp(right, left) < 0) {
    Mpz prod;
    mpz_mul(prod.get(), t_left.get(), right);
    t_left.Clear();
    *out_left = ModNonAliasedMove(std::move(prod), left);
  } else {
    Mpz r_rl = ModNonAliased(right, left);
    Mpz prod;
    mpz_mul(prod.get(), t_left.get(), r_rl.get());
    t_left.Clear();
    r_rl.Clear();
    *out_left = ModNonAliasedMove(std::move(prod), left);
  }

  if (mpz_sgn(t_right.get()) == 0) {
    out_right->Clear();
  } else if (mpz_cmp_ui(t_right.get(), 1) == 0) {
    t_right.Clear();
    *out_right = ModNonAliased(left, right);
  } else if (mpz_cmp(left, right) < 0) {
    Mpz prod;
    mpz_mul(prod.get(), t_right.get(), left);
    t_right.Clear();
    *out_right = ModNonAliasedMove(std::move(prod), right);
  } else {
    Mpz r_lr = ModNonAliased(left, right);
    Mpz prod;
    mpz_mul(prod.get(), t_right.get(), r_lr.get());
    t_right.Clear();
    r_lr.Clear();
    *out_right = ModNonAliasedMove(std::move(prod), right);
  }
}

size_t MaxWorkersForOutputBytes(size_t est_output_bytes) {
  if (est_output_bytes == 0) return 8;
  return std::max<size_t>(1, kMaxConcurrentFftOutputBytes / est_output_bytes);
}

// Computes the product of `nodes[0 .. count - 1]` bottom-up with bounded FFT
// concurrency.
Mpz RangeProduct(const Mpz* nodes, size_t count, ThreadPool* pool) {
  if (count == 0) {
    Mpz one;
    mpz_set_ui(one.get(), 1);
    return one;
  }
  if (count == 1) {
    Mpz copy;
    mpz_set(copy.get(), nodes[0].get());
    return copy;
  }

  size_t total_bytes = 0;
  for (size_t i = 0; i < count; ++i) {
    total_bytes += nodes[i].ByteSize();
  }

  const size_t first_pairs = count / 2;
  const size_t first_size = (count + 1) / 2;
  std::vector<Mpz> cur(first_size);
  const size_t first_pair_bytes =
      total_bytes / std::max<size_t>(1, first_pairs);
  if (pool != nullptr && first_pairs >= 2) {
    pool->ParallelFor(
        first_pairs, MaxWorkersForOutputBytes(first_pair_bytes),
        [&](size_t p, size_t /*slot*/) {
          mpz_mul(cur[p].get(), nodes[2 * p].get(), nodes[2 * p + 1].get());
        });
  } else {
    for (size_t p = 0; p < first_pairs; ++p) {
      mpz_mul(cur[p].get(), nodes[2 * p].get(), nodes[2 * p + 1].get());
    }
  }
  if (count % 2 == 1) {
    mpz_set(cur[first_pairs].get(), nodes[count - 1].get());
  }

  while (cur.size() > 1) {
    const size_t m = cur.size();
    const size_t pairs = m / 2;
    std::vector<Mpz> next((m + 1) / 2);
    const size_t pair_bytes = total_bytes / std::max<size_t>(1, pairs);
    if (pool != nullptr && pairs >= 2) {
      pool->ParallelFor(
          pairs, MaxWorkersForOutputBytes(pair_bytes),
          [&](size_t p, size_t /*slot*/) {
            mpz_mul(next[p].get(), cur[2 * p].get(), cur[2 * p + 1].get());
            cur[2 * p].Clear();
            cur[2 * p + 1].Clear();
          });
    } else {
      for (size_t p = 0; p < pairs; ++p) {
        mpz_mul(next[p].get(), cur[2 * p].get(), cur[2 * p + 1].get());
        cur[2 * p].Clear();
        cur[2 * p + 1].Clear();
      }
    }
    if (m % 2 == 1) {
      next[pairs] = std::move(cur[m - 1]);
    }
    cur = std::move(next);
  }
  return std::move(cur[0]);
}

// Solves remainders `out[i] = (root_rem * prod_{j != i} nodes[j]) mod nodes[i]`
// for an array of `Mpz` nodes by building internal tree levels up to size 2
// (never forming the root product) and freeing each level during descent.
std::vector<Mpz> SolveNodeArrayRemainders(std::vector<Mpz> base_nodes,
                                          Mpz&& root_rem, ThreadPool* pool) {
  const size_t n = base_nodes.size();
  if (n == 0) return {};
  if (n == 1) {
    std::vector<Mpz> out(1);
    out[0] = ModNonAliasedMove(std::move(root_rem), base_nodes[0].get());
    return out;
  }
  if (n == 2) {
    std::vector<Mpz> out(2);
    CrossRemaindersPair(base_nodes[0].get(), base_nodes[1].get(),
                        std::move(root_rem), &out[0], &out[1]);
    return out;
  }

  size_t total_bytes = 0;
  for (const Mpz& z : base_nodes) {
    total_bytes += z.ByteSize();
  }

  std::vector<std::vector<Mpz>> levels;
  levels.push_back(std::move(base_nodes));
  while (levels.back().size() > 2) {
    const std::vector<Mpz>& prev = levels.back();
    const size_t m = prev.size();
    const size_t pairs = m / 2;
    std::vector<Mpz> next((m + 1) / 2);
    const size_t pair_bytes = total_bytes / std::max<size_t>(1, pairs);
    if (pool != nullptr && pairs >= 2 && total_bytes >= (256 * 1024)) {
      pool->ParallelFor(
          pairs, MaxWorkersForOutputBytes(pair_bytes),
          [&](size_t p, size_t /*slot*/) {
            mpz_mul(next[p].get(), prev[2 * p].get(), prev[2 * p + 1].get());
          });
    } else {
      for (size_t p = 0; p < pairs; ++p) {
        mpz_mul(next[p].get(), prev[2 * p].get(), prev[2 * p + 1].get());
      }
    }
    if (m % 2 == 1) {
      mpz_set(next[pairs].get(), prev[m - 1].get());
    }
    levels.push_back(std::move(next));
  }

  std::vector<Mpz> rems(2);
  {
    std::vector<Mpz> top = std::move(levels.back());
    levels.pop_back();
    CrossRemaindersPair(top[0].get(), top[1].get(), std::move(root_rem),
                        &rems[0], &rems[1]);
  }

  while (!levels.empty()) {
    std::vector<Mpz> nodes = std::move(levels.back());
    levels.pop_back();
    const size_t m = nodes.size();
    const size_t pairs = m / 2;
    std::vector<Mpz> next_rems(m);
    const size_t pair_bytes = total_bytes / std::max<size_t>(1, pairs);
    if (pool != nullptr && pairs >= 2 && total_bytes >= (256 * 1024)) {
      pool->ParallelFor(
          pairs, MaxWorkersForOutputBytes(pair_bytes),
          [&](size_t p, size_t /*slot*/) {
            CrossRemaindersPair(nodes[2 * p].get(), nodes[2 * p + 1].get(),
                                std::move(rems[p]), &next_rems[2 * p],
                                &next_rems[2 * p + 1]);
            nodes[2 * p].Clear();
            nodes[2 * p + 1].Clear();
          });
    } else {
      for (size_t p = 0; p < pairs; ++p) {
        CrossRemaindersPair(nodes[2 * p].get(), nodes[2 * p + 1].get(),
                            std::move(rems[p]), &next_rems[2 * p],
                            &next_rems[2 * p + 1]);
        nodes[2 * p].Clear();
        nodes[2 * p + 1].Clear();
      }
    }
    if (m % 2 == 1) {
      next_rems[m - 1] =
          ModNonAliasedMove(std::move(rems[pairs]), nodes[m - 1].get());
      nodes[m - 1].Clear();
    }
    rems = std::move(next_rems);
  }
  return rems;
}

// Depth-first cross-remainder solver for the top super-chunk tier (`S[0..M-1]`)
// so we never materialize multiple full-dataset tree levels simultaneously.
void DepthFirstRemainders(const std::vector<Mpz>& nodes, size_t begin,
                          size_t end, Mpz&& rem, ThreadPool* pool,
                          std::vector<Mpz>* out) {
  const size_t cnt = end - begin;
  if (cnt == 0) return;
  if (cnt == 1) {
    (*out)[begin] = ModNonAliasedMove(std::move(rem), nodes[begin].get());
    return;
  }
  if (cnt == 2) {
    CrossRemaindersPair(nodes[begin].get(), nodes[begin + 1].get(),
                        std::move(rem), &(*out)[begin], &(*out)[begin + 1]);
    return;
  }

  const size_t mid = begin + cnt / 2;
  Mpz prod_left = RangeProduct(nodes.data() + begin, mid - begin, pool);
  Mpz prod_right = RangeProduct(nodes.data() + mid, end - mid, pool);
  Mpz rem_left;
  Mpz rem_right;
  CrossRemaindersPair(prod_left.get(), prod_right.get(), std::move(rem),
                      &rem_left, &rem_right);
  prod_left.Clear();
  prod_right.Clear();

  DepthFirstRemainders(nodes, begin, mid, std::move(rem_left), pool, out);
  DepthFirstRemainders(nodes, mid, end, std::move(rem_right), pool, out);
}

}  // namespace

struct RsaBatchAccumulator::Impl {
  explicit Impl(RsaBatchOptions opts) : options(opts) {
    if (options.chunk_target_bytes == 0) {
      options.chunk_target_bytes = 16ULL * 1024 * 1024;
    }
    if (options.chunks_per_superchunk < 2) {
      options.chunks_per_superchunk = 2;
    }
    limb_offsets.push_back(0);
  }

  size_t num_unique() const { return limb_offsets.size() - 1; }

  const mp_limb_t* LeafPtr(uint32_t uid) const {
    return limb_arena.data() + limb_offsets[uid];
  }

  size_t LeafLimbs(uint32_t uid) const {
    return static_cast<size_t>(limb_offsets[uid + 1] - limb_offsets[uid]);
  }

  bool LeafIsNegative(uint32_t uid) const {
    return has_negative_leaves && uid < uid_is_negative.size() &&
           uid_is_negative[uid];
  }

  void EnsureDedupCapacity(size_t needed_unique) {
    if (!dedup_slots.empty() && needed_unique * 16 <= dedup_slots.size() * 10) {
      return;
    }
    size_t new_cap = dedup_slots.empty() ? 1024 : dedup_slots.size() * 2;
    while (needed_unique * 16 > new_cap * 10) {
      new_cap *= 2;
    }
    dedup_slots.assign(new_cap, DedupSlot{kEmptyHashSlot, 0});
    const size_t mask = new_cap - 1;
    const uint32_t current_unique = static_cast<uint32_t>(num_unique());
    for (uint32_t uid = 0; uid < current_unique; ++uid) {
      const uint64_t h =
          HashSignedLimbs(LeafIsNegative(uid), LeafPtr(uid), LeafLimbs(uid));
      const uint16_t tag = static_cast<uint16_t>(h >> 48);
      size_t slot = static_cast<size_t>(h) & mask;
      while (dedup_slots[slot].uid != kEmptyHashSlot) {
        slot = (slot + 1) & mask;
      }
      dedup_slots[slot] = DedupSlot{uid, tag};
    }
  }

  void DeallocateDedupTable() { std::vector<DedupSlot>().swap(dedup_slots); }

  void FinalizeIngestion() {
    DeallocateDedupTable();
    std::vector<mp_limb_t>().swap(tmp_limb_buf);
    if (limb_arena.capacity() > limb_arena.size() + (limb_arena.size() >> 2)) {
      limb_arena.shrink_to_fit();
    }
    if (limb_offsets.capacity() >
        limb_offsets.size() + (limb_offsets.size() >> 2)) {
      limb_offsets.shrink_to_fit();
    }
  }

  uint32_t InternSignedLimbs(bool is_negative, const mp_limb_t* limbs,
                             size_t num_limbs) {
    if (num_limbs == 0) {
      has_zero_input = true;
      return kUidZero;
    }
    if (num_limbs == 1 && limbs[0] == 1) {
      return kUidOne;
    }

    EnsureDedupCapacity(num_unique() + 1);
    const uint64_t h = HashSignedLimbs(is_negative, limbs, num_limbs);
    const uint16_t tag = static_cast<uint16_t>(h >> 48);
    const size_t mask = dedup_slots.size() - 1;
    size_t slot = static_cast<size_t>(h) & mask;

    while (dedup_slots[slot].uid != kEmptyHashSlot) {
      if (dedup_slots[slot].tag == tag) {
        const uint32_t cand = dedup_slots[slot].uid;
        if (LeafLimbs(cand) == num_limbs &&
            LeafIsNegative(cand) == is_negative &&
            std::memcmp(LeafPtr(cand), limbs, num_limbs * kLimbBytes) == 0) {
          return cand;
        }
      }
      slot = (slot + 1) & mask;
    }

    const uint32_t new_uid = static_cast<uint32_t>(num_unique());
    limb_arena.insert(limb_arena.end(), limbs, limbs + num_limbs);
    limb_offsets.push_back(static_cast<uint64_t>(limb_arena.size()));
    if (is_negative) {
      if (!has_negative_leaves) {
        has_negative_leaves = true;
        uid_is_negative.resize(new_uid, false);
      }
      uid_is_negative.push_back(true);
    } else if (has_negative_leaves) {
      uid_is_negative.push_back(false);
    }
    dedup_slots[slot] = DedupSlot{new_uid, tag};
    return new_uid;
  }

  Mpz BuildChunkLeafProduct(uint32_t uid_begin, uint32_t uid_end) const {
    const uint32_t count = uid_end - uid_begin;
    if (count == 0) {
      Mpz one;
      mpz_set_ui(one.get(), 1);
      return one;
    }
    if (count == 1) {
      Mpz out;
      mpz_t ro;
      mpz_roinit_n(ro, LeafPtr(uid_begin),
                   static_cast<mp_size_t>(LeafLimbs(uid_begin)));
      mpz_set(out.get(), ro);
      return out;
    }
    if (count == 2) {
      Mpz out;
      mpz_t ro0;
      mpz_t ro1;
      mpz_roinit_n(ro0, LeafPtr(uid_begin),
                   static_cast<mp_size_t>(LeafLimbs(uid_begin)));
      mpz_roinit_n(ro1, LeafPtr(uid_begin + 1),
                   static_cast<mp_size_t>(LeafLimbs(uid_begin + 1)));
      mpz_mul(out.get(), ro0, ro1);
      return out;
    }
    const uint32_t mid = uid_begin + count / 2;
    Mpz left = BuildChunkLeafProduct(uid_begin, mid);
    Mpz right = BuildChunkLeafProduct(mid, uid_end);
    Mpz out;
    mpz_mul(out.get(), left.get(), right.get());
    return out;
  }

  template <typename EmitFn>
  void SolveChunk(uint32_t uid_begin, uint32_t uid_end, Mpz&& chunk_rem,
                  ThreadPool* inner_pool, size_t worker_slot,
                  EmitFn&& emit_leaf_gcd) const {
    const uint32_t count = uid_end - uid_begin;
    if (count == 0) return;
    if (count == 1) {
      mpz_t ro;
      mpz_roinit_n(ro, LeafPtr(uid_begin),
                   static_cast<mp_size_t>(LeafLimbs(uid_begin)));
      Mpz g;
      mpz_gcd(g.get(), ro, chunk_rem.get());
      chunk_rem.Clear();
      emit_leaf_gcd(uid_begin, g.get(), worker_slot);
      return;
    }
    if (count == 2) {
      mpz_t ro0;
      mpz_t ro1;
      mpz_roinit_n(ro0, LeafPtr(uid_begin),
                   static_cast<mp_size_t>(LeafLimbs(uid_begin)));
      mpz_roinit_n(ro1, LeafPtr(uid_begin + 1),
                   static_cast<mp_size_t>(LeafLimbs(uid_begin + 1)));
      Mpz r0;
      Mpz r1;
      CrossRemaindersPair(ro0, ro1, std::move(chunk_rem), &r0, &r1);
      Mpz g0;
      mpz_gcd(g0.get(), ro0, r0.get());
      r0.Clear();
      emit_leaf_gcd(uid_begin, g0.get(), worker_slot);

      Mpz g1;
      mpz_gcd(g1.get(), ro1, r1.get());
      r1.Clear();
      emit_leaf_gcd(uid_begin + 1, g1.get(), worker_slot);
      return;
    }

    const size_t pairs = count / 2;
    std::vector<Mpz> level1((count + 1) / 2);
    if (inner_pool != nullptr && pairs >= 256) {
      inner_pool->ParallelFor(
          pairs, inner_pool->num_threads(), [&](size_t p, size_t /*slot*/) {
            const uint32_t u0 = uid_begin + static_cast<uint32_t>(2 * p);
            mpz_t ro0;
            mpz_t ro1;
            mpz_roinit_n(ro0, LeafPtr(u0),
                         static_cast<mp_size_t>(LeafLimbs(u0)));
            mpz_roinit_n(ro1, LeafPtr(u0 + 1),
                         static_cast<mp_size_t>(LeafLimbs(u0 + 1)));
            mpz_mul(level1[p].get(), ro0, ro1);
          });
    } else {
      for (size_t p = 0; p < pairs; ++p) {
        const uint32_t u0 = uid_begin + static_cast<uint32_t>(2 * p);
        mpz_t ro0;
        mpz_t ro1;
        mpz_roinit_n(ro0, LeafPtr(u0), static_cast<mp_size_t>(LeafLimbs(u0)));
        mpz_roinit_n(ro1, LeafPtr(u0 + 1),
                     static_cast<mp_size_t>(LeafLimbs(u0 + 1)));
        mpz_mul(level1[p].get(), ro0, ro1);
      }
    }
    if (count % 2 == 1) {
      const uint32_t u_last = uid_end - 1;
      mpz_t ro_last;
      mpz_roinit_n(ro_last, LeafPtr(u_last),
                   static_cast<mp_size_t>(LeafLimbs(u_last)));
      mpz_set(level1[pairs].get(), ro_last);
    }

    std::vector<Mpz> rems1 = SolveNodeArrayRemainders(
        std::move(level1), std::move(chunk_rem), inner_pool);

    if (inner_pool != nullptr && pairs >= 256) {
      inner_pool->ParallelFor(
          pairs, inner_pool->num_threads(), [&](size_t p, size_t slot) {
            const uint32_t u0 = uid_begin + static_cast<uint32_t>(2 * p);
            mpz_t ro0;
            mpz_t ro1;
            mpz_roinit_n(ro0, LeafPtr(u0),
                         static_cast<mp_size_t>(LeafLimbs(u0)));
            mpz_roinit_n(ro1, LeafPtr(u0 + 1),
                         static_cast<mp_size_t>(LeafLimbs(u0 + 1)));
            Mpz r0;
            Mpz r1;
            CrossRemaindersPair(ro0, ro1, std::move(rems1[p]), &r0, &r1);
            Mpz g0;
            mpz_gcd(g0.get(), ro0, r0.get());
            r0.Clear();
            emit_leaf_gcd(u0, g0.get(), slot);

            Mpz g1;
            mpz_gcd(g1.get(), ro1, r1.get());
            r1.Clear();
            emit_leaf_gcd(u0 + 1, g1.get(), slot);
          });
    } else {
      for (size_t p = 0; p < pairs; ++p) {
        const uint32_t u0 = uid_begin + static_cast<uint32_t>(2 * p);
        mpz_t ro0;
        mpz_t ro1;
        mpz_roinit_n(ro0, LeafPtr(u0), static_cast<mp_size_t>(LeafLimbs(u0)));
        mpz_roinit_n(ro1, LeafPtr(u0 + 1),
                     static_cast<mp_size_t>(LeafLimbs(u0 + 1)));
        Mpz r0;
        Mpz r1;
        CrossRemaindersPair(ro0, ro1, std::move(rems1[p]), &r0, &r1);
        Mpz g0;
        mpz_gcd(g0.get(), ro0, r0.get());
        r0.Clear();
        emit_leaf_gcd(u0, g0.get(), worker_slot);

        Mpz g1;
        mpz_gcd(g1.get(), ro1, r1.get());
        r1.Clear();
        emit_leaf_gcd(u0 + 1, g1.get(), worker_slot);
      }
    }
    if (count % 2 == 1) {
      const uint32_t u_last = uid_end - 1;
      mpz_t ro_last;
      mpz_roinit_n(ro_last, LeafPtr(u_last),
                   static_cast<mp_size_t>(LeafLimbs(u_last)));
      Mpz g_last;
      mpz_gcd(g_last.get(), ro_last, rems1[pairs].get());
      rems1[pairs].Clear();
      emit_leaf_gcd(u_last, g_last.get(), worker_slot);
    }
  }

  std::vector<std::pair<uint32_t, uint32_t>> PartitionChunks() const {
    std::vector<std::pair<uint32_t, uint32_t>> chunks;
    const uint32_t total = static_cast<uint32_t>(num_unique());
    if (total == 0) return chunks;

    uint32_t chunk_start = 0;
    size_t chunk_bytes = 0;
    for (uint32_t uid = 0; uid < total; ++uid) {
      const size_t leaf_bytes = LeafLimbs(uid) * kLimbBytes;
      if (chunk_bytes > 0 &&
          chunk_bytes + leaf_bytes > options.chunk_target_bytes) {
        chunks.emplace_back(chunk_start, uid);
        chunk_start = uid;
        chunk_bytes = 0;
      }
      chunk_bytes += leaf_bytes;
    }
    chunks.emplace_back(chunk_start, total);
    return chunks;
  }

  template <typename EmitFn>
  void SolveUniqueLeaves(Mpz&& root_rem, ThreadPool* pool,
                         EmitFn&& emit_leaf_gcd) const {
    const uint32_t total_unique = static_cast<uint32_t>(num_unique());
    if (total_unique == 0) return;
    if (total_unique == 1) {
      SolveChunk(0, 1, std::move(root_rem), nullptr, 0, emit_leaf_gcd);
      return;
    }

    const std::vector<std::pair<uint32_t, uint32_t>> chunks = PartitionChunks();
    const size_t num_chunks = chunks.size();

    if (num_chunks == 1) {
      SolveChunk(chunks[0].first, chunks[0].second, std::move(root_rem), pool,
                 0, emit_leaf_gcd);
      return;
    }

    std::vector<Mpz> chunk_prods(num_chunks);
    pool->ParallelFor(
        num_chunks, pool->num_threads(), [&](size_t c, size_t /*slot*/) {
          chunk_prods[c] =
              BuildChunkLeafProduct(chunks[c].first, chunks[c].second);
        });

    if (num_chunks <= options.chunks_per_superchunk) {
      std::vector<Mpz> chunk_rems = SolveNodeArrayRemainders(
          std::move(chunk_prods), std::move(root_rem), pool);
      pool->ParallelFor(
          num_chunks, pool->num_threads(), [&](size_t c, size_t slot) {
            SolveChunk(chunks[c].first, chunks[c].second,
                       std::move(chunk_rems[c]), nullptr, slot, emit_leaf_gcd);
          });
      return;
    }

    const size_t group = options.chunks_per_superchunk;
    const size_t num_super = (num_chunks + group - 1) / group;
    std::vector<Mpz> super_prods(num_super);
    for (size_t g = 0; g < num_super; ++g) {
      const size_t c_begin = g * group;
      const size_t c_end = std::min(num_chunks, c_begin + group);
      super_prods[g] =
          RangeProduct(chunk_prods.data() + c_begin, c_end - c_begin, pool);
    }

    std::vector<Mpz> super_rems(num_super);
    DepthFirstRemainders(super_prods, 0, num_super, std::move(root_rem), pool,
                         &super_rems);
    std::vector<Mpz>().swap(super_prods);

    for (size_t g = 0; g < num_super; ++g) {
      const size_t c_begin = g * group;
      const size_t c_end = std::min(num_chunks, c_begin + group);
      const size_t sub_count = c_end - c_begin;

      std::vector<Mpz> sub_prods(sub_count);
      for (size_t i = 0; i < sub_count; ++i) {
        sub_prods[i] = std::move(chunk_prods[c_begin + i]);
      }

      std::vector<Mpz> sub_rems = SolveNodeArrayRemainders(
          std::move(sub_prods), std::move(super_rems[g]), pool);

      pool->ParallelFor(
          sub_count, pool->num_threads(), [&](size_t i, size_t slot) {
            const size_t c = c_begin + i;
            SolveChunk(chunks[c].first, chunks[c].second,
                       std::move(sub_rems[i]), nullptr, slot, emit_leaf_gcd);
          });
    }
  }

  void ReleaseAll() {
    DeallocateDedupTable();
    std::vector<mp_limb_t>().swap(limb_arena);
    std::vector<uint64_t>().swap(limb_offsets);
    limb_offsets.push_back(0);
    std::vector<bool>().swap(uid_is_negative);
    has_negative_leaves = false;
    has_zero_input = false;
    std::vector<uint32_t>().swap(input_to_uid);
    total_inputs = 0;
  }

  RsaBatchOptions options;
  std::vector<mp_limb_t> tmp_limb_buf;

  std::vector<mp_limb_t> limb_arena;
  std::vector<uint64_t> limb_offsets;
  std::vector<bool> uid_is_negative;
  bool has_negative_leaves = false;
  bool has_zero_input = false;
  std::vector<DedupSlot> dedup_slots;

  size_t total_inputs = 0;
  std::vector<uint32_t> input_to_uid;
};

RsaBatchAccumulator::RsaBatchAccumulator(RsaBatchOptions options)
    : impl_(std::make_unique<Impl>(options)) {}

RsaBatchAccumulator::~RsaBatchAccumulator() = default;
RsaBatchAccumulator::RsaBatchAccumulator(RsaBatchAccumulator&&) noexcept =
    default;
RsaBatchAccumulator& RsaBatchAccumulator::operator=(
    RsaBatchAccumulator&&) noexcept = default;

void RsaBatchAccumulator::Reserve(size_t expected_inputs,
                                  size_t expected_limb_bytes) {
  impl_->input_to_uid.reserve(expected_inputs);
  impl_->limb_offsets.reserve(expected_inputs + 1);
  if (expected_limb_bytes > 0) {
    impl_->limb_arena.reserve((expected_limb_bytes + kLimbBytes - 1) /
                              kLimbBytes);
  }
  if (expected_inputs > 0) {
    impl_->EnsureDedupCapacity(expected_inputs);
  }
}

size_t RsaBatchAccumulator::num_inputs() const { return impl_->total_inputs; }

size_t RsaBatchAccumulator::num_unique_leaves() const {
  return impl_->num_unique();
}

void RsaBatchAccumulator::AddSignedBigEndian(bool is_negative,
                                             std::string_view magnitude_be) {
  const size_t num_limbs =
      ParseBigEndianToLimbs(magnitude_be, &impl_->tmp_limb_buf);
  const bool neg = (num_limbs > 0) && is_negative;
  const uint32_t uid =
      impl_->InternSignedLimbs(neg, impl_->tmp_limb_buf.data(), num_limbs);
  impl_->input_to_uid.push_back(uid);
  ++impl_->total_inputs;
}

void RsaBatchAccumulator::AddModulusBigEndian(std::string_view modulus_be,
                                              bool subtract_one) {
  ParseBigEndianToLimbs(modulus_be, &impl_->tmp_limb_buf);
  if (subtract_one) {
    SubtractOneInPlace(&impl_->tmp_limb_buf);
  }
  const size_t num_limbs = impl_->tmp_limb_buf.size();
  // Clamp malformed RSA moduli yielding values <= 1 to 1 so a single zero/one
  // record cannot poison or crash valid keys in the batch.
  if (num_limbs == 0 || (num_limbs == 1 && impl_->tmp_limb_buf[0] == 1)) {
    impl_->input_to_uid.push_back(kUidOne);
    ++impl_->total_inputs;
    return;
  }
  const uint32_t uid =
      impl_->InternSignedLimbs(false, impl_->tmp_limb_buf.data(), num_limbs);
  impl_->input_to_uid.push_back(uid);
  ++impl_->total_inputs;
}

std::vector<std::string> RsaBatchAccumulator::ComputeAllGcds(
    std::optional<std::string_view> other_prod_magnitude_be) {
  impl_->FinalizeIngestion();

  const size_t n = impl_->total_inputs;
  std::vector<std::string> out(n);
  if (n == 0) return out;

  Mpz other_mpz;
  if (other_prod_magnitude_be.has_value()) {
    other_mpz = BigEndianToMpz(*other_prod_magnitude_be);
    if (mpz_sgn(other_mpz.get()) == 0) {
      for (size_t i = 0; i < n; ++i) {
        const uint32_t uid = impl_->input_to_uid[i];
        if (uid == kUidZero) {
          out[i] = {};
        } else if (uid == kUidOne) {
          out[i] = std::string("\x01", 1);
        } else {
          out[i] =
              LimbsToBigEndianBytes(impl_->LeafPtr(uid), impl_->LeafLimbs(uid));
        }
      }
      impl_->ReleaseAll();
      return out;
    }
  } else {
    mpz_set_ui(other_mpz.get(), 1);
  }

  ThreadPool pool(impl_->options.num_threads);

  if (impl_->has_zero_input) {
    Mpz nonzero_prod;
    if (impl_->num_unique() == 0) {
      mpz_set(nonzero_prod.get(), other_mpz.get());
    } else {
      const std::vector<std::pair<uint32_t, uint32_t>> chunks =
          impl_->PartitionChunks();
      std::vector<Mpz> chunk_prods(chunks.size());
      pool.ParallelFor(
          chunks.size(), pool.num_threads(), [&](size_t c, size_t /*slot*/) {
            chunk_prods[c] = impl_->BuildChunkLeafProduct(chunks[c].first,
                                                          chunks[c].second);
          });
      Mpz leaves_prod =
          RangeProduct(chunk_prods.data(), chunk_prods.size(), &pool);
      mpz_mul(nonzero_prod.get(), leaves_prod.get(), other_mpz.get());
    }
    const std::string zero_gcd_be = MpzToBigEndianBytes(nonzero_prod.get());
    nonzero_prod.Clear();

    for (size_t i = 0; i < n; ++i) {
      const uint32_t uid = impl_->input_to_uid[i];
      if (uid == kUidZero) {
        out[i] = zero_gcd_be;
      } else if (uid == kUidOne) {
        out[i] = std::string("\x01", 1);
      } else {
        out[i] =
            LimbsToBigEndianBytes(impl_->LeafPtr(uid), impl_->LeafLimbs(uid));
      }
    }
    impl_->ReleaseAll();
    return out;
  }

  const size_t num_unique = impl_->num_unique();
  if (num_unique == 0 ||
      (num_unique == 1 && mpz_cmp_ui(other_mpz.get(), 1) == 0)) {
    std::fill(out.begin(), out.end(), std::string("\x01", 1));
    impl_->ReleaseAll();
    return out;
  }

  std::vector<std::string> uid_gcds(num_unique);
  impl_->SolveUniqueLeaves(
      std::move(other_mpz), &pool,
      [&](uint32_t uid, mpz_srcptr gcd_val, size_t /*slot*/) {
        uid_gcds[uid] = MpzToBigEndianBytes(gcd_val);
      });

  for (size_t i = 0; i < n; ++i) {
    const uint32_t uid = impl_->input_to_uid[i];
    if (uid == kUidOne) {
      out[i] = std::string("\x01", 1);
    } else {
      out[i] = uid_gcds[uid];
    }
  }
  impl_->ReleaseAll();
  return out;
}

std::vector<std::pair<int64_t, std::string>>
RsaBatchAccumulator::ComputeFilteredGcds(
    std::string_view min_gcd_be,
    std::optional<std::string_view> other_prod_magnitude_be) {
  impl_->FinalizeIngestion();

  const size_t n = impl_->total_inputs;
  std::vector<std::pair<int64_t, std::string>> hits;
  if (n == 0) {
    impl_->ReleaseAll();
    return hits;
  }

  const Mpz min_gcd_mpz = BigEndianToMpz(min_gcd_be);
  const bool other_is_zero =
      other_prod_magnitude_be.has_value() &&
      mpz_sgn(BigEndianToMpz(*other_prod_magnitude_be).get()) == 0;
  if (impl_->has_zero_input || other_is_zero ||
      mpz_cmp_ui(min_gcd_mpz.get(), 1) <= 0) {
    std::vector<std::string> all_gcds = ComputeAllGcds(other_prod_magnitude_be);
    for (size_t i = 0; i < n; ++i) {
      Mpz g = BigEndianToMpz(all_gcds[i]);
      if (mpz_cmp(g.get(), min_gcd_mpz.get()) >= 0) {
        hits.emplace_back(static_cast<int64_t>(i), std::move(all_gcds[i]));
      }
    }
    return hits;
  }

  Mpz other_mpz;
  if (other_prod_magnitude_be.has_value()) {
    other_mpz = BigEndianToMpz(*other_prod_magnitude_be);
  } else {
    mpz_set_ui(other_mpz.get(), 1);
  }

  const size_t num_unique = impl_->num_unique();
  if (num_unique == 0 ||
      (num_unique == 1 && mpz_cmp_ui(other_mpz.get(), 1) == 0)) {
    impl_->ReleaseAll();
    return hits;
  }

  ThreadPool pool(impl_->options.num_threads);
  std::vector<std::vector<std::pair<uint32_t, std::string>>> per_worker_hits(
      pool.num_threads());

  impl_->SolveUniqueLeaves(
      std::move(other_mpz), &pool,
      [&](uint32_t uid, mpz_srcptr gcd_val, size_t slot) {
        if (mpz_cmp(gcd_val, min_gcd_mpz.get()) >= 0) {
          per_worker_hits[slot].emplace_back(uid, MpzToBigEndianBytes(gcd_val));
        }
      });

  std::unordered_map<uint32_t, std::string> weak_uid_to_gcd;
  for (auto& vec : per_worker_hits) {
    for (auto& kv : vec) {
      weak_uid_to_gcd.emplace(kv.first, std::move(kv.second));
    }
  }

  if (!weak_uid_to_gcd.empty()) {
    for (size_t i = 0; i < n; ++i) {
      const uint32_t uid = impl_->input_to_uid[i];
      if (uid == kUidOne || uid == kUidZero) continue;
      auto it = weak_uid_to_gcd.find(uid);
      if (it != weak_uid_to_gcd.end()) {
        hits.emplace_back(static_cast<int64_t>(i), it->second);
      }
    }
  }

  impl_->ReleaseAll();
  return hits;
}

}  // namespace paranoid_crypto::lib::cc_util
