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

#ifdef __x86_64__
#ifdef __CLMUL__
#include <emmintrin.h>  // SSE2
#include <wmmintrin.h>  // clmul
#include <xmmintrin.h>  // Datatype __mm128i
#define USE_CLMUL
#endif
#endif

#ifdef __aarch64__
#ifdef __ARM_NEON
#include <arm_neon.h>
#define USE_CLMUL
#endif
#endif

#include <string>
#include <vector>

namespace paranoid_crypto::lib::randomness_tests::cc_util {

#ifdef USE_CLMUL
#ifdef __x86_64__
#define _mm_extract_epi64(x, imm) \
  _mm_cvtsi128_si64(_mm_srli_si128((x), 8 * (imm)))

inline void clmul(uint64_t x, uint64_t y, uint64_t *hi, uint64_t *lo) {
  __m128i t0 = _mm_set_epi64x(0, x);
  __m128i t1 = _mm_set_epi64x(0, y);
  __m128i tmp = _mm_clmulepi64_si128(t0, t1, 0x00);
  *hi = _mm_extract_epi64(tmp, 1);
  *lo = _mm_extract_epi64(tmp, 0);
}
#endif
#ifdef __aarch64__
#ifdef __ARM_NEON
inline void clmul(uint64_t x, uint64_t y, uint64_t *hi, uint64_t *lo) {
  poly128_t t = vmull_p64(x, y);
  *hi = static_cast<uint64_t>(t >> 64);
  *lo = static_cast<uint64_t>(t);
}
#endif
#endif

// Implements the Berlekamp-Massey algorithm for binary sequences.
//
// The Berlekamp-Massey algorithm iteratively computes two shortest LFSRs
// poly_b, poly_c for a subsequence of the input sequence seq. The algorithm
// extends these polynomials to larger subsequences by computing a discrepancy.
// The discrepancy can be derived from the product of the polynomials seq and
// poly_c, by determining if the coefficient at a given position is 0 or not.
//
// The implementation here does not compute poly_b and poly_c. Instead it uses
// two auxiliary variables sb and sc, which are truncated products of seq with
// the polynomials poly_b and poly_c respectively. Computing sb and sc
// incrementally can be done efficiently since doing so allows to use carry-less
// multiplication.
//
// The main loop in this implementation works in steps of 64 bits.
// Each step processes 64 bits of the input sequence. It computes polynomials
// a, b, c, d, such that the shortest LFSRs after these 64 bits could be
// computed from the shortest LFSRs before as:
//   poly_b' = a * poly_b + b * poly_c
//   poly_c' = c * poly_b + d * poly_c
// This computation is of course not being performed, since there is no need
// for poly_b and poly_c. Instead sb and sc are updated in a similar manner.
//
// The speedup from using carry-less multiplication is constant. The complexity
// is still O(n^2) like typical implementations of Berlekamp-Massey. Faster
// algorithms (e.g. by using Karatsuba multiplication) are possible.
// Such implementations are much more complex and may not give a lot of
// improvement for typical sequences of a few thousand bits.
int LfsrLengthImpl(const std::vector<uint64_t> &seq, int n) {
  std::vector<uint64_t> sb(seq);
  std::vector<uint64_t> sc(seq);
  std::vector<uint64_t> tb(seq.size(), 0);
  std::vector<uint64_t> tc(seq.size(), 0);
  int lfsr_len = 0;
  int n0 = n - (n & 63);
  int size = seq.size();
  for (int j = 0; j < n0; j += 64) {
    uint64_t sb0 = sb[0];
    uint64_t sc0 = sc[0];
    uint64_t a = 1;
    uint64_t b = 0;
    uint64_t c = 0;
    uint64_t d = 1;
    uint64_t carry_a = 0;
    uint64_t carry_c = 0;
    for (int i = 0; i < 64; i++) {
      int disc = sc0 & 1;
      sc0 >>= 1;
      carry_a = a >> 63;
      carry_c = 0;
      a <<= 1;
      b <<= 1;
      if (disc == 1) {
        if (2 * lfsr_len <= i + j) {
          lfsr_len = (i + j) + 1 - lfsr_len;
          std::swap(sb0, sc0);
          std::swap(a, c);
          std::swap(b, d);
          std::swap(carry_a, carry_c);
        }
        sc0 ^= sb0;
        c ^= a;
        carry_c ^= carry_a;
        d ^= b;
      }
    }
    if (carry_a) {
      tb = sb;
    } else {
      for (int i = 0; i < size; i++) {
        tb[i] = 0;
      }
    }
    if (carry_c) {
      tc = sb;
    } else {
      for (int i = 0; i < size; i++) {
        tc[i] = 0;
      }
    }
    tb[0] = sb0;
    tc[0] = sc0;
    for (int i = 1; i < size; i++) {
      uint64_t hi;
      uint64_t lo;
      uint64_t sbi = sb[i];
      uint64_t sci = sc[i];
      clmul(a, sbi, &hi, &lo);
      tb[i - 1] ^= lo;
      tb[i] ^= hi;
      clmul(b, sci, &hi, &lo);
      tb[i - 1] ^= lo;
      tb[i] ^= hi;
      clmul(c, sbi, &hi, &lo);
      tc[i - 1] ^= lo;
      tc[i] ^= hi;
      clmul(d, sci, &hi, &lo);
      tc[i - 1] ^= lo;
      tc[i] ^= hi;
    }
    sb.swap(tb);
    sc.swap(tc);
    size--;
  }
  uint64_t sb0 = sb[0];
  uint64_t sc0 = sc[0];
  for (int i = n0; i < n; i++) {
    int disc = sc0 & 1;
    sc0 >>= 1;
    if (disc == 1) {
      if (2 * lfsr_len <= i) {
        lfsr_len = i + 1 - lfsr_len;
        std::swap(sb0, sc0);
      }
      sc0 ^= sb0;
    }
  }
  return lfsr_len;
}

#else
// This is fall-back code for CPU's without clmul.
// The code hasn't been optimized.
int LfsrLengthImpl(const std::vector<uint64_t> &seq, int n) {
  std::vector<uint64_t> sb(seq);
  std::vector<uint64_t> sc(seq);
  int lfsr_len = 0;
  for (int i = 0; i < n; i++) {
    int disc = sc[0] & 1;
    for (int j = 0; j < sc.size() - 1; j++) {
      sc[j] = (sc[j] >> 1) | (sc[j + 1] << 63);
    }
    sc[sc.size() - 1] >>= 1;
    if (disc == 1) {
      if (2 * lfsr_len <= i) {
        lfsr_len = i + 1 - lfsr_len;
        sb.swap(sc);
      }
      for (int j = 0; j < sc.size(); j++) {
        sc[j] ^= sb[j];
      }
    }
  }
  return lfsr_len;
}
#endif

bool LfsrLength(const std::vector<uint8_t> &seq, int n, int *length) {
  if (n < 0 || (size_t)n > 8 * seq.size()) {
    return false;
  }
  std::vector<uint64_t> s((seq.size() + 7) / 8);
  for (size_t i = 0; i < seq.size(); i++) {
    uint64_t byte = seq[i];
    s[i / 8] ^= byte << (8 * (i & 7));
  }
  *length = LfsrLengthImpl(s, n);
  return true;
}

int LfsrLengthStr(const std::string &seq, int n) {
  // TODO(bleichen): To avoid duplication of memory it would be better to
  //   convert python bytes directly to vector<uint8_t>.
  //   Whether such a conversion is possible and sufficiently well supported
  //   is unclear to me. The only discussion I could find so far is
  //   https://github.com/pybind/pybind11/issues/1807
  int length;
  if (LfsrLength(std::vector<uint8_t>(seq.begin(), seq.end()), n, &length))
    return length;
  return -1;
}

}  // namespace paranoid_crypto::lib::randomness_tests::cc_util
