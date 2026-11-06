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

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "testing/base/public/gunit.h"

namespace paranoid_crypto::lib::cc_util {
namespace {

std::string PackU16LE(uint16_t v) {
  std::string s(2, '\0');
  s[0] = static_cast<char>(v & 0xFFU);
  s[1] = static_cast<char>((v >> 8) & 0xFFU);
  return s;
}

// Reference arithmetic on y^2 = x^3 + 1006*x + 4 (mod 1009), G = (0, 2),
// prime group order n = 967.
constexpr int kMod = 1009;
constexpr int kA = 1006;
constexpr int kOrder = 967;

int ModNorm(int x) {
  int r = x % kMod;
  return r < 0 ? r + kMod : r;
}

int ModInv(int x) {
  x = ModNorm(x);
  int res = 1;
  int base = x;
  int exp = kMod - 2;
  while (exp > 0) {
    if (exp & 1) res = (res * base) % kMod;
    base = (base * base) % kMod;
    exp >>= 1;
  }
  return res;
}

struct RefPt {
  int x;
  int y;
  bool inf;
};

RefPt RefAdd(RefPt p, RefPt q) {
  if (p.inf) return q;
  if (q.inf) return p;
  if (p.x == q.x) {
    if (p.y != q.y || p.y == 0) return {0, 0, true};
    int lam = ModNorm(3 * p.x * p.x + kA) * ModInv(2 * p.y) % kMod;
    int x3 = ModNorm(lam * lam - 2 * p.x);
    int y3 = ModNorm(lam * (p.x - x3) - p.y);
    return {x3, y3, false};
  }
  int lam = ModNorm(p.y - q.y) * ModInv(p.x - q.x) % kMod;
  int x3 = ModNorm(lam * lam - p.x - q.x);
  int y3 = ModNorm(lam * (p.x - x3) - p.y);
  return {x3, y3, false};
}

RefPt RefMulG(int k) {
  int s = k % kOrder;
  if (s < 0) s += kOrder;
  RefPt acc{0, 0, true};
  RefPt cur{0, 2, false};
  while (s > 0) {
    if (s & 1) acc = RefAdd(acc, cur);
    cur = RefAdd(cur, cur);
    s >>= 1;
  }
  return acc;
}

std::string PackRefPts(const std::vector<RefPt>& pts) {
  std::string out;
  out.reserve(pts.size() * 5);
  for (const RefPt& p : pts) {
    if (p.inf) {
      out.append(5, '\0');
    } else {
      out.push_back('\x01');
      out.append(PackU16LE(static_cast<uint16_t>(p.x)));
      out.append(PackU16LE(static_cast<uint16_t>(p.y)));
    }
  }
  return out;
}

std::unique_ptr<EcBatchEngine> MakeSmallEngine() {
  return EcBatchEngine::Create(PackU16LE(kMod), PackU16LE(kA), PackU16LE(0),
                               PackU16LE(2));
}

std::string HexBE32ToLE(std::string_view hex) {
  std::string out(32, '\0');
  auto nib = [](char c) -> uint8_t {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    return static_cast<uint8_t>(c - 'A' + 10);
  };
  for (int i = 0; i < 32; ++i) {
    uint8_t b =
        static_cast<uint8_t>((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
    out[31 - i] = static_cast<char>(b);
  }
  return out;
}

TEST(EcBatchTest, RejectsInvalidParameters) {
  // Empty modulus.
  EXPECT_EQ(EcBatchEngine::Create("", "", "", ""), nullptr);
  // Mismatched coordinate byte lengths.
  EXPECT_EQ(EcBatchEngine::Create(PackU16LE(1009), std::string(1, '\0'),
                                  PackU16LE(0), PackU16LE(2)),
            nullptr);
  // Even modulus.
  EXPECT_EQ(EcBatchEngine::Create(PackU16LE(1008), PackU16LE(0), PackU16LE(0),
                                  PackU16LE(2)),
            nullptr);
  // Modulus < 5.
  EXPECT_EQ(EcBatchEngine::Create(PackU16LE(3), PackU16LE(0), PackU16LE(0),
                                  PackU16LE(1)),
            nullptr);
  // Coordinate >= modulus.
  EXPECT_EQ(EcBatchEngine::Create(PackU16LE(1009), PackU16LE(1009),
                                  PackU16LE(0), PackU16LE(2)),
            nullptr);
  // Modulus > 1024 bytes.
  std::string big_mod(1025, '\0');
  big_mod[0] = '\x05';
  EXPECT_EQ(EcBatchEngine::Create(big_mod, std::string(1025, '\0'),
                                  std::string(1025, '\0'),
                                  std::string(1025, '\0')),
            nullptr);
}

TEST(EcBatchTest, InvalidPackedBufferReturnsFalse) {
  auto eng = MakeSmallEngine();
  ASSERT_NE(eng, nullptr);
  EXPECT_EQ(eng->coord_bytes(), 2);
  std::vector<std::pair<int64_t, int64_t>> dl_hits;
  EXPECT_FALSE(eng->BatchDL(std::string(4, '\0'), 16, 1, &dl_hits));
  std::vector<ExtendedDlMatch> ext_hits;
  EXPECT_FALSE(eng->ExtendedBatchDL(std::string(5, '\0'), std::string(3, '\0'),
                                    2, 1, 1, "", &ext_hits));
  std::vector<DiffDlMatch> diff_hits;
  EXPECT_FALSE(eng->DiffBatchDL(std::string(4, '\0'), "", 16, 64, &diff_hits));
}

TEST(EcBatchTest, SmallCurveBatchDLExhaustive) {
  auto eng = MakeSmallEngine();
  ASSERT_NE(eng, nullptr);

  std::vector<RefPt> pts;
  pts.reserve(kOrder);
  for (int d = 0; d < kOrder; ++d) {
    pts.push_back(RefMulG(d));
  }
  std::vector<std::pair<int64_t, int64_t>> hits;
  ASSERT_TRUE(eng->BatchDL(PackRefPts(pts), 400, pts.size(), &hits));
  std::vector<int> solved(kOrder, -1);
  for (const auto& [idx, signed_dl] : hits) {
    int norm = static_cast<int>(signed_dl % kOrder);
    if (norm < 0) norm += kOrder;
    solved[static_cast<size_t>(idx)] = norm;
  }
  for (int d = 0; d < 400; ++d) {
    EXPECT_EQ(solved[d], d) << "Missing DL " << d;
  }
  EXPECT_GT(eng->table_size(), 0);
}

TEST(EcBatchTest, SmallCurveDiffBatchDLSymmetricTiledAndDuplicates) {
  auto eng = MakeSmallEngine();
  ASSERT_NE(eng, nullptr);

  std::vector<int> scalars = {100, 100, 117, 500, 500, 800, 785};
  std::vector<RefPt> pts;
  for (int s : scalars) pts.push_back(RefMulG(s));
  std::string packed = PackRefPts(pts);

  auto check_hits = [&](const std::vector<DiffDlMatch>& hits) {
    std::vector<bool> matched(scalars.size(), false);
    for (const DiffDlMatch& h : hits) {
      ASSERT_GE(h.point_index, 0);
      ASSERT_LT(h.point_index, static_cast<int64_t>(scalars.size()));
      ASSERT_GE(h.ref_index, 0);
      ASSERT_LT(h.ref_index, static_cast<int64_t>(scalars.size()));
      EXPECT_NE(h.dl, 0);
      EXPECT_LT(std::abs(h.dl), 20);
      int diff = (scalars[h.point_index] - scalars[h.ref_index]) % kOrder;
      if (diff > kOrder / 2) diff -= kOrder;
      if (diff < -kOrder / 2) diff += kOrder;
      EXPECT_EQ(diff, h.dl);
      matched[h.point_index] = true;
      matched[h.ref_index] = true;
    }
    EXPECT_TRUE(matched[0]);
    EXPECT_TRUE(matched[1]);
    EXPECT_TRUE(matched[2]);
    EXPECT_FALSE(matched[3]);
    EXPECT_FALSE(matched[4]);
    EXPECT_TRUE(matched[5]);
    EXPECT_TRUE(matched[6]);
  };

  std::vector<DiffDlMatch> hits_full;
  ASSERT_TRUE(eng->DiffBatchDL(packed, "", /*max_diff=*/20,
                               EcBatchEngine::kDefaultMaxDiffBabyEntries,
                               &hits_full));
  check_hits(hits_full);

  std::vector<DiffDlMatch> hits_tiled;
  ASSERT_TRUE(eng->DiffBatchDL(packed, "", /*max_diff=*/20,
                               /*max_baby_entries=*/9, &hits_tiled));
  check_hits(hits_tiled);
}

TEST(EcBatchTest, P256EngineBatchAndDiffDL) {
  std::string mod_le = HexBE32ToLE(
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
  std::string a_le = HexBE32ToLE(
      "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
  std::string gx_le = HexBE32ToLE(
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
  std::string gy_le = HexBE32ToLE(
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
  auto eng = EcBatchEngine::Create(mod_le, a_le, gx_le, gy_le);
  ASSERT_NE(eng, nullptr);
  EXPECT_EQ(eng->coord_bytes(), 32);

  // Pack [INFINITY, 1*G, 2*G].
  std::string x2_le = HexBE32ToLE(
      "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978");
  std::string y2_le = HexBE32ToLE(
      "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
  std::string pts;
  pts.append(65, '\0');
  pts.push_back('\x01');
  pts.append(gx_le);
  pts.append(gy_le);
  pts.push_back('\x01');
  pts.append(x2_le);
  pts.append(y2_le);

  std::vector<std::pair<int64_t, int64_t>> dl_hits;
  ASSERT_TRUE(eng->BatchDL(pts, 16, 3, &dl_hits));
  ASSERT_EQ(dl_hits.size(), 3U);
  EXPECT_EQ(dl_hits[0], std::make_pair(int64_t{0}, int64_t{0}));
  EXPECT_EQ(dl_hits[1], std::make_pair(int64_t{1}, int64_t{1}));
  EXPECT_EQ(dl_hits[2], std::make_pair(int64_t{2}, int64_t{2}));

  // DiffBatchDL on [1*G, 2*G] should find difference +/-1.
  std::string two_pts = pts.substr(65);
  std::vector<DiffDlMatch> diff_hits;
  ASSERT_TRUE(eng->DiffBatchDL(two_pts, "", 16, 1024, &diff_hits));
  ASSERT_EQ(diff_hits.size(), 1U);
  EXPECT_EQ(std::abs(diff_hits[0].dl), 1);
}

}  // namespace
}  // namespace paranoid_crypto::lib::cc_util
