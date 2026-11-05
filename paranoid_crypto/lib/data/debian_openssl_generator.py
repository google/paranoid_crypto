# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Module for reconstructing EC private keys affected by CVE-2008-0166.

NOTE: This clean-room implementation models the crippled Debian/Ubuntu OpenSSL
0.9.8c-0.9.8g PRNG solely as a helper for testing public keys potentially
vulnerable to CVE-2008-0166 (reconstructing candidate scalars from compact
(config_index, pid) metadata in openssl_denylist_ec.lzma). Please do not
copy-paste nor use this code.
"""

import hashlib
import struct

_STATE_SIZE = 1023
_MD_DIGEST_LENGTH = 20
_ENTROPY_NEEDED = 32.0

# Each configuration is (sizeof_long, little_endian, mode, sizeof_stat):
#   - (4, True, ..., 88):  32-bit little-endian (i386, arm, armel, mipsel)
#   - (8, True, ..., 144): 64-bit little-endian (amd64, ia64, alpha)
#   - (4, False, ..., 88): 32-bit big-endian (powerpc, sparc, s390, hppa, m68k,
#     mips)
# Pre-seeding modes prior to EC_KEY_generate_key:
#   - "no_rnd":     RAND_status() called (CLI/OpenSSH with no ~/.rnd file)
#   - "with_rnd":   RAND_load_file("~/.rnd") with 1024-byte file (stat + 1024B)
#   - "rnd_0bytes": RAND_load_file("/dev/null" or empty ~/.rnd) + RAND_status()
#   - "direct_api": Direct EC_KEY_generate_key() call with no prior RAND calls
CONFIGS: tuple[tuple[int, bool, str, int], ...] = (
    (4, True, "no_rnd", 88),
    (4, True, "with_rnd", 88),
    (4, True, "rnd_0bytes", 88),
    (4, True, "direct_api", 88),
    (8, True, "no_rnd", 144),
    (8, True, "with_rnd", 144),
    (8, True, "rnd_0bytes", 144),
    (8, True, "direct_api", 144),
    (4, False, "no_rnd", 88),
    (4, False, "with_rnd", 88),
    (4, False, "rnd_0bytes", 88),
    (4, False, "direct_api", 88),
)


class CrippledMD5SHA1Rand:
  """Clean-room model of OpenSSL 0.9.8 md_rand.c with the CVE-2008-0166 bug."""

  def __init__(self, sizeof_long: int, little_endian: bool, pid: int):
    self.sizeof_long = sizeof_long
    self.little_endian = little_endian
    self.pid = pid
    self.pack_pid = struct.pack("<i" if little_endian else ">i", pid)
    if sizeof_long == 4:
      self._pack_counts = struct.Struct("<ii" if little_endian else ">ii").pack
    else:
      self._pack_counts = struct.Struct("<qq" if little_endian else ">qq").pack

    self.state = bytearray(_STATE_SIZE + _MD_DIGEST_LENGTH)
    self.state_num = 0
    self.state_index = 0
    self.md = bytearray(_MD_DIGEST_LENGTH)
    self.md_count = [0, 0]
    self.entropy = 0.0
    self.initialized = False
    self.stirred_pool = False

  def rand_add(self, num: int, add: float) -> None:
    """Models ssleay_rand_add with the input buffer update removed."""
    if num == 0:
      return
    st_idx = self.state_index
    md_c0, md_c1 = self.md_count[0], self.md_count[1]
    local_md = bytes(self.md)

    self.state_index += num
    if self.state_index >= _STATE_SIZE:
      self.state_index %= _STATE_SIZE
      self.state_num = _STATE_SIZE
    elif self.state_num < _STATE_SIZE:
      if self.state_index > self.state_num:
        self.state_num = self.state_index

    self.md_count[1] += (num // _MD_DIGEST_LENGTH) + (
        1 if (num % _MD_DIGEST_LENGTH) > 0 else 0
    )

    state = self.state
    pack = self._pack_counts
    for i in range(0, num, _MD_DIGEST_LENGTH):
      j = num - i
      if j > _MD_DIGEST_LENGTH:
        j = _MD_DIGEST_LENGTH
      h = hashlib.sha1()
      h.update(local_md)
      k = (st_idx + j) - _STATE_SIZE
      if k > 0:
        h.update(state[st_idx : st_idx + j - k])
        h.update(state[0:k])
      else:
        h.update(state[st_idx : st_idx + j])
      # CVE-2008-0166: MD_Update(&m, buf, j) was commented out in Debian.
      h.update(pack(md_c0, md_c1))
      local_md = h.digest()
      md_c1 += 1
      for k_idx in range(j):
        state[st_idx] ^= local_md[k_idx]
        st_idx += 1
        if st_idx >= _STATE_SIZE:
          st_idx = 0

    for k_idx in range(_MD_DIGEST_LENGTH):
      self.md[k_idx] ^= local_md[k_idx]
    if self.entropy < _ENTROPY_NEEDED:
      self.entropy += add

  def rand_poll(self) -> None:
    """Models RAND_poll on Linux (/dev/urandom 32B + pid + uid + time)."""
    self.rand_add(32, 32.0)
    self.rand_add(self.sizeof_long, 0.0)
    self.rand_add(self.sizeof_long, 0.0)
    self.rand_add(self.sizeof_long, 0.0)

  def rand_status(self) -> bool:
    """Models ssleay_rand_status."""
    if not self.initialized:
      self.rand_poll()
      self.initialized = True
    return self.entropy >= _ENTROPY_NEEDED

  def rand_bytes(self, num: int) -> bytes:
    """Models ssleay_rand_bytes with the output buffer update removed."""
    if num <= 0:
      return b""
    num_ceil = (1 + (num - 1) // 10) * 10
    if not self.initialized:
      self.rand_poll()
      self.initialized = True

    do_stir_pool = not self.stirred_pool
    ok = self.entropy >= _ENTROPY_NEEDED
    if not ok:
      self.entropy -= num
      if self.entropy < 0:
        self.entropy = 0.0

    if do_stir_pool:
      n = _STATE_SIZE
      while n > 0:
        self.rand_add(_MD_DIGEST_LENGTH, 0.0)
        n -= _MD_DIGEST_LENGTH
      if ok:
        self.stirred_pool = True

    st_idx = self.state_index
    st_num = self.state_num
    md_c0, md_c1 = self.md_count[0], self.md_count[1]
    local_md = bytes(self.md)

    self.state_index += num_ceil
    if self.state_index > self.state_num:
      self.state_index %= self.state_num

    self.md_count[0] += 1

    out = bytearray()
    first = True
    state = self.state
    pack = self._pack_counts
    rem = num
    while rem > 0:
      j = 10 if rem >= 10 else rem
      rem -= j
      h = hashlib.sha1()
      if first and self.pid != 0:
        h.update(self.pack_pid)
      first = False
      h.update(local_md)
      h.update(pack(md_c0, md_c1))
      # CVE-2008-0166: MD_Update(&m, buf, j) was commented out in Debian.
      k = (st_idx + 10) - st_num
      if k > 0:
        h.update(state[st_idx : st_idx + 10 - k])
        h.update(state[0:k])
      else:
        h.update(state[st_idx : st_idx + 10])
      local_md = h.digest()
      for i in range(10):
        state[st_idx] ^= local_md[i]
        st_idx += 1
        if st_idx >= st_num:
          st_idx = 0
        if i < j:
          out.append(local_md[i + 10])

    h = hashlib.sha1()
    h.update(pack(md_c0, md_c1))
    h.update(local_md)
    h.update(self.md)
    self.md[:] = h.digest()
    return bytes(out)

  def bn_rand(self, bits: int, top: int, bottom: int) -> int:
    """Models OpenSSL 0.9.8 bn_rand."""
    if bits == 0:
      return 0
    num_bytes = (bits + 7) // 8
    bit = (bits - 1) % 8
    mask = (0xFF << (bit + 1)) & 0xFF
    # time(&tim); RAND_add(&tim, sizeof(tim), 0.0);
    self.rand_add(self.sizeof_long, 0.0)
    buf = bytearray(self.rand_bytes(num_bytes))
    if top >= 0:
      if top:
        if bit == 0:
          buf[0] = 1
          buf[1] |= 0x80
        else:
          buf[0] |= 3 << (bit - 1)
      else:
        buf[0] |= 1 << bit
    buf[0] &= ~mask
    if bottom:
      buf[num_bytes - 1] |= 1
    return int.from_bytes(buf, "big")

  def bn_rand_range(self, range_val: int) -> int:
    """Models OpenSSL 0.9.8 bn_rand_range."""
    n = range_val.bit_length()
    if n == 1:
      return 0
    bit_n2 = (range_val >> (n - 2)) & 1
    bit_n3 = ((range_val >> (n - 3)) & 1) if n >= 3 else 0
    if not bit_n2 and not bit_n3:
      while True:
        r = self.bn_rand(n + 1, -1, 0)
        if r >= range_val:
          r -= range_val
          if r >= range_val:
            r -= range_val
        if r < range_val:
          return r
    else:
      while True:
        r = self.bn_rand(n, -1, 0)
        if r < range_val:
          return r


def generate_ec_private_key(config_index: int, pid: int, order: int) -> int:
  """Reconstructs the EC private key d for a (config_index, pid, order) tuple.

  Args:
    config_index: Index into CONFIGS (0..11).
    pid: Process ID (0..32767) mixed into MD_Update during RAND_bytes.
    order: Subgroup order n of the elliptic curve.

  Returns:
    The generated EC private scalar d in [1, order - 1].
  """
  sizeof_long, little_endian, mode, sizeof_stat = CONFIGS[config_index]
  prng = CrippledMD5SHA1Rand(sizeof_long, little_endian, pid)
  if mode == "no_rnd":
    prng.rand_status()
  elif mode == "with_rnd":
    prng.rand_add(sizeof_stat, 0.0)
    prng.rand_add(1024, 1024.0)
  elif mode == "rnd_0bytes":
    prng.rand_add(sizeof_stat, 0.0)
    prng.rand_status()
  elif mode == "direct_api":
    pass
  else:
    raise ValueError(f"Unknown mode: {mode}")

  while True:
    d = prng.bn_rand_range(order)
    if d != 0:
      return d
