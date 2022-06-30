from absl.testing import absltest
from paranoid_crypto.lib.randomness_tests.cc_util.pybind import berlekamp_massey


class BerlekampMasseyTest(absltest.TestCase):
  """Tests the pybind binding.

  The tests for the C++ implementation are in
    paranoid_crypto/lib/randomness_tests/cc_util/berlekamp_massey_test.cc
  The tests comparing the C++ version with the native python version are in
    paranoid_crypto/lib/randomness_tests/berlekamp_massey_test.py
  """

  # Format: seq, n, lfsr_len
  KTV = [(4, 3, 3), (4, 5, 3), (4, 6, 3), (36, 6, 3), (356, 9, 4),
         (12345, 14, 7)]

  def testKtv(self):
    for seq, n, lfsr_len in self.KTV:
      byte_size = (n + 7) // 8
      ba = seq.to_bytes(byte_size, "little")
      self.assertEqual(lfsr_len, berlekamp_massey.LfsrLength(ba, n))

  def testWrongSize(self):
    self.assertEqual(berlekamp_massey.LfsrLength(bytes(), -1), -1)
    self.assertEqual(berlekamp_massey.LfsrLength(bytes(8), 65), -1)

  def testOverflow(self):
    """Checks that large sizes are rejected.

    This test is to some degree implementation dependent.
    E.g. sizes larger than 2^64 raise an OverflowError.
    The main property we expect is simply that there is no crash.
    """
    with self.assertRaises(TypeError):
      berlekamp_massey.LfsrLength(bytes(8), 2**31)
    with self.assertRaises(TypeError):
      berlekamp_massey.LfsrLength(bytes(8), 2**32)
    with self.assertRaises(TypeError):
      berlekamp_massey.LfsrLength(bytes(8), 2**32 + 8)

  def testWrongType(self):
    with self.assertRaises(TypeError):
      berlekamp_massey.LfsrLength(12345, 22)
    with self.assertRaises(TypeError):
      berlekamp_massey.LfsrLength(None, 8)


if __name__ == "__main__":
  absltest.main()
