from absl.testing import absltest
from paranoid_crypto.lib.randomness_tests import exp1
from paranoid_crypto.lib.randomness_tests import extended_nist_suite


class ExtendedNistSuite(absltest.TestCase):

  def testLargeBinaryMatrixRank(self):
    """Regression test."""
    size = 1000000
    bits = exp1.bits(size)
    test_result = extended_nist_suite.LargeBinaryMatrixRank(bits, size)
    p_values = [pv[1] for pv in test_result]
    expected = [
        0.133636,  # p-value for 64*64 matrix with rank 62
        0.711212,  # p-value for 128*128 matrix with rank 127
        0.711212,  # p-value for 256*256 matrix with rank 255
        1.0,  # p-value for 512*512 matrix with rank 512
    ]
    self.assertSequenceAlmostEqual(expected, p_values, delta=1e-06)


if __name__ == "__main__":
  absltest.main()
