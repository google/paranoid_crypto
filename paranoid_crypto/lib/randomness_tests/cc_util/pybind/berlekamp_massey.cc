#include "paranoid_crypto/lib/randomness_tests/cc_util/berlekamp_massey.h"

#include "pybind11/pybind11.h"

namespace paranoid_crypto::lib::randomness_tests::cc_util::pybind {

PYBIND11_MODULE(berlekamp_massey, m) { m.def("LfsrLength", LfsrLengthStr); }

}  // namespace paranoid_crypto::lib::randomness_tests::cc_util::pybind
