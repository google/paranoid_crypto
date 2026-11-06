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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace paranoid_crypto::lib::cc_util::pybind {

namespace py = ::pybind11;

PYBIND11_MODULE(rsa_batch, m) {
  py::class_<RsaBatchAccumulator>(m, "RsaBatchAccumulator")
      .def(py::init([](size_t chunk_target_bytes, size_t chunks_per_superchunk,
                       int num_threads) {
             RsaBatchOptions opts;
             opts.chunk_target_bytes = chunk_target_bytes;
             opts.chunks_per_superchunk = chunks_per_superchunk;
             opts.num_threads = num_threads;
             return RsaBatchAccumulator(opts);
           }),
           py::arg("chunk_target_bytes") = 16ULL * 1024 * 1024,
           py::arg("chunks_per_superchunk") = 64, py::arg("num_threads") = 0)
      .def(
          "Reserve",
          [](RsaBatchAccumulator& self, size_t expected_inputs,
             size_t expected_limb_bytes) {
            py::gil_scoped_release release;
            self.Reserve(expected_inputs, expected_limb_bytes);
          },
          py::arg("expected_inputs"), py::arg("expected_limb_bytes") = 0)
      .def("num_inputs", &RsaBatchAccumulator::num_inputs)
      .def("num_unique_leaves", &RsaBatchAccumulator::num_unique_leaves)
      .def("AddSignedBigEndian",
           [](RsaBatchAccumulator& self, bool is_negative,
              py::bytes magnitude_be) {
             auto sv = static_cast<std::string_view>(magnitude_be);
             py::gil_scoped_release release;
             self.AddSignedBigEndian(is_negative, sv);
           })
      .def("AddSignedBatch",
           [](RsaBatchAccumulator& self, py::sequence items) {
             const size_t n = py::len(items);
             std::vector<py::bytes> pinned;
             std::vector<std::pair<bool, std::string_view>> views;
             pinned.reserve(n);
             views.reserve(n);
             for (size_t i = 0; i < n; ++i) {
               py::tuple tup = items[i].cast<py::tuple>();
               if (tup.size() != 2) {
                 throw py::value_error(
                     "Each item in AddSignedBatch must be (is_neg, bytes)");
               }
               bool is_neg = tup[0].cast<bool>();
               py::bytes b = tup[1].cast<py::bytes>();
               views.emplace_back(is_neg, static_cast<std::string_view>(b));
               pinned.push_back(std::move(b));
             }
             {
               py::gil_scoped_release release;
               for (const auto& [is_neg, sv] : views) {
                 self.AddSignedBigEndian(is_neg, sv);
               }
             }
           })
      .def(
          "AddModulusBigEndian",
          [](RsaBatchAccumulator& self, py::bytes modulus_be,
             bool subtract_one) {
            auto sv = static_cast<std::string_view>(modulus_be);
            py::gil_scoped_release release;
            self.AddModulusBigEndian(sv, subtract_one);
          },
          py::arg("modulus_be"), py::arg("subtract_one") = false)
      .def(
          "AddModulusBatch",
          [](RsaBatchAccumulator& self, py::sequence moduli_bytes,
             bool subtract_one) {
            const size_t n = py::len(moduli_bytes);
            std::vector<py::bytes> pinned;
            std::vector<std::string_view> views;
            pinned.reserve(n);
            views.reserve(n);
            for (size_t i = 0; i < n; ++i) {
              py::bytes b = moduli_bytes[i].cast<py::bytes>();
              views.push_back(static_cast<std::string_view>(b));
              pinned.push_back(std::move(b));
            }
            {
              py::gil_scoped_release release;
              for (std::string_view sv : views) {
                self.AddModulusBigEndian(sv, subtract_one);
              }
            }
          },
          py::arg("moduli_bytes"), py::arg("subtract_one") = false)
      .def(
          "ComputeAllGcds",
          [](RsaBatchAccumulator& self,
             std::optional<py::bytes> other_prod_be) {
            std::optional<std::string_view> other_sv;
            if (other_prod_be.has_value()) {
              other_sv = static_cast<std::string_view>(*other_prod_be);
            }
            std::vector<std::string> raw;
            {
              py::gil_scoped_release release;
              raw = self.ComputeAllGcds(other_sv);
            }
            py::list out(raw.size());
            for (size_t i = 0; i < raw.size(); ++i) {
              out[i] = py::bytes(raw[i]);
            }
            return out;
          },
          py::arg("other_prod_be") = py::none())
      .def(
          "ComputeFilteredGcds",
          [](RsaBatchAccumulator& self, py::bytes min_gcd_be,
             std::optional<py::bytes> other_prod_be) {
            auto min_sv = static_cast<std::string_view>(min_gcd_be);
            std::optional<std::string_view> other_sv;
            if (other_prod_be.has_value()) {
              other_sv = static_cast<std::string_view>(*other_prod_be);
            }
            std::vector<std::pair<int64_t, std::string>> hits;
            {
              py::gil_scoped_release release;
              hits = self.ComputeFilteredGcds(min_sv, other_sv);
            }
            py::list out(hits.size());
            for (size_t i = 0; i < hits.size(); ++i) {
              out[i] = py::make_tuple(hits[i].first, py::bytes(hits[i].second));
            }
            return out;
          },
          py::arg("min_gcd_be"), py::arg("other_prod_be") = py::none());
}

}  // namespace paranoid_crypto::lib::cc_util::pybind
