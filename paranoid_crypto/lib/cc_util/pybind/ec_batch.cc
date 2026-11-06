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
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace paranoid_crypto::lib::cc_util::pybind {

namespace py = ::pybind11;

PYBIND11_MODULE(ec_batch, m) {
  m.attr("MAX_DL_TABLE_SIZE") = EcBatchEngine::kMaxDlTableSize;
  m.attr("DEFAULT_MAX_DIFF_BABY_ENTRIES") =
      EcBatchEngine::kDefaultMaxDiffBabyEntries;

  py::class_<EcBatchEngine>(m, "EcBatchEngine")
      .def_static(
          "Create",
          [](py::bytes mod_le, py::bytes a_le, py::bytes gx_le,
             py::bytes gy_le) {
            auto mod_sv = static_cast<std::string_view>(mod_le);
            auto a_sv = static_cast<std::string_view>(a_le);
            auto gx_sv = static_cast<std::string_view>(gx_le);
            auto gy_sv = static_cast<std::string_view>(gy_le);
            py::gil_scoped_release release;
            return EcBatchEngine::Create(mod_sv, a_sv, gx_sv, gy_sv);
          })
      .def("coord_bytes", &EcBatchEngine::coord_bytes)
      .def("table_size", &EcBatchEngine::table_size)
      .def("EnsureTable",
           [](EcBatchEngine& self, int64_t target_size) {
             py::gil_scoped_release release;
             self.EnsureTable(target_size);
           })
      .def("BatchDL",
           [](EcBatchEngine& self, py::bytes points_le, int64_t n,
              int64_t expected_points) {
             auto pts_sv = static_cast<std::string_view>(points_le);
             std::vector<std::pair<int64_t, int64_t>> hits;
             bool ok = false;
             {
               py::gil_scoped_release release;
               ok = self.BatchDL(pts_sv, n, expected_points, &hits);
             }
             if (!ok) {
               throw py::value_error("Invalid packed points byte length");
             }
             return hits;
           })
      .def("ExtendedBatchDL",
           [](EcBatchEngine& self, py::bytes points_le, py::bytes inverses_le,
              int scalar_bytes, int num_byte_shifts, int num_window_mults,
              py::bytes comp_points_le) {
             auto pts_sv = static_cast<std::string_view>(points_le);
             auto inv_sv = static_cast<std::string_view>(inverses_le);
             auto comp_sv = static_cast<std::string_view>(comp_points_le);
             std::vector<ExtendedDlMatch> hits;
             bool ok = false;
             {
               py::gil_scoped_release release;
               ok = self.ExtendedBatchDL(pts_sv, inv_sv, scalar_bytes,
                                         num_byte_shifts, num_window_mults,
                                         comp_sv, &hits);
             }
             if (!ok) {
               throw py::value_error("Invalid ExtendedBatchDL packed inputs");
             }
             std::vector<std::tuple<int64_t, int32_t, int32_t, int64_t>> out;
             out.reserve(hits.size());
             for (const ExtendedDlMatch& h : hits) {
               out.emplace_back(h.key_index, h.kind, h.aux_index, h.signed_dl);
             }
             return out;
           })
      .def("DiffBatchDL",
           [](EcBatchEngine& self, py::bytes points_le,
              py::bytes other_points_le, int64_t max_diff,
              int64_t max_baby_entries) {
             auto pts_sv = static_cast<std::string_view>(points_le);
             auto other_sv = static_cast<std::string_view>(other_points_le);
             std::vector<DiffDlMatch> hits;
             bool ok = false;
             {
               py::gil_scoped_release release;
               ok = self.DiffBatchDL(pts_sv, other_sv, max_diff,
                                     max_baby_entries, &hits);
             }
             if (!ok) {
               throw py::value_error("Invalid DiffBatchDL packed inputs");
             }
             std::vector<std::tuple<int64_t, int64_t, int64_t>> out;
             out.reserve(hits.size());
             for (const DiffDlMatch& h : hits) {
               out.emplace_back(h.point_index, h.ref_index, h.dl);
             }
             return out;
           });
}

}  // namespace paranoid_crypto::lib::cc_util::pybind
