# Copyright 2022 Google LLC
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
"""Tests for paranoid_crypto.lib.cr50_u2f_weakness.py."""

from absl.testing import absltest
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import cr50_u2f_weakness
from paranoid_crypto.lib import ec_util

SAMPLE_U2F_SECP224R1 = {
    "curve":
        paranoid_pb2.CurveType.CURVE_SECP224R1,
    "priv":
        1405058413736824527508563347417521711547493598731770651248399557419,
    "signatures": [
        {
            "r":
                4066333731994269891001682666254148727467591992523762347602363161331,
            "s":
                8539628877927249734775286169797583055890332428977859231497710055685,
            "digest":
                "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"
        },
        {
            "r":
                3245391768243107066936528979125927615913454077906891650801735937702,
            "s":
                26723670119267067991281972514667761580142089061261022027775654624554,
            "digest":
                "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"
        },
    ]
}

SAMPLE_U2F_SECP256R1 = {
    "curve":
        paranoid_pb2.CurveType.CURVE_SECP256R1,
    "priv":
        46313670404577787786748712380680137560820270160639462371779709866557866780772,
    "signatures": [
        {
            "r":
                15701026971377442081090839023848360058966109880255660361465838467323068302022,
            "s":
                13427114352134903018852715621960200348541010143402442336291414488315260135418,
            "digest":
                "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"
        },
        {
            "r":
                22615145658369751563317802956100046241449728980523633040731324963990847461966,
            "s":
                68031669449768417658968724756377897116555527139830588191576968382729281116202,
            "digest":
                "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"
        },
        {
            "r":
                12723503560978590896261413195310164943275342441135691675710975003818420289947,
            "s":
                94216918566023799170480608031895673448980903213349846038118511847443355146426,
            "digest":
                "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"
        },
        {
            "r":
                60146365945992178761491902181431898268689455398369153865281373532514504242105,
            "s":
                14967720978214280636460378124194892645683462108806102605009285353361083631002,
            "digest":
                "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"
        },
    ]
}

SAMPLE_U2F_SECP384R1 = {
    "curve":
        paranoid_pb2.CurveType.CURVE_SECP384R1,
    "priv":
        11751609212910524090459682262583216517179731851904677053084405969331142645346591451632145178134174408737279658982850,
    "signatures": [
        {
            "r":
                26939681562583055433444593353749990617315122021007091638297032952103386523573201754080414264259406008911044072000673,
            "s":
                27902259167652179925526895445489434575121307781155277141877437622541200180273802144552970398692782112372887799244765,
            "digest":
                "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"
        },
        {
            "r":
                37155947669390621514708888440803607757913794927325740871271777557399694626472569009917143758199181778442555149894477,
            "s":
                23935062211519575550058037326846305645141799503782038317219239387108416708993965634708709602616451110969161134030433,
            "digest":
                "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"
        },
    ]
}


class Cr50U2fWeaknessTest(absltest.TestCase):

  def GetCurve(self, curve_type: paranoid_pb2.CurveType) -> ec_util.EcCurve:
    """Returns an elliptic curve for a given name.

    Args:
      curve_type: the type of the curve

    Returns:
      the elliptic curve
    """
    curve = ec_util.CURVE_FACTORY.get(curve_type, None)
    if curve is None:
      raise ValueError("Unknown Curve:" + str(curve_type))
    else:
      return curve

  def CheckSample(self, sample):
    curve = self.GetCurve(sample["curve"])
    n = curve.n
    signatures = sample["signatures"]
    priv = sample["priv"]
    for j in range(len(signatures)):
      for i in range(j):
        r1 = signatures[i]["r"]
        s1 = signatures[i]["s"]
        digest1 = signatures[i]["digest"]
        z1 = curve.TransformOrderLen(int(digest1, 16), len(digest1) * 4)
        r2 = signatures[j]["r"]
        s2 = signatures[j]["s"]
        digest2 = signatures[j]["digest"]
        z2 = curve.TransformOrderLen(int(digest2, 16), len(digest2) * 4)
        guesses = cr50_u2f_weakness.Cr50U2fGuesses(r1, s1, z1, r2, s2, z2, n)
        self.assertContainsSubset([priv], guesses)

  def testU2fSecp224r1(self):
    self.CheckSample(SAMPLE_U2F_SECP224R1)

  def testU2fSecp256r1(self):
    self.CheckSample(SAMPLE_U2F_SECP256R1)

  def testU2fSecp384r1(self):
    self.CheckSample(SAMPLE_U2F_SECP384R1)


if __name__ == "__main__":
  absltest.main()
