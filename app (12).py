"""Read-only preservation checks; never imports or executes application code.

Run from the project directory with:
    python -B -m unittest discover -s tests -p 'test_integrity.py' -v
"""

import codecs
import csv
import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "original_snapshot"
JSONL_NAME = "privacy_threat_dataset.jsonl"
SEED_NAME = "dataset_source.json"
JSONL_SHA256 = "b7b3ba360ee348d373f54a9ec324346de4b5e3d70c5e1d6f22d23eb8d7754e97"
SEED_SHA256 = "e49521a585124d27f85d062fd4b21959f6a5609b6203ddbec8db29dbb08a63e6"
FIELDS = [
    "id", "sub_label", "source", "text", "фрагмент_ИМЯ",
    "фрагмент_ТЕЛЕФОН", "фрагмент_АДРЕС", "фрагмент_EMAIL",
    "фрагмент_АККАУНТ", "фрагмент_ГЕОЛОКАЦИЯ", "language", "is_anonymized",
]
SNAPSHOT_NAMES = {
    "README.md", "app.py", "auto_collector.py", "build_13500.ps1",
    SEED_NAME, "generate_dataset.py", "privacy_threat_dataset.csv",
    JSONL_NAME, "privacy_threat_dataset_excel.csv", "requirements.txt",
    "run_build.bat", "run_build.ps1", "run_export.ps1",
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DatasetIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # UTF-8, without a permissive BOM-stripping decoder, is intentional.
        with (ROOT / JSONL_NAME).open(encoding="utf-8", newline="") as stream:
            cls.records = [json.loads(line) for line in stream]

    def test_canonical_jsonl_bytes_are_unchanged(self):
        self.assertEqual(sha256(ROOT / JSONL_NAME), JSONL_SHA256)
        self.assertEqual(sha256(SNAPSHOT / JSONL_NAME), JSONL_SHA256)
        self.assertEqual(
            (ROOT / JSONL_NAME).read_bytes(),
            (SNAPSHOT / JSONL_NAME).read_bytes(),
        )

    def test_all_canonical_rows_ids_fields_and_types_survive(self):
        self.assertEqual(len(self.records), 13_500)
        self.assertEqual([row["id"] for row in self.records], list(range(1, 13_501)))
        self.assertEqual(len({row["id"] for row in self.records}), 13_500)
        self.assertEqual(len({row["text"] for row in self.records}), 324)
        self.assertEqual(
            Counter(row["language"] for row in self.records),
            Counter({"ru": 10_124, "en": 3_376}),
        )
        for row in self.records:
            with self.subTest(record_id=row["id"]):
                self.assertEqual(list(row), FIELDS)
                self.assertIs(type(row["id"]), int)
                self.assertIs(type(row["is_anonymized"]), bool)
                for field in FIELDS:
                    if field not in ("id", "is_anonymized"):
                        self.assertIs(type(row[field]), str, field)

    def assert_csv_matches_canonical(self, name, delimiter):
        with (ROOT / name).open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream, delimiter=delimiter, strict=True)
            self.assertEqual(next(reader), FIELDS)
            rows = list(reader)
        self.assertEqual(len(rows), 13_500)
        self.assertEqual(len(rows), len(self.records))
        for index, (cells, original) in enumerate(zip(rows, self.records), 1):
            with self.subTest(file=name, row=index, record_id=original["id"]):
                self.assertEqual(len(cells), len(FIELDS))
                restored = dict(zip(FIELDS, cells))
                # Check exact ID text before restoring its JSON numeric type.
                self.assertEqual(restored["id"], str(original["id"]))
                self.assertIn(restored["is_anonymized"], ("true", "false", "True", "False"))
                restored["id"] = int(restored["id"])
                restored["is_anonymized"] = restored["is_anonymized"].lower() == "true"
                # Equality checks every field, exact Unicode, blanks and order.
                self.assertEqual(restored, original)

    def test_standard_csv_matches_every_jsonl_record(self):
        self.assert_csv_matches_canonical("privacy_threat_dataset.csv", ",")

    def test_excel_csv_matches_every_jsonl_record(self):
        self.assert_csv_matches_canonical("privacy_threat_dataset_excel.csv", ";")

    def test_export_encoding_contract(self):
        standard = (ROOT / "privacy_threat_dataset.csv").read_bytes()
        excel = (ROOT / "privacy_threat_dataset_excel.csv").read_bytes()
        jsonl = (ROOT / JSONL_NAME).read_bytes()
        self.assertFalse(standard.startswith(codecs.BOM_UTF8))
        self.assertTrue(excel.startswith(codecs.BOM_UTF8))
        self.assertFalse(jsonl.startswith(codecs.BOM_UTF8))
        standard.decode("utf-8", errors="strict")
        excel.decode("utf-8-sig", errors="strict")
        jsonl.decode("utf-8", errors="strict")

    def test_original_48_row_seed_is_unchanged(self):
        self.assertEqual(sha256(ROOT / SEED_NAME), SEED_SHA256)
        self.assertEqual(sha256(SNAPSHOT / SEED_NAME), SEED_SHA256)
        self.assertEqual(
            (ROOT / SEED_NAME).read_bytes(),
            (SNAPSHOT / SEED_NAME).read_bytes(),
        )
        seed = json.loads((ROOT / SEED_NAME).read_text(encoding="utf-8-sig"))
        self.assertEqual(len(seed), 48)
        self.assertEqual([row["id"] for row in seed], list(range(1, 49)))
        self.assertEqual(Counter(row["language"] for row in seed), Counter({"ru": 36, "en": 12}))

    def test_every_original_snapshot_file_matches_manifest(self):
        manifest = json.loads((ROOT / "SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
        expected = manifest["snapshot_files"]
        self.assertEqual(set(expected), SNAPSHOT_NAMES)
        self.assertEqual({path.name for path in SNAPSHOT.iterdir()}, SNAPSHOT_NAMES)
        self.assertEqual(expected[JSONL_NAME], JSONL_SHA256)
        self.assertEqual(expected[SEED_NAME], SEED_SHA256)
        for name, digest in expected.items():
            with self.subTest(file=name):
                self.assertEqual(Path(name).name, name)
                self.assertEqual(sha256(SNAPSHOT / name), digest)

    def test_original_csv_damage_is_preserved_only_in_snapshot(self):
        with (SNAPSHOT / "privacy_threat_dataset.csv").open(
            encoding="utf-8-sig", newline=""
        ) as stream:
            reader = csv.reader(stream, delimiter=",", strict=True)
            self.assertEqual(next(reader), FIELDS)
            widths = Counter(len(row) for row in reader)
        self.assertEqual(widths, Counter({1: 6_473, 12: 7_027}))
        self.assertEqual(sum(widths.values()), 13_500)


if __name__ == "__main__":
    unittest.main()
