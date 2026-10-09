"""Offline deterministic checks for privacy-safe quality reports; no network/I/O writes."""
import copy
import csv
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dataset_utils import SUB_LABELS, TOKENS
from quality_report import (
    FINDING_COLUMNS, FINDING_LIMIT, GROUP_LIMIT, SAMPLE_LIMIT,
    analyze_quality, findings_to_csv, report_to_json,
)


def row(record_id=1, text="Educational sample without identifying content.", **changes):
    record = {"id": record_id, "text": text, "source": "Synthetic classroom exercise",
              "sub_label": "DOXING", "language": "en", "is_anonymized": True,
              **{f"фрагмент_{token}": "" for token in TOKENS}}
    record.update(changes)
    return record


class QualityReportTests(unittest.TestCase):
    def test_normal_record_and_zero_balances(self):
        report = analyze_quality([row()])
        self.assertEqual(report["record_count"], 1)
        self.assertEqual(report["scope"], "full")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["class_balance"], {label: int(label == "DOXING") for label in SUB_LABELS})
        self.assertEqual(report["language_balance"], {"en": 1, "kk": 0, "ru": 0})
        self.assertEqual(report["summary"]["structural_issue_count"], 0)
        self.assertIn("not proof", report["limitations"])
        self.assertNotIn("score", report)
        self.assertNotIn("score", report["summary"])

    def test_empty_dataset_has_zero_counts_and_csv_header(self):
        report = analyze_quality([], scope="filtered")
        self.assertEqual(report["record_count"], 0)
        self.assertEqual(report["scope"], "filtered")
        self.assertTrue(all(value == 0 for value in report["summary"].values()))
        self.assertEqual(report["class_balance"], dict.fromkeys(SUB_LABELS, 0))
        self.assertEqual(report["language_balance"], {"en": 0, "kk": 0, "ru": 0})
        self.assertEqual(findings_to_csv(report).decode("utf-8-sig"), ",".join(FINDING_COLUMNS) + "\n")
        json.loads(report_to_json(report))

    def test_input_validation_has_no_silent_fallback(self):
        for value in (None, {}, "[]", ()):
            with self.subTest(value=value), self.assertRaises(TypeError):
                analyze_quality(value)
        with self.assertRaises(ValueError):
            analyze_quality([], scope="unknown")

    def test_missing_core_and_empty_core_are_distinct(self):
        first = row(); del first["source"]
        second = row(2, " ", language=None, is_anonymized=False)
        report = analyze_quality([first, second])
        self.assertEqual(report["summary"]["missing_core_fields"], 1)
        self.assertEqual(report["summary"]["empty_core_fields"], 2)
        self.assertEqual(report["missing_core_fields"]["source"], 1)
        self.assertEqual(report["empty_core_fields"]["text"], 1)
        self.assertEqual(report["empty_core_fields"]["language"], 1)
        self.assertEqual(report["empty_core_fields"]["is_anonymized"], 0)
        self.assertEqual(report["summary"]["invalid_types"], 1)
        self.assertEqual(report["summary"]["structural_issue_count"], 4)
        self.assertEqual(report["summary"]["structural_issue_rows"], 2)

    def test_empty_or_absent_optional_fragments_are_valid_without_markers(self):
        first = row()
        second = {k: v for k, v in row(2, "Another example.").items() if not k.startswith("фрагмент_")}
        third = row(3, "Third example.", **{"фрагмент_EMAIL": "  "})
        report = analyze_quality([first, second, third])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["missing_core_fields"], 0)

    def test_none_optional_fragment_is_wrong_type(self):
        report = analyze_quality([row(**{"фрагмент_EMAIL": None})])
        self.assertEqual([(f["rule"], f["field"]) for f in report["findings"]], [("invalid_type", "фрагмент_EMAIL")])

    def test_markers_consistent_and_empty_optional_values(self):
        record = row(text="Contact [EMAIL] or [ТЕЛЕФОН].", **{"фрагмент_EMAIL": "[EMAIL]", "фрагмент_ТЕЛЕФОН": "[ТЕЛЕФОН]"})
        self.assertEqual(analyze_quality([record])["findings"], [])

    def test_marker_inconsistencies_have_explicit_rules(self):
        first = row(text="Contact [EMAIL].")
        second = row(2, "Contact [EMAIL]."); del second["фрагмент_EMAIL"]
        third = row(3, "Third example.", **{"фрагмент_EMAIL": "[EMAIL]"})
        fourth = row(4, "Contact [EMAIL].", **{"фрагмент_EMAIL": "incorrect marker"})
        report = analyze_quality([first, second, third, fourth])
        self.assertEqual(report["summary"]["marker_issues"], 4)
        self.assertEqual([f["rule"] for f in report["findings"]], ["marker_fragment_empty", "marker_fragment_missing", "marker_not_in_text", "marker_fragment_value"])
        self.assertNotIn("incorrect marker", report_to_json(report).decode())

    def test_ids_types_unknown_labels_and_language(self):
        records = [row(True), row("1"), row(-2), row(0), row(5, sub_label="PRIVATE_UNKNOWN", language="English", is_anonymized="yes")]
        report = analyze_quality(records)
        self.assertEqual(report["summary"]["invalid_ids"], 4)
        self.assertEqual(report["summary"]["invalid_types"], 3)
        self.assertEqual(report["summary"]["unknown_labels"], 1)
        self.assertEqual(report["summary"]["invalid_languages"], 1)
        self.assertEqual(report["summary"]["unique_valid_ids"], 1)
        self.assertEqual(report["summary"]["unclassified_rows"], 1)
        self.assertNotIn("PRIVATE_UNKNOWN", report_to_json(report).decode())
        self.assertNotIn("English", report_to_json(report).decode().split('"rules"')[0])

    def test_duplicate_ids_do_not_coerce_bool_float_or_string(self):
        report = analyze_quality([row(1), row(1), row(True), row("1"), row(1.0)])
        self.assertEqual(report["summary"]["duplicate_id_groups"], 1)
        self.assertEqual(report["summary"]["duplicate_id_extra_rows"], 1)
        self.assertEqual(report["duplicate_id_groups"], [{"record_id": 1, "count": 2, "row_numbers": [1, 2], "record_ids": [1, 1]}])

    def test_exact_duplicates_and_conflicting_labels(self):
        records = [row(1, "Same"), row(2, "Same", sub_label="DOXING_THREAT"), row(3, "Same"), row(4, "same"), row(5, "Same ")]
        report = analyze_quality(records)
        self.assertEqual(report["summary"]["unique_exact_texts"], 3)
        self.assertEqual(report["summary"]["exact_text_duplicate_groups"], 1)
        self.assertEqual(report["summary"]["exact_text_extra_rows"], 2)
        self.assertEqual(report["summary"]["conflicting_label_groups"], 1)
        self.assertEqual(report["exact_text_duplicate_groups"], [{"count": 3, "row_numbers": [1, 2, 3], "record_ids": [1, 2, 3], "group_id": "text-1"}])
        self.assertEqual(report["conflicting_label_groups"][0]["sub_labels"], ["DOXING", "DOXING_THREAT"])
        self.assertEqual(report["conflicting_label_groups"][0]["distinct_label_count"], 2)
        self.assertEqual(report["findings"], [])  # Repeats are aggregate groups, not thousands of row findings.

    def test_unknown_conflicting_labels_are_counted_and_redacted(self):
        records = [row(1, "Same", sub_label="private-label-one"), row(2, "Same", sub_label="private-label-two")]
        report = analyze_quality(records)
        group = report["conflicting_label_groups"][0]
        self.assertEqual(group["unknown_label_count"], 2)
        self.assertEqual(group["distinct_label_count"], 2)
        self.assertEqual(group["sub_labels"], [])
        self.assertNotIn("private-label", report_to_json(report).decode())

    def test_empty_text_is_not_a_duplicate_text_group(self):
        report = analyze_quality([row(1, ""), row(2, ""), row(3, None), row(4, " ")])
        self.assertEqual(report["summary"]["unique_exact_texts"], 0)
        self.assertEqual(report["summary"]["exact_text_extra_rows"], 0)
        self.assertEqual(report["summary"]["empty_core_fields"], 4)

    def test_additional_valid_language_and_invalid_balance(self):
        report = analyze_quality([row(1, language="fr"), row(2, language=[]), None])
        self.assertEqual(report["language_balance"], {"en": 0, "fr": 1, "kk": 0, "ru": 0})
        self.assertEqual(report["summary"]["invalid_or_missing_language_rows"], 2)
        self.assertEqual(sum(report["class_balance"].values()) + report["summary"]["unclassified_rows"], 3)

    def test_synthetic_pii_format_examples_never_leak_matches(self):
        examples = {
            "possible_email": "Mail alice@training-mail.net",
            "possible_phone": "Call +1 (202) 555-0198",
            "possible_handle": "Message @training_reader",
            "possible_gps": "Coordinates 55.755800, 37.617600",
            "possible_address": "Meet at 123 Practice Street",
        }
        for rule, text in examples.items():
            with self.subTest(rule=rule):
                report = analyze_quality([row(text=text)])
                self.assertEqual(report["summary"]["possible_pii_signals"], 1)
                self.assertEqual(report["summary"]["possible_pii_records"], 1)
                self.assertEqual(report["possible_pii_by_rule"][rule], 1)
                self.assertEqual(report["findings"][0]["rule"], rule)
                self.assertEqual(set(report["findings"][0]), set(FINDING_COLUMNS))
                self.assertNotIn(text, report_to_json(report).decode())
                self.assertNotIn(text, findings_to_csv(report).decode("utf-8-sig"))

    def test_multiple_categories_one_row_and_repeated_matches(self):
        record = row(text="alice@training-mail.net bob@training-mail.net @training_reader +1 202-555-0198")
        report = analyze_quality([record])
        self.assertEqual(report["summary"]["possible_pii_signals"], 3)
        self.assertEqual(report["summary"]["possible_pii_records"], 1)
        self.assertEqual(report["possible_pii_by_rule"]["possible_email"], 1)

    def test_source_and_fragments_are_also_scanned_without_leaking(self):
        record = row(source="alice@training-mail.net", **{"фрагмент_EMAIL": "bob@training-mail.net"})
        report = analyze_quality([record])
        self.assertEqual(report["summary"]["possible_pii_signals"], 2)
        self.assertEqual(report["summary"]["possible_pii_records"], 1)
        self.assertNotIn("training-mail.net", report_to_json(report).decode())

    def test_known_placeholders_and_reserved_examples_are_excluded(self):
        record = row(text="[EMAIL] [ТЕЛЕФОН] @[АККАУНТ] [ГЕОЛОКАЦИЯ] [АДРЕС] [ИМЯ] {PHONE} <EMAIL> @username @handle person@example.com person@sample.test")
        for token in TOKENS:
            record[f"фрагмент_{token}"] = f"[{token}]"
        report = analyze_quality([record])
        self.assertEqual(report["summary"]["possible_pii_signals"], 0)
        self.assertEqual(report["summary"]["marker_issues"], 0)

    def test_unknown_bracket_contents_are_still_scanned(self):
        report = analyze_quality([row(text="[alice@training-mail.net]")])
        self.assertEqual(report["possible_pii_by_rule"]["possible_email"], 1)

    def test_coordinate_ranges_and_no_phone_double_count(self):
        first = analyze_quality([row(text="55.7558, 37.6176")])
        self.assertEqual(first["possible_pii_by_rule"]["possible_gps"], 1)
        self.assertEqual(first["possible_pii_by_rule"]["possible_phone"], 0)
        second = analyze_quality([row(text="91.7558, 181.6176")])
        self.assertEqual(second["possible_pii_by_rule"]["possible_gps"], 0)

    def test_cyrillic_address_hint(self):
        report = analyze_quality([row(text="Учебный пример: ул. Учебная, д. 12")])
        self.assertEqual(report["possible_pii_by_rule"]["possible_address"], 1)

    def test_malformed_rows_and_weird_ids_serialize_strictly(self):
        records = [None, [], 3, "raw row text", row(float("nan")), row(float("inf")), row({}), row([]), row(None), row(2 ** 20000)]
        report = analyze_quality(records)
        self.assertEqual(report["record_count"], 10)
        self.assertEqual(report["summary"]["invalid_rows"], 4)
        self.assertEqual(report["summary"]["invalid_ids"], 5)
        self.assertEqual(report["summary"]["unique_valid_ids"], 1)
        encoded = report_to_json(report)
        self.assertNotIn(b"NaN", encoded)
        self.assertNotIn(b"Infinity", encoded)
        self.assertNotIn(b"raw row text", encoded)
        self.assertTrue(all(f["record_id"] is None for f in report["findings"]))
        json.loads(encoded)
        json.dumps(report, allow_nan=False)

    def test_json_export_explicitly_rejects_nonfinite_values(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                report_to_json({"value": value})

    def test_csv_stable_columns_bom_and_unicode(self):
        report = analyze_quality([row(text="[ИМЯ]")])
        payload = findings_to_csv(report)
        self.assertTrue(payload.startswith(b"\xef\xbb\xbf"))
        reader = csv.DictReader(io.StringIO(payload.decode("utf-8-sig")))
        self.assertEqual(tuple(reader.fieldnames), FINDING_COLUMNS)
        values = list(reader)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["field"], "фрагмент_ИМЯ")
        self.assertEqual(values[0]["record_id"], "1")
        self.assertFalse(report_to_json(report).startswith(b"\xef\xbb\xbf"))

    def test_output_is_deterministic_and_input_is_unchanged(self):
        records = [row(1, "Shared"), row(2, "Shared", sub_label="DOXING_THREAT"), row(3, "[EMAIL]")]
        original = copy.deepcopy(records)
        self.assertEqual(report_to_json(analyze_quality(records)), report_to_json(analyze_quality(records)))
        self.assertEqual(records, original)

    def test_findings_are_bounded_but_all_rows_checked(self):
        records = [row(i + 1, text=f"Sample {i}", source="") for i in range(FINDING_LIMIT + 10)]
        records[-1]["text"] = "Contact alice@training-mail.net"
        report = analyze_quality(records)
        self.assertEqual(report["record_count"], FINDING_LIMIT + 10)
        self.assertEqual(report["summary"]["empty_core_fields"], FINDING_LIMIT + 10)
        self.assertEqual(report["summary"]["possible_pii_records"], 1)
        self.assertEqual(len(report["findings"]), FINDING_LIMIT)
        self.assertEqual(report["sampling"]["findings_omitted"], 11)

    def test_group_lists_and_samples_have_explicit_bounds(self):
        records = [row(1, "Repeated sample") for _ in range(30)]
        report = analyze_quality(records)
        self.assertEqual(report["duplicate_id_groups"][0]["count"], 30)
        self.assertEqual(report["summary"]["duplicate_id_extra_rows"], 29)
        self.assertEqual(report["exact_text_duplicate_groups"][0]["count"], 30)
        self.assertEqual(report["exact_text_duplicate_groups"][0]["row_numbers"], list(range(1, SAMPLE_LIMIT + 1)))
        self.assertEqual(report["sampling"]["group_sample_limit"], SAMPLE_LIMIT)
        many_groups = [row(2 * i + j + 1, f"Repeated example {i}") for i in range(GROUP_LIMIT + 1) for j in range(2)]
        result = analyze_quality(many_groups)
        self.assertEqual(result["summary"]["exact_text_duplicate_groups"], GROUP_LIMIT + 1)
        self.assertEqual(len(result["exact_text_duplicate_groups"]), GROUP_LIMIT)
        self.assertEqual(result["sampling"]["exact_text_duplicate_groups_omitted"], 1)

    def test_all_canonical_rows_and_verified_counts(self):
        # Read data only, never import or execute the archived generator/collector.
        path = ROOT / "privacy_threat_dataset.jsonl"
        data = path.read_bytes()
        records = [json.loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()]
        report = analyze_quality(records)
        self.assertEqual(report["record_count"], 13500)
        expected = {"unique_valid_ids": 13500, "unique_exact_texts": 324, "exact_text_duplicate_groups": 324,
                    "exact_text_extra_rows": 13176, "structural_issue_count": 0, "marker_issues": 0,
                    "possible_pii_signals": 0, "conflicting_label_groups": 0}
        for key, value in expected.items():
            self.assertEqual(report["summary"][key], value, key)
        self.assertEqual(report["language_balance"], {"en": 3376, "kk": 0, "ru": 10124})
        self.assertEqual(sum(report["class_balance"].values()), 13500)
        self.assertEqual(report["class_balance"]["DOXING"], 1692)
        self.assertEqual(report["class_balance"]["PERSONAL_DATA_REQUEST"], 1686)
        self.assertEqual(report["findings"], [])
        self.assertLess(len(report_to_json(report)), 150_000)
        self.assertEqual(path.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
