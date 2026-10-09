"""Offline regressions for the updated code only."""
import copy
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dataset_utils import (DatasetError, DERIVED_FIELDS, enrich_records, export_frame,
                           filter_data, language_summary, platform_from_source,
                           read_jsonl, read_seed, validate_records)
from generate_dataset import export_dataset


class DataHelpersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = read_jsonl(ROOT / 'privacy_threat_dataset.jsonl')
        cls.seed = read_seed(ROOT / 'dataset_source.json')
        cls.frame = enrich_records(cls.records, cls.seed)

    def test_languages_use_observed_data(self):
        self.assertEqual(language_summary(self.frame), '2 (en, ru)')
        self.assertEqual(language_summary(pd.DataFrame({'language': ['kk', 'ru', None, '']})), '2 (kk, ru)')
        self.assertEqual(language_summary(self.frame.iloc[:0]), '0')

    def test_all_rows_match_known_templates(self):
        self.assertEqual(set(self.frame.origin_status), {'template_match'})
        self.assertEqual(self.frame.base_example_id.nunique(), 48)
        self.assertEqual(self.frame.text.nunique(), 324)
        self.assertEqual(self.frame.drop(columns=list(DERIVED_FIELDS)).to_dict('records'), self.records)

    def test_unknown_provenance_is_not_invented(self):
        changed = copy.deepcopy(self.records[:1])
        changed[0]['text'] = 'Новая учебная запись без совпадения'
        frame = enrich_records(changed, self.seed)
        self.assertEqual(frame.iloc[0].origin_status, 'unverified')
        self.assertTrue(pd.isna(frame.iloc[0].base_example_id))

    def test_ambiguous_template_is_unverified(self):
        seed = copy.deepcopy(self.seed)
        twin = copy.deepcopy(seed[0]); twin['id'] = 999
        seed.append(twin)
        frame = enrich_records(self.records[:1], seed)
        self.assertEqual(frame.iloc[0].origin_status, 'unverified')

    def test_no_derived_field_collision(self):
        changed = copy.deepcopy(self.records[:1]); changed[0]['platform'] = 'user value'
        with self.assertRaises(DatasetError):
            enrich_records(changed, self.seed)

    def test_platform_normalization_and_mixed_grouping(self):
        self.assertEqual(platform_from_source('Telegram (городские чаты)'), 'Telegram')
        self.assertEqual(platform_from_source('X / Twitter (live tracking)'), 'X / Twitter')
        self.assertEqual(platform_from_source('Twitter / Reddit (leaked DMs)'),
                         'Несколько платформ: Reddit + X / Twitter')
        self.assertEqual(platform_from_source('Reddit (r/OSINT / forums)'), 'Reddit')
        self.assertEqual(platform_from_source('unknown service'), 'Не определена')
        self.assertEqual(int(self.frame.platform.value_counts().sum()), 13500)
        self.assertEqual(self.frame.platform.nunique(), 15)

    def test_literal_metacharacter_search(self):
        for query in ['[ИМЯ]', '[EMAIL]', '[', '(', '.', '+', 'a|b', '\\', 'СЛИВ', 'dOx', 'қазақ']:
            with self.subTest(query=query):
                result = filter_data(self.frame, query=query)
                expected = [r['id'] for r in self.records if query.casefold() in r['text'].casefold()]
                self.assertEqual(result.id.tolist(), expected)

    def test_null_text_search_is_safe(self):
        frame = self.frame.iloc[:2].copy(); frame.loc[frame.index[0], 'text'] = None
        self.assertEqual(filter_data(frame, query='[ИМЯ]').id.tolist(), [2])

    def test_empty_selection_means_no_rows(self):
        for name in ['languages', 'platforms', 'sources', 'sub_labels']:
            with self.subTest(dimension=name):
                self.assertTrue(filter_data(self.frame, **{name: []}).empty)
        self.assertEqual(len(filter_data(self.frame)), 13500)

    def test_filter_intersection_and_original_order(self):
        result = filter_data(self.frame, languages=['ru'], platforms=['Telegram'],
                             sub_labels=['DOXING'], query='[ИМЯ]')
        expected = self.frame[(self.frame.language == 'ru') & (self.frame.platform == 'Telegram') &
                              (self.frame.sub_label == 'DOXING')]
        self.assertEqual(result.id.tolist(), expected.id.tolist())

    def test_full_and_filtered_jsonl_export_preserves_original_values(self):
        for frame in (self.frame, filter_data(self.frame, languages=['en'])):
            payload = export_frame(frame, 'jsonl')
            self.assertFalse(payload.startswith(b'\xef\xbb\xbf'))
            parsed = [json.loads(line) for line in payload.decode('utf-8').splitlines()]
            wanted = frame.drop(columns=list(DERIVED_FIELDS)).to_dict('records')
            self.assertEqual(parsed, wanted)
        self.assertEqual(export_frame(self.frame.iloc[:0], 'jsonl'), b'')

    def test_csv_encodings_quoting_and_unicode_roundtrip(self):
        value = 'Казахша: Әңгімені тексеру; "цитата", перенос\n[ИМЯ] + =SUM(1,2)'
        frame = pd.DataFrame([{'id': '001', 'text': value, 'is_anonymized': False}])
        for kind, delimiter, encoding in [('csv', ',', 'utf-8'), ('excel', ';', 'utf-8-sig')]:
            payload = export_frame(frame, kind)
            self.assertEqual(payload.startswith(b'\xef\xbb\xbf'), kind == 'excel')
            parsed = list(csv.DictReader(io.StringIO(payload.decode(encoding)), delimiter=delimiter))
            self.assertEqual(parsed, [{'id': '001', 'text': value, 'is_anonymized': 'False'}])

    def test_optional_derived_fields_and_empty_header(self):
        parsed = json.loads(export_frame(self.frame.iloc[:1], 'jsonl', include_derived=True))
        self.assertTrue(set(DERIVED_FIELDS).issubset(parsed))
        self.assertEqual(parsed['base_example_id'], 1)
        for kind in ['csv', 'excel']:
            text = export_frame(self.frame.iloc[:0], kind).decode('utf-8-sig')
            self.assertEqual(len(text.splitlines()), 1)
            self.assertTrue(text.startswith('id'))

    def test_validation_rejects_bad_types_missing_fields_and_duplicate_ids(self):
        for field, value in [('id', True), ('id', '1'), ('id', -1), ('language', ''),
                             ('text', None), ('sub_label', 'UNKNOWN'), ('is_anonymized', 'true')]:
            with self.subTest(field=field, value=value):
                data = copy.deepcopy(self.records[:1]); data[0][field] = value
                with self.assertRaises(DatasetError): validate_records(data)
        with self.assertRaises(DatasetError): validate_records([])
        with self.assertRaises(DatasetError): validate_records([self.records[0], self.records[0]])
        with self.assertRaises(DatasetError): validate_records([{'id': 1}])

    def test_invalid_jsonl_fails_with_line_number(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'bad.jsonl'; path.write_text('{\n', encoding='utf-8')
            with self.assertRaisesRegex(DatasetError, 'строка 1'): read_jsonl(path)

    def test_offline_export_uses_new_directory_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'new_export'
            source = ROOT / 'privacy_threat_dataset.jsonl'
            before = source.read_bytes()
            self.assertEqual(export_dataset(source, out), 13500)
            self.assertEqual(read_jsonl(out / 'privacy_threat_dataset.jsonl'), self.records)
            with self.assertRaises(FileExistsError): export_dataset(source, out)
            self.assertEqual(source.read_bytes(), before)

    def test_failed_serialization_leaves_no_output_or_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'new_export'
            with patch('generate_dataset.export_frame', side_effect=OSError('simulated write failure')):
                with self.assertRaises(OSError):
                    export_dataset(ROOT / 'privacy_threat_dataset.jsonl', out)
            self.assertFalse(out.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
