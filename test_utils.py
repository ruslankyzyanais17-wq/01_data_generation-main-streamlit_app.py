"""Offline v2 AppTest regressions for reviewed new modules only.

Real serializers and download-button arguments are captured, not replaced with
fake payloads. Invalid-input fixtures are disposable copies; bundled inputs and
original_snapshot are never modified or executed. AppTest checks Streamlit
state/output, not browser pixels or a browser's download-save dialog.
"""
import codecs
from contextlib import contextmanager
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import streamlit as st
from streamlit.delta_generator import DeltaGenerator
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import dataset_utils
import quality_report

INPUT_HASHES = {
    'privacy_threat_dataset.jsonl': 'b7b3ba360ee348d373f54a9ec324346de4b5e3d70c5e1d6f22d23eb8d7754e97',
    'dataset_source.json': 'e49521a585124d27f85d062fd4b21959f6a5609b6203ddbec8db29dbb08a63e6',
    'privacy_threat_dataset.csv': 'e88589d0668c0e04afa509b1940a605419bfd66a46d4d2c39bce2d7523d09f10',
    'privacy_threat_dataset_excel.csv': 'fbc21cc838b11c0cb9f7bf8c79b7b53789cd49703d84963e64912b85b2937cda',
}
TIMEOUT = 30


def input_hashes(root=ROOT):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in INPUT_HASHES}


@contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


@contextmanager
def capture_payloads():
    """Retain real export bytes and what the UI actually passes for download."""
    captured = {'dataset_calls': [], 'quality_json_calls': [], 'quality_csv_calls': [], 'downloads': {}}
    original_export = dataset_utils.export_frame
    original_json = quality_report.report_to_json
    original_csv = quality_report.findings_to_csv
    original_download = DeltaGenerator.download_button
    original_top_download = st.download_button

    def export(frame, format_name, *, include_derived=False):
        result = original_export(frame, format_name, include_derived=include_derived)
        captured['dataset_calls'].append((format_name, include_derived, len(frame), result))
        return result

    def quality_json(report):
        result = original_json(report)
        captured['quality_json_calls'].append((report, result))
        return result

    def quality_csv(report):
        result = original_csv(report)
        captured['quality_csv_calls'].append((report, result))
        return result

    def download(self, label, data, *args, **kwargs):
        captured['downloads'][kwargs.get('key')] = {'label': label, 'data': data, **kwargs}
        return original_download(self, label, data, *args, **kwargs)

    def top_download(label, data, *args, **kwargs):
        captured['downloads'][kwargs.get('key')] = {'label': label, 'data': data, **kwargs}
        return original_top_download(label, data, *args, **kwargs)

    with patch.object(st, 'download_button', new=top_download), \
         patch.object(dataset_utils, 'export_frame', side_effect=export), \
         patch.object(quality_report, 'report_to_json', side_effect=quality_json), \
         patch.object(quality_report, 'findings_to_csv', side_effect=quality_csv), \
         patch.object(DeltaGenerator, 'download_button', new=download):
        yield captured


class AppRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = dataset_utils.read_jsonl(ROOT / 'privacy_threat_dataset.jsonl')
        cls.seed = dataset_utils.read_seed(ROOT / 'dataset_source.json')
        cls.frame = dataset_utils.enrich_records(cls.records, cls.seed)
        cls.manifest_hash = hashlib.sha256((ROOT / 'SOURCE_MANIFEST.json').read_bytes()).hexdigest()
        if input_hashes() != INPUT_HASHES:
            raise AssertionError('Canonical input SHA-256 differs before UI testing')

    def tearDown(self):
        self.assertEqual(input_hashes(), INPUT_HASHES, 'Application interaction changed an input file')
        self.assertEqual(hashlib.sha256((ROOT / 'SOURCE_MANIFEST.json').read_bytes()).hexdigest(), self.manifest_hash)

    def assert_clean(self, at):
        self.assertEqual([item.message for item in at.exception], [])

    def app(self, path=None, section=None):
        at = AppTest.from_file(str(path or ROOT / 'app.py'), default_timeout=TIMEOUT).run()
        self.assert_clean(at)
        if section:
            at.radio(key='navigation').set_value(section).run()
            self.assert_clean(at)
        return at

    def metrics(self, at):
        return {item.label: item.value for item in at.metric}

    def captions(self, at):
        return '\n'.join(item.value for item in at.caption)

    def texts(self, at):
        return '\n'.join(item.value for item in at.text)

    def assert_catalog_ids(self, at, expected, *, page=1, size=25, unique=False):
        self.assert_clean(at)
        expected_rows = self.frame.loc[self.frame['id'].isin(expected)]
        if unique:
            expected_rows = expected_rows.drop_duplicates('text')
        total = len(expected_rows)
        pages = max(1, math.ceil(total / size))
        page = max(1, min(page, pages))
        expected_page = expected_rows.iloc[(page - 1) * size:page * size]['id'].tolist()
        self.assertIn(f'Найдено {len(expected):,} из 13,500 записей', self.captions(at))
        self.assertEqual(at.number_input(key='page_number').value, page)
        self.assertEqual(at.number_input(key='page_number').max, pages)
        self.assertIn(f'из {total:,} · страница {page} / {pages}', self.captions(at))
        if expected_page:
            self.assertEqual(at.dataframe[0].value['id'].tolist(), expected_page)
            self.assertIn(at.selectbox(key='record_id').value, expected_page)
        else:
            self.assertEqual(len(at.dataframe), 0)
            self.assertTrue(at.number_input(key='page_number').disabled)
            self.assertTrue(any('нет записей' in item.value for item in at.info))
        return expected_page

    def test_overview_counts_and_navigation_round_trip(self):
        at = self.app()
        self.assertEqual(self.metrics(at), {'Записей в выборке': '13500', 'Уникальных текстов': '324',
                         'Повторных строк': '13176', 'Базовых примеров': '48'})
        self.assertEqual(at.radio(key='navigation').options, ['Обзор', 'Каталог', 'Качество'])
        self.assertEqual(at.multiselect(key='filter_languages').value, ['en', 'ru'])
        self.assertEqual(len(at.multiselect(key='filter_sources').value), 48)
        self.assertEqual(len(at.multiselect(key='filter_platforms').value), 15)
        at.button(key='open_catalog').click().run()
        self.assertEqual(at.radio(key='navigation').value, 'Каталог')
        self.assert_catalog_ids(at, list(range(1, 13_501)))
        for section in ('Качество', 'Обзор', 'Каталог', 'Качество', 'Обзор'):
            at.radio(key='navigation').set_value(section).run()
            self.assert_clean(at)
            self.assertEqual(at.radio(key='navigation').value, section)
        self.assertEqual(self.metrics(at)['Записей в выборке'], '13500')

    def test_catalog_navigation_remembers_page_record_and_export_preferences(self):
        at = self.app(section='Каталог')
        at.selectbox(key='page_size').set_value(50)
        at.toggle(key='unique_texts_only').set_value(True)
        at.radio(key='export_scope').set_value('Весь набор')
        at.checkbox(key='include_derived').set_value(True).run()
        at.number_input(key='page_number').set_value(3).run()
        chosen = int(at.dataframe[0].value['id'].iloc[-1])
        at.selectbox(key='record_id').set_value(chosen).run()
        before_ids = at.dataframe[0].value['id'].tolist()
        for section in ('Качество', 'Обзор', 'Качество'):
            at.radio(key='navigation').set_value(section).run()
            self.assert_clean(at)
            at.radio(key='navigation').set_value('Каталог').run()
            self.assert_clean(at)
            self.assertEqual(at.number_input(key='page_number').value, 3)
            self.assertEqual(at.selectbox(key='record_id').value, chosen)
            self.assertEqual(at.dataframe[0].value['id'].tolist(), before_ids)
            self.assertEqual(at.selectbox(key='page_size').value, 50)
            self.assertTrue(at.toggle(key='unique_texts_only').value)
            self.assertEqual(at.radio(key='export_scope').value, 'Весь набор')
            self.assertTrue(at.checkbox(key='include_derived').value)
        at.radio(key='navigation').set_value('Качество').run()
        at.multiselect(key='filter_languages').set_value(['en']).run()
        at.radio(key='navigation').set_value('Каталог').run()
        expected = [row['id'] for row in self.records if row['language'] == 'en']
        self.assert_catalog_ids(at, expected, size=50, unique=True)
        at.number_input(key='page_number').set_value(2).run()
        at.radio(key='navigation').set_value('Обзор').run()
        at.button(key='reset_filters').click().run()
        at.radio(key='navigation').set_value('Каталог').run()
        self.assert_catalog_ids(at, list(range(1, 13_501)), size=50, unique=True)

    def test_all_page_sizes_first_second_last_and_stale_page_clamp(self):
        at = self.app(section='Каталог')
        expected = list(range(1, 13_501))
        for size in (25, 50, 100):
            with self.subTest(size=size):
                at.selectbox(key='page_size').set_value(size).run()
                self.assert_catalog_ids(at, expected, size=size)
                at.number_input(key='page_number').set_value(2).run()
                self.assert_catalog_ids(at, expected, size=size, page=2)
                pages = math.ceil(len(expected) / size)
                at.number_input(key='page_number').set_value(pages).run()
                self.assert_catalog_ids(at, expected, size=size, page=pages)

    def test_reload_smaller_dataset_clamps_last_page_without_mutating_inputs(self):
        at = self.app(section='Каталог')
        try:
            for size in (25, 50, 100):
                at.selectbox(key='page_size').set_value(size).run()
                at.number_input(key='page_number').set_value(math.ceil(13_500 / size)).run()
                # Simulate a newly read smaller dataset, without rewriting any file.
                with patch.object(dataset_utils, 'read_jsonl', return_value=self.records[:1_000]):
                    at.button(key='reload_data').click().run()
                self.assert_clean(at)
                pages = math.ceil(1_000 / size)
                self.assertEqual(at.number_input(key='page_number').value, pages)
                self.assertEqual(at.number_input(key='page_number').max, pages)
                self.assertEqual(at.dataframe[0].value['id'].tolist(), list(range(1_001 - size, 1_001)))
                self.assertEqual(at.selectbox(key='record_id').value, 1_001 - size)
                self.assertIn('Найдено 1,000 из 1,000', self.captions(at))
                at.button(key='reload_data').click().run()
                self.assert_clean(at)
        finally:
            at.button(key='reload_data').click().run()

    def test_unique_listing_has_324_texts_and_last_partial_page(self):
        at = self.app(section='Каталог')
        at.toggle(key='unique_texts_only').set_value(True).run()
        expected = list(range(1, 13_501))
        self.assert_catalog_ids(at, expected, unique=True)
        counts = self.frame['text'].value_counts()
        shown = at.dataframe[0].value
        self.assertEqual(shown['text_repeat_count'].tolist(), shown['text'].map(counts).tolist())
        for size, last_rows in ((25, 24), (50, 24), (100, 24)):
            at.selectbox(key='page_size').set_value(size).run()
            pages = math.ceil(324 / size)
            at.number_input(key='page_number').set_value(pages).run()
            self.assert_catalog_ids(at, expected, unique=True, size=size, page=pages)
            self.assertEqual(len(at.dataframe[0].value), last_rows)
        at.toggle(key='unique_texts_only').set_value(False).run()
        self.assert_catalog_ids(at, expected, size=100)

    def test_record_card_full_values_context_group_and_json_download(self):
        at = self.app(section='Каталог')
        for chosen in (1, 25, 26, 13_500):
            with self.subTest(record=chosen):
                at.number_input(key='page_number').set_value(math.ceil(chosen / 25)).run()
                at.selectbox(key='record_id').set_value(chosen)
                with capture_payloads() as captured:
                    at.run()
                self.assert_clean(at)
                row = self.records[chosen - 1]
                enriched = self.frame.iloc[chosen - 1]
                self.assertIn(row['text'], [item.value for item in at.text])
                self.assertIn(row['source'], [item.value for item in at.text])
                self.assertIn(row['sub_label'], self.captions(at))
                self.assertIn('is_anonymized: true', self.captions(at))
                template = self.frame.loc[self.frame['base_example_id'].eq(enriched['base_example_id'])]
                self.assertEqual(at.dataframe[1].value['id'].tolist(), template['id'].head(10).tolist())
                markdown = '\n'.join(item.value for item in at.markdown)
                self.assertIn(f"Точных совпадений текста во всём наборе: {(self.frame['text'] == row['text']).sum()}", markdown)
                self.assertIn(f"Базовый пример #{enriched['base_example_id']}: {len(template)} записей", markdown)
                download = captured['downloads']['download_record']
                self.assertEqual(download['file_name'], f'privacy_record_{chosen}.json')
                self.assertEqual(download['mime'], 'application/json')
                self.assertEqual(json.loads(download['data']), row)
                self.assertEqual(list(json.loads(download['data'])), list(dataset_utils.FIELDS))
                single_calls = [call for call in captured['dataset_calls'] if call[0] == 'jsonl' and call[2] == 1]
                self.assertEqual(json.loads(single_calls[0][3]), row)

    def test_stale_record_selection_is_replaced_after_page_filter_and_empty(self):
        at = self.app(section='Каталог')
        at.selectbox(key='record_id').set_value(25).run()
        at.number_input(key='page_number').set_value(2).run()
        self.assertEqual(at.selectbox(key='record_id').value, 26)
        at.selectbox(key='record_id').set_value(50).run()
        at.multiselect(key='filter_languages').set_value(['en']).run()
        expected = [r['id'] for r in self.records if r['language'] == 'en']
        page_ids = self.assert_catalog_ids(at, expected)
        self.assertEqual(at.selectbox(key='record_id').value, page_ids[0])
        at.text_input(key='search_query').set_value('absent-unique-sentinel-9471').run()
        self.assert_catalog_ids(at, [])
        self.assertEqual(len(at.selectbox), 1)  # Page-size only; no stale record card.
        at.button(key='empty_reset').click().run()
        self.assert_catalog_ids(at, list(range(1, 13_501)))
        self.assertIn(at.selectbox(key='record_id').value, list(range(1, 26)))

    def test_literal_search_order_and_repeated_page_reset(self):
        at = self.app(section='Каталог')
        for query in ('[', '[ИМЯ]', '(', '.', 'a|b', '\\', 'номер', 'НОМЕР', ''):
            with self.subTest(query=query):
                if at.number_input(key='page_number').max > 1:
                    at.number_input(key='page_number').set_value(2).run()
                at.text_input(key='search_query').set_value(query).run()
                expected = [row['id'] for row in self.records if query.casefold() in row['text'].casefold()]
                self.assert_catalog_ids(at, expected)
                if query:
                    self.assertIn('Поиск: ' + query, self.texts(at))

    def test_all_empty_filters_reload_and_both_reset_routes(self):
        at = self.app(section='Каталог')
        for index, key in enumerate(('filter_languages', 'filter_platforms', 'filter_sources', 'filter_labels')):
            with self.subTest(key=key):
                at.number_input(key='page_number').set_value(2).run()
                at.multiselect(key=key).set_value([]).run()
                self.assert_catalog_ids(at, [])
                with capture_payloads() as captured:
                    at.button(key='reload_data').click().run()
                self.assertEqual(at.multiselect(key=key).value, [])
                self.assert_catalog_ids(at, [])
                self.assertEqual(captured['downloads']['download_jsonl']['data'], b'')
                for kind, delimiter in (('csv', ','), ('excel', ';')):
                    payload = captured['downloads']['download_' + kind]['data']
                    reader = csv.DictReader(io.StringIO(payload.decode('utf-8-sig')), delimiter=delimiter)
                    self.assertEqual(reader.fieldnames, list(dataset_utils.FIELDS))
                    self.assertEqual(list(reader), [])
                at.button(key='reset_filters' if index % 2 else 'empty_reset').click().run()
                self.assert_catalog_ids(at, list(range(1, 13_501)))
                self.assertEqual(at.text_input(key='search_query').value, '')
                self.assertFalse('Активные фильтры:' in self.texts(at))

    def test_language_platform_source_label_and_search_intersect(self):
        at = self.app(section='Каталог')
        sources = [self.records[0]['source'], self.records[13]['source']]
        at.multiselect(key='filter_languages').set_value(['ru'])
        at.multiselect(key='filter_platforms').set_value(['Telegram'])
        at.multiselect(key='filter_sources').set_value(sources)
        at.multiselect(key='filter_labels').set_value(['DOXING'])
        at.text_input(key='search_query').set_value('[ИМЯ]').run()
        expected = [row['id'] for row in self.records if row['language'] == 'ru' and row['source'] in sources
                    and row['source'].startswith('Telegram (') and row['sub_label'] == 'DOXING'
                    and '[имя]' in row['text'].casefold()]
        self.assertGreater(len(expected), 0)
        self.assert_catalog_ids(at, expected)
        local = self.frame.loc[self.frame['id'].isin(expected)]
        shown = at.dataframe[0].value
        self.assertEqual(shown['text_repeat_count'].tolist(), shown['text'].map(local['text'].value_counts()).tolist())
        at.multiselect(key='filter_platforms').set_value(['Reddit']).run()
        self.assert_catalog_ids(at, [])

    def test_reload_preserves_filters_page_selection_and_export_preferences(self):
        at = self.app(section='Каталог')
        at.text_input(key='search_query').set_value('[ИМЯ]')
        at.multiselect(key='filter_languages').set_value(['ru'])
        at.multiselect(key='filter_platforms').set_value(['Telegram'])
        at.multiselect(key='filter_sources').set_value([self.records[0]['source']])
        at.multiselect(key='filter_labels').set_value(['DOXING'])
        at.radio(key='export_scope').set_value('Весь набор')
        at.checkbox(key='include_derived').set_value(True).run()
        at.number_input(key='page_number').set_value(2).run()
        last_id = at.dataframe[0].value['id'].iloc[-1]
        at.selectbox(key='record_id').set_value(int(last_id)).run()
        before_ids = at.dataframe[0].value['id'].tolist()
        before_values = {item.key: item.value for item in at.multiselect}
        for _ in range(2):
            at.button(key='reload_data').click().run()
            self.assert_clean(at)
            self.assertEqual(at.dataframe[0].value['id'].tolist(), before_ids)
            self.assertEqual({item.key: item.value for item in at.multiselect}, before_values)
            self.assertEqual(at.number_input(key='page_number').value, 2)
            self.assertEqual(at.selectbox(key='record_id').value, last_id)
            self.assertEqual(at.text_input(key='search_query').value, '[ИМЯ]')
            self.assertEqual(at.radio(key='export_scope').value, 'Весь набор')
            self.assertTrue(at.checkbox(key='include_derived').value)

    def test_real_full_filtered_exports_keep_duplicates_and_optional_fields(self):
        at = self.app(section='Каталог')
        at.multiselect(key='filter_languages').set_value(['en'])
        at.toggle(key='unique_texts_only').set_value(True).run()
        for scope, derived in (('Отфильтрованные записи', False), ('Весь набор', False),
                               ('Весь набор', True), ('Отфильтрованные записи', True)):
            with self.subTest(scope=scope, derived=derived):
                at.radio(key='export_scope').set_value(scope)
                at.checkbox(key='include_derived').set_value(derived)
                with capture_payloads() as captured:
                    at.run()
                self.assert_clean(at)
                expected = self.records if scope == 'Весь набор' else [r for r in self.records if r['language'] == 'en']
                expected_fields = list(dataset_utils.FIELDS) + (list(dataset_utils.DERIVED_FIELDS) if derived else [])
                json_payload = captured['downloads']['download_jsonl']['data']
                json_rows = [json.loads(line) for line in json_payload.decode('utf-8').splitlines()]
                self.assertEqual(len(json_rows), len(expected))
                self.assertGreater(len(json_rows), len({r['text'] for r in json_rows}))
                self.assertIn(json_payload, [call[3] for call in captured['dataset_calls'] if call[:3] == ('jsonl', derived, len(expected))])
                for actual, original in zip(json_rows, expected):
                    self.assertEqual(list(actual), expected_fields)
                    self.assertEqual({key: actual[key] for key in dataset_utils.FIELDS}, original)
                    if derived:
                        enriched = self.frame.iloc[original['id'] - 1]
                        self.assertEqual(actual['platform'], enriched['platform'])
                        self.assertEqual(actual['base_example_id'], int(enriched['base_example_id']))
                        self.assertEqual(actual['origin_status'], 'template_match')
                for kind, delimiter in (('csv', ','), ('excel', ';')):
                    download = captured['downloads']['download_' + kind]
                    payload = download['data']
                    self.assertIn(payload, [call[3] for call in captured['dataset_calls'] if call[:3] == (kind, derived, len(expected))])
                    self.assertEqual(payload.startswith(codecs.BOM_UTF8), kind == 'excel')
                    reader = csv.DictReader(io.StringIO(payload.decode('utf-8-sig'), newline=''), delimiter=delimiter)
                    csv_rows = list(reader)
                    self.assertEqual(reader.fieldnames, expected_fields)
                    self.assertEqual(len(csv_rows), len(expected))
                    for actual, original in zip(csv_rows, expected):
                        self.assertNotIn(None, actual)
                        for field in dataset_utils.FIELDS:
                            self.assertEqual(actual[field], str(original[field]))
                self.assertEqual(len(at.get('download_button')), 4)

    def test_quality_full_filtered_empty_reports_and_real_export_bytes(self):
        at = self.app(section='Качество')
        at.multiselect(key='filter_languages').set_value(['en']).run()
        for scope, empty in (('Весь набор', False), ('Текущая выборка', False),
                             ('Текущая выборка', True), ('Весь набор', True)):
            with self.subTest(scope=scope, empty=empty):
                at.radio(key='quality_scope').set_value(scope)
                at.text_input(key='search_query').set_value('absent-unique-sentinel-9471' if empty else '')
                with capture_payloads() as captured:
                    at.run()
                self.assert_clean(at)
                expected = self.records if scope == 'Весь набор' else ([] if empty else [r for r in self.records if r['language'] == 'en'])
                report = json.loads(captured['downloads']['quality_json']['data'])
                expected_report = quality_report.analyze_quality(expected, scope='full' if scope == 'Весь набор' else 'filtered')
                self.assertEqual(report, expected_report)
                self.assertEqual(captured['downloads']['quality_json']['data'], captured['quality_json_calls'][0][1])
                self.assertEqual(captured['downloads']['quality_csv']['data'], captured['quality_csv_calls'][0][1])
                self.assertIn(f"Проверено {len(expected):,} записей", self.captions(at))
                self.assertEqual(self.metrics(at)['Повторных строк'], str(report['summary']['exact_text_extra_rows']))
                csv_payload = captured['downloads']['quality_csv']['data']
                self.assertTrue(csv_payload.startswith(codecs.BOM_UTF8))
                reader = csv.DictReader(io.StringIO(csv_payload.decode('utf-8-sig')))
                self.assertEqual(reader.fieldnames, list(quality_report.FINDING_COLUMNS))
                self.assertEqual(len(list(reader)), len(report['findings']))
                self.assertEqual(len(at.get('download_button')), 2)
                self.assertTrue(any('эвристики' in item.value for item in at.warning))

    def test_quality_finding_filter_resets_when_scope_removes_selected_rule(self):
        # Synthetic test strings only; no private user data or collection.
        base = {**self.records[0], 'source': 'Synthetic classroom fixture',
                **{f'фрагмент_{token}': '' for token in dataset_utils.TOKENS}}
        rows = [{**base, 'id': 1, 'language': 'en', 'text': 'Sample @fixture_handle_7426'},
                {**base, 'id': 2, 'language': 'ru', 'text': 'Sample coordinates 51.5007, -0.1246'},
                {**base, 'id': 3, 'language': 'ru', 'text': 'No signal in this synthetic sample'}]
        content = ('\n'.join(json.dumps(row, ensure_ascii=False) for row in rows)).encode('utf-8')
        with self.isolated_app(content) as path:
            at = self.app(path, section='Качество')
            self.assertEqual(set(at.selectbox(key='finding_rule').options),
                             {'Все правила', 'possible_handle', 'possible_gps'})
            at.selectbox(key='finding_rule').set_value('possible_handle').run()
            self.assertEqual(at.dataframe[0].value.columns.tolist(), ['Строка', 'ID', 'Правило', 'Поле', 'Причина'])
            self.assertEqual(at.dataframe[0].value['Правило'].tolist(), ['possible_handle'])
            at.radio(key='quality_scope').set_value('Текущая выборка')
            at.multiselect(key='filter_languages').set_value(['ru'])
            with capture_payloads() as captured:
                at.run()
            self.assert_clean(at)
            self.assertEqual(at.selectbox(key='finding_rule').value, 'Все правила')
            self.assertEqual(at.dataframe[0].value['Правило'].tolist(), ['possible_gps'])
            report = json.loads(captured['downloads']['quality_json']['data'])
            self.assertEqual(report, quality_report.analyze_quality(rows[1:], scope='filtered'))
            self.assertEqual(report['findings'][0]['row_number'], 1)
            for key in ('quality_json', 'quality_csv'):
                payload = captured['downloads'][key]['data'].decode('utf-8-sig')
                self.assertNotIn('@fixture_handle_7426', payload)
                self.assertNotIn('51.5007', payload)
            at.text_input(key='search_query').set_value('No signal').run()
            self.assert_clean(at)
            self.assertEqual(len(at.selectbox), 0)
            at.button(key='reset_filters').click().run()
            self.assert_clean(at)
            self.assertEqual(at.selectbox(key='finding_rule').value, 'Все правила')

    def test_filters_persist_across_navigation_and_overview_empty_reset(self):
        at = self.app(section='Каталог')
        at.multiselect(key='filter_languages').set_value(['en']).run()
        for section in ('Качество', 'Обзор', 'Каталог', 'Обзор'):
            at.radio(key='navigation').set_value(section).run()
            self.assert_clean(at)
            self.assertEqual(at.multiselect(key='filter_languages').value, ['en'])
            self.assertIn('Найдено 3,376 из 13,500', self.captions(at))
        at.multiselect(key='filter_languages').set_value([]).run()
        self.assertEqual(self.metrics(at)['Записей в выборке'], '0')
        at.button(key='empty_reset').click().run()
        self.assertEqual(self.metrics(at)['Записей в выборке'], '13500')

    @contextmanager
    def isolated_app(self, data_bytes, seed_bytes=None):
        with tempfile.TemporaryDirectory(prefix='privacy_v2_invalid_') as folder:
            isolated = Path(folder)
            for name in ('app.py', 'dataset_utils.py', 'product_utils.py', 'quality_report.py', 'dataset_source.json'):
                (isolated / name).write_bytes((ROOT / name).read_bytes())
            if data_bytes is not None:
                (isolated / 'privacy_threat_dataset.jsonl').write_bytes(data_bytes)
            if seed_bytes is not None:
                (isolated / 'dataset_source.json').write_bytes(seed_bytes)
            (isolated / 'privacy_threat_dataset.csv').write_text('id,text\n1,fallback\n', encoding='utf-8')
            before = {p.name: p.read_bytes() for p in isolated.iterdir() if p.is_file()}
            yield isolated / 'app.py'
            after = {p.name: p.read_bytes() for p in isolated.iterdir() if p.is_file()}
            self.assertEqual(after, before, 'Failure handling rewrote or created an input')

    def test_missing_corrupt_jsonl_stops_without_fallback_or_download(self):
        for name, content in (('missing', None), ('invalid_json', b'{"id":'),
                              ('invalid_utf8', b'\xff\xfe\xfa'), ('valid_then_invalid', json.dumps(self.records[0]).encode() + b'\n{')):
            with self.subTest(fixture=name), self.isolated_app(content) as path:
                with capture_payloads() as captured:
                    at = self.app(path)
                self.assertTrue(any('Не удалось загрузить данные' in item.value for item in at.error))
                self.assertTrue(any('не заменяет полный набор' in item.value for item in at.info))
                self.assertEqual(len(at.metric), 0)
                self.assertEqual(len(at.dataframe), 0)
                self.assertEqual(len(at.radio), 0)
                self.assertEqual(captured['downloads'], {})
                self.assertEqual(captured['dataset_calls'], [])

    def test_schema_errors_and_empty_input_offer_truthful_diagnostics_only(self):
        fixtures = ([{'id': 1}], [1, None, []], [],
                    [{**self.records[0], 'id': True, 'sub_label': 'unknown'}],
                    [self.records[0], self.records[0]])
        for records in fixtures:
            content = ('\n'.join(json.dumps(row, ensure_ascii=False) for row in records)).encode('utf-8')
            with self.subTest(records=len(records)), self.isolated_app(content) as path:
                with capture_payloads() as captured:
                    at = self.app(path)
                self.assertTrue(any('Не удалось загрузить данные' in item.value for item in at.error))
                self.assertEqual(len(at.metric), 0)
                self.assertEqual(len(at.dataframe), 0)
                self.assertEqual(set(captured['downloads']), {'invalid_quality_json'})
                report = json.loads(captured['downloads']['invalid_quality_json']['data'])
                self.assertEqual(report, quality_report.analyze_quality(records))
                self.assertEqual(report['record_count'], len(records))
                self.assertEqual(captured['dataset_calls'], [])

    def test_corrupt_seed_has_no_fallback_and_preserves_jsonl_diagnostics(self):
        content = (json.dumps(self.records[0], ensure_ascii=False) + '\n').encode('utf-8')
        with self.isolated_app(content, b'broken seed') as path:
            with capture_payloads() as captured:
                at = self.app(path)
            self.assertTrue(at.error)
            self.assertEqual(len(at.metric), 0)
            self.assertEqual(set(captured['downloads']), {'invalid_quality_json'})
            self.assertEqual(json.loads(captured['downloads']['invalid_quality_json']['data'])['record_count'], 1)

    def test_launch_from_alternate_cwd_ignores_conflicting_inputs(self):
        with tempfile.TemporaryDirectory(prefix='privacy_v2_cwd_') as folder:
            unrelated = Path(folder)
            (unrelated / 'privacy_threat_dataset.jsonl').write_text('not valid JSON', encoding='utf-8')
            (unrelated / 'dataset_source.json').write_text('[]', encoding='utf-8')
            with working_directory(unrelated):
                at = self.app()
                self.assertEqual(self.metrics(at)['Записей в выборке'], '13500')
                at.radio(key='navigation').set_value('Каталог').run()
                self.assert_catalog_ids(at, list(range(1, 13_501)))
                at.button(key='reload_data').click().run()
                self.assert_catalog_ids(at, list(range(1, 13_501)))
            self.assertEqual((unrelated / 'privacy_threat_dataset.jsonl').read_text(), 'not valid JSON')


if __name__ == '__main__':
    unittest.main()
