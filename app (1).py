"""Read-only unit coverage for v2 catalog helpers; never imports legacy code."""
import copy
from pathlib import Path
import sys
import unittest

import pandas as pd
from pandas.testing import assert_frame_equal

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dataset_utils import enrich_records, read_jsonl, read_seed
from product_utils import active_filter_labels, catalog_view, page_slice, record_context


class ProductHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frame = enrich_records(read_jsonl(ROOT / 'privacy_threat_dataset.jsonl'),
                                   read_seed(ROOT / 'dataset_source.json'))

    def test_full_and_unique_views_preserve_order_and_input(self):
        before = self.frame.copy(deep=True)
        all_rows = catalog_view(self.frame)
        unique_rows = catalog_view(self.frame, True)
        self.assertEqual(len(all_rows), 13_500)
        self.assertEqual(len(unique_rows), 324)
        self.assertEqual(unique_rows['id'].tolist(), self.frame.drop_duplicates('text')['id'].tolist())
        counts = self.frame['text'].value_counts()
        self.assertEqual(all_rows['text_repeat_count'].tolist(), all_rows['text'].map(counts).tolist())
        self.assertEqual(unique_rows['text_repeat_count'].sum(), 13_500)
        assert_frame_equal(self.frame, before)
        all_rows.loc[all_rows.index[0], 'text'] = 'changed copy'
        assert_frame_equal(self.frame, before)

    def test_repeat_counts_are_local_to_filtered_selection(self):
        selected = self.frame.iloc[:200]
        result = catalog_view(selected, True)
        self.assertEqual(result['text_repeat_count'].sum(), 200)
        self.assertEqual(result['text'].tolist(), selected['text'].drop_duplicates().tolist())
        self.assertTrue((result['text_repeat_count'] <= result['text'].map(self.frame['text'].value_counts())).all())

    def test_empty_catalog_and_pages(self):
        result = catalog_view(self.frame.iloc[:0], True)
        self.assertTrue(result.empty)
        self.assertIn('text_repeat_count', result)
        for size in (25, 50, 100):
            page, meta = page_slice(result, 999, size)
            self.assertTrue(page.empty)
            self.assertEqual(meta, {'page': 1, 'pages': 1, 'first': 0, 'last': 0, 'total': 0})

    def test_pagination_sizes_first_middle_last_and_clamps(self):
        frame = self.frame.iloc[:263].copy()
        before = frame.copy(deep=True)
        for size in (25, 50, 100):
            pages = (len(frame) + size - 1) // size
            for requested, expected in ((-1, 1), (0, 1), (1, 1), (2, 2), (pages, pages), (999, pages)):
                with self.subTest(size=size, page=requested):
                    result, meta = page_slice(frame, requested, size)
                    start = (expected - 1) * size
                    assert_frame_equal(result, frame.iloc[start:start + size])
                    self.assertEqual(meta, {'page': expected, 'pages': pages, 'first': start + 1,
                                           'last': min(start + size, len(frame)), 'total': 263})
        assert_frame_equal(frame, before)

    def test_page_slice_uses_position_with_noncontiguous_index(self):
        frame = self.frame.iloc[::17]
        result, meta = page_slice(frame, 2, 25)
        self.assertEqual(result.index.tolist(), frame.index[25:50].tolist())
        result.iloc[0, 0] = -1
        self.assertGreater(frame.iloc[25]['id'], 0)
        self.assertEqual(meta['first'], 26)

    def test_unsupported_page_size_fails_explicitly(self):
        for size in (0, 1, 24, 26, 200, '25', None):
            with self.subTest(size=size), self.assertRaises(ValueError):
                page_slice(self.frame, 1, size)

    def test_record_context_uses_complete_template_and_exact_groups(self):
        before = self.frame.copy(deep=True)
        for chosen in (1, 25, 324, 13_500):
            row = self.frame.loc[self.frame['id'].eq(chosen)].iloc[0]
            exact = self.frame.loc[self.frame['text'].eq(row['text'])]
            template = self.frame.loc[self.frame['base_example_id'].eq(row['base_example_id'])]
            self.assertEqual(record_context(self.frame, chosen), {
                'id': chosen, 'exact_count': len(exact), 'exact_ids': exact['id'].tolist(),
                'base_example_id': int(row['base_example_id']), 'template_count': len(template),
                'template_unique_texts': template['text'].nunique(), 'template_ids': template['id'].tolist(),
            })
        assert_frame_equal(self.frame, before)

    def test_record_context_missing_and_unverified(self):
        with self.assertRaises(KeyError):
            record_context(self.frame, -999)
        frame = pd.DataFrame({'id': [1, 2, 3], 'text': ['Same', 'Same', 'Other'],
                              'base_example_id': pd.array([None, 1, 1], dtype='Int64')})
        self.assertEqual(record_context(frame, 1), {'id': 1, 'exact_count': 2, 'exact_ids': [1, 2],
                         'base_example_id': None, 'template_count': 0, 'template_unique_texts': 0, 'template_ids': []})

    def test_active_filters_no_constraints_and_all_four_intersections(self):
        options = {'filter_languages': ['en', 'ru'], 'filter_platforms': ['Telegram', 'Reddit'],
                   'filter_sources': ['one', 'two'], 'filter_labels': ['DOXING', 'DOXING_THREAT']}
        before = copy.deepcopy(options)
        self.assertEqual(active_filter_labels('', options, options), [])
        reordered = {key: list(reversed(values)) for key, values in options.items()}
        self.assertEqual(active_filter_labels('', reordered, options), [])
        selected = {key: values[:1] for key, values in options.items()}
        selected['filter_languages'] = []
        self.assertEqual(active_filter_labels('[ИМЯ]', selected, options), [
            'Поиск: [ИМЯ]', 'Языки: 0 из 2', 'Платформы: 1 из 2', 'Источники: 1 из 2', 'Подклассы: 1 из 2'])
        self.assertEqual(options, before)

    def test_active_query_display_truncation_does_not_mutate_search(self):
        options = {key: [] for key in ('filter_languages', 'filter_platforms', 'filter_sources', 'filter_labels')}
        query = 'я' * 61
        self.assertEqual(active_filter_labels(query, options, options), ['Поиск: ' + 'я' * 57 + '…'])
        self.assertEqual(active_filter_labels('x' * 60, options, options), ['Поиск: ' + 'x' * 60])
        self.assertEqual(query, 'я' * 61)


if __name__ == '__main__':
    unittest.main()
