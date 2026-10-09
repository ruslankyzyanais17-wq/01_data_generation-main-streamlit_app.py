"""Presentation helpers: deterministic paging and contextual record summaries."""
from __future__ import annotations
import math
import pandas as pd


def catalog_view(frame: pd.DataFrame, unique_only: bool = False) -> pd.DataFrame:
    view = frame.copy()
    view['text_repeat_count'] = view.groupby('text', dropna=False)['id'].transform('size')
    return view.drop_duplicates('text', keep='first') if unique_only else view


def page_slice(frame: pd.DataFrame, page: int, size: int):
    if size not in (25, 50, 100):
        raise ValueError('Размер страницы должен быть 25, 50 или 100.')
    pages = max(1, math.ceil(len(frame) / size))
    page = max(1, min(int(page), pages))
    start = (page - 1) * size
    return frame.iloc[start:start + size].copy(), {
        'page': page, 'pages': pages, 'first': start + 1 if len(frame) else 0,
        'last': min(start + size, len(frame)), 'total': len(frame),
    }


def active_filter_labels(query: str, selections: dict, options: dict) -> list[str]:
    labels = []
    if query:
        short = query if len(query) <= 60 else query[:57] + '…'
        labels.append('Поиск: ' + short)
    names = {'filter_languages': 'Языки', 'filter_platforms': 'Платформы',
             'filter_sources': 'Источники', 'filter_labels': 'Подклассы'}
    for key, title in names.items():
        selected, available = selections[key], options[key]
        if set(selected) != set(available):
            labels.append(f'{title}: {len(selected)} из {len(available)}')
    return labels


def record_context(frame: pd.DataFrame, record_id: int) -> dict:
    found = frame.loc[frame['id'].eq(record_id)]
    if found.empty:
        raise KeyError(f'Запись {record_id} не найдена')
    record = found.iloc[0]
    exact = frame.loc[frame['text'].eq(record['text'])]
    base = record['base_example_id']
    template = frame.iloc[:0] if pd.isna(base) else frame.loc[frame['base_example_id'].eq(base).fillna(False)]
    return {
        'id': int(record['id']), 'exact_count': len(exact),
        'exact_ids': exact['id'].astype(int).tolist(),
        'base_example_id': None if pd.isna(base) else int(base),
        'template_count': len(template), 'template_unique_texts': template['text'].nunique(),
        'template_ids': template['id'].astype(int).tolist(),
    }
