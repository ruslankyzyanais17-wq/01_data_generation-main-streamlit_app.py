"""Deterministic, offline, read-only checks for the educational dataset.

This inspector deliberately accepts malformed rows that the strict loader rejects.
No finding or exported group contains source text or a matched PII-like value.
"""
from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from typing import Any

from dataset_utils import BASE_FIELDS, SUB_LABELS, TOKENS

REQUIRED_FIELDS = BASE_FIELDS
FINDING_COLUMNS = ("row_number", "record_id", "rule", "field", "reason")
FINDING_LIMIT = 1000
GROUP_LIMIT = 1000
SAMPLE_LIMIT = 5
KNOWN_LANGUAGES = ("ru", "en", "kk")
PII_FIELDS = ("text", "source", *(f"фрагмент_{token}" for token in TOKENS))
LIMITATION = (
    "Offline structural checks and transparent format heuristics only. A possible-PII "
    "signal is not proof of real private data, identity, sensitivity, or a privacy violation. "
    "Signals may be false positives; undetected data may remain. This report does not "
    "certify anonymization, provenance, consent, dataset independence, or legal compliance. "
    "Duplicates compare exact, non-empty text without normalization. Row numbers are "
    "1-based positions in the inspected input, including a filtered selection."
)
RULES = {
    "required_missing": "A required core field is absent. Optional fragments may be absent when their literal marker is absent.",
    "required_empty": "A present required core field is null or a whitespace-only string; False and zero are not empty.",
    "invalid_row": "A row is not a dictionary; it is counted but cannot be field-checked.",
    "invalid_id": "A present ID must be a positive Python integer; bool is not an integer ID. Invalid IDs are redacted to null in exports.",
    "invalid_type": "Core text fields and present fragment fields must be strings; is_anonymized must be bool; id must be int excluding bool.",
    "unknown_label": "A non-empty string sub_label is not one of the nine documented labels. Unknown values are not copied into the report.",
    "invalid_language": "A non-empty string language is not a lowercase two- or three-letter code.",
    "duplicate_id": "Repeated valid integer IDs are aggregated by ID; extra rows are count minus one per group.",
    "exact_text_duplicate": "Repeated non-empty exact text is aggregated without exposing text; extra rows are count minus one per group.",
    "conflicting_label": "Identical non-empty exact text has two or more distinct non-empty string sub_label values. Unknown label names are redacted.",
    "marker_fragment_missing": "A literal [TOKEN] occurs in text but its optional fragment field is absent.",
    "marker_fragment_empty": "A literal [TOKEN] occurs in text but its fragment field is empty.",
    "marker_not_in_text": "A non-empty fragment is supplied while its corresponding literal [TOKEN] is absent from text.",
    "marker_fragment_value": "A non-empty fragment must equal its corresponding literal [TOKEN] exactly.",
    "possible_email": "Email-shaped string, excluding reserved example.com/example.org/example.net and .example/.invalid/.test domains.",
    "possible_phone": "A phone-shaped run with 10–15 digits, allowing +, spaces, dots, hyphens and parentheses; GPS-coordinate spans are excluded.",
    "possible_handle": "An @handle with 3–32 ASCII letters/digits/underscores, starting with a letter/underscore and outside an email; generic @username/@handle/@account/@placeholder are excluded.",
    "possible_gps": "Comma/semicolon-separated decimal latitude/longitude, at least three fractional digits, within geographic numeric ranges.",
    "possible_address": "An English number plus street-suffix pattern, or a Russian/Kazakh street-keyword phrase with a building-number hint. This is only an address hint.",
}
STRUCTURAL_RULES = ("required_missing", "required_empty", "invalid_row", "invalid_id", "invalid_type", "unknown_label", "invalid_language")
PII_RULES = ("possible_email", "possible_phone", "possible_handle", "possible_gps", "possible_address")
_PLACEHOLDER_NAMES = (*TOKENS, "NAME", "PHONE", "TELEPHONE", "ADDRESS", "ACCOUNT", "HANDLE", "USERNAME", "GPS", "LOCATION", "LATITUDE", "LONGITUDE")
_PLACEHOLDER_RE = re.compile(
    r"(?:\[(?:" + "|".join(_PLACEHOLDER_NAMES) + r")\]|\{(?:" + "|".join(_PLACEHOLDER_NAMES) + r")\}|<(?:" + "|".join(_PLACEHOLDER_NAMES) + r")>)", re.I
)
_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+)(?![\w-])", re.I)
_PHONE_RE = re.compile(r"(?<![\w.])\+?\d(?:[\d ()\-.]{7,}\d)(?![\w.])")
_HANDLE_RE = re.compile(r"(?<![\w@.+-])@([A-Za-z_][A-Za-z0-9_]{2,31})\b")
_GPS_RE = re.compile(r"(?<![\w.])([+-]?\d{1,2}\.\d{3,})\s*[,;]\s*([+-]?\d{1,3}\.\d{3,})(?![\w.])")
_ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+[A-Za-z][A-Za-z .'-]{0,50}\s(?:street|st|road|rd|avenue|ave|lane|ln|drive|dr|boulevard|blvd|way)\b"
    r"|(?:\bулица\b|\bул\.|\bпроспект\b|\bпр-т\b|\bкөше\b|\bкөшесі\b)[^\n;:!?\[\]<>]{0,60}\b\d{1,6}\b",
    re.I,
)


def _is_empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _valid_id(value: Any) -> bool:
    return type(value) is int and value > 0


def _safe_id(value: Any) -> int | None:
    # Exceptionally large integer IDs cannot be encoded by Python's strict JSON
    # encoder under its integer-string limit. They remain valid for grouping.
    return value if _valid_id(value) and value.bit_length() <= 4096 else None


def _pii_signals(text: str) -> list[str]:
    """Return rule names only, never matching strings or spans."""
    cleaned = _PLACEHOLDER_RE.sub(" ", text)
    signals = set()
    for match in _EMAIL_RE.finditer(cleaned):
        domain = match.group(1).casefold()
        if domain not in {"example.com", "example.org", "example.net"} and not domain.endswith((".example", ".invalid", ".test")):
            signals.add("possible_email")
    gps_spans = []
    for match in _GPS_RE.finditer(cleaned):
        if abs(float(match.group(1))) <= 90 and abs(float(match.group(2))) <= 180:
            signals.add("possible_gps")
            gps_spans.append(match.span())
    phone_text = cleaned
    for start, end in reversed(gps_spans):
        phone_text = phone_text[:start] + " " * (end - start) + phone_text[end:]
    if any(10 <= sum(char.isdigit() for char in match.group()) <= 15 for match in _PHONE_RE.finditer(phone_text)):
        signals.add("possible_phone")
    if any(match.group(1).casefold() not in {"username", "handle", "account", "placeholder"} for match in _HANDLE_RE.finditer(cleaned)):
        signals.add("possible_handle")
    if _ADDRESS_RE.search(cleaned):
        signals.add("possible_address")
    return [rule for rule in PII_RULES if rule in signals]


def analyze_quality(records: list[dict], *, scope: str = "full") -> dict:
    """Inspect every supplied row without changing it or performing I/O.

    Counts cover the entire supplied input. Detailed findings and group lists are
    bounded and explicitly marked; each group retains only its first five IDs and
    row numbers. No raw text, unrecognized label, or invalid ID value is exported.
    """
    if not isinstance(records, list):
        raise TypeError("records must be a list")
    if scope not in ("full", "filtered"):
        raise ValueError("scope must be 'full' or 'filtered'")
    counts = Counter()
    field_missing = {field: 0 for field in REQUIRED_FIELDS}
    field_empty = {field: 0 for field in REQUIRED_FIELDS}
    classes = {label: 0 for label in SUB_LABELS}
    languages = {language: 0 for language in KNOWN_LANGUAGES}
    findings = []
    id_groups: dict[int, dict] = {}
    text_groups: dict[str, dict] = {}
    pii_counts = {rule: 0 for rule in PII_RULES}
    pii_rows = set()
    rows_with_findings = set()
    structural_rows = set()

    def finding(row: int, record_id: Any, rule: str, field: str, reason: str) -> None:
        counts[rule] += 1
        rows_with_findings.add(row)
        if rule in STRUCTURAL_RULES:
            structural_rows.add(row)
        if len(findings) < FINDING_LIMIT:
            findings.append(dict(zip(FINDING_COLUMNS, (row, _safe_id(record_id), rule, field, reason))))

    def add_group(groups: dict, key: Any, row: int, record_id: Any) -> dict:
        group = groups.setdefault(key, {"count": 0, "row_numbers": [], "record_ids": []})
        group["count"] += 1
        if len(group["row_numbers"]) < SAMPLE_LIMIT:
            group["row_numbers"].append(row)
            group["record_ids"].append(_safe_id(record_id))
        return group

    for row, record in enumerate(records, 1):
        if not isinstance(record, dict):
            finding(row, None, "invalid_row", "", "Expected a JSON object; field checks skipped.")
            continue
        counts["object_rows"] += 1
        record_id = record.get("id")
        for field in REQUIRED_FIELDS:
            if field not in record:
                field_missing[field] += 1
                finding(row, record_id, "required_missing", field, "Required core field is absent.")
            elif _is_empty(record[field]):
                field_empty[field] += 1
                finding(row, record_id, "required_empty", field, "Required core field is null or an empty string.")
        if "id" in record and not _valid_id(record_id):
            finding(row, record_id, "invalid_id", "id", "Expected a positive integer ID; booleans are not IDs.")
        if _valid_id(record_id):
            add_group(id_groups, record_id, row, record_id)
        typed_fields = ("id", "text", "source", "sub_label", "language", "is_anonymized", *(f"фрагмент_{token}" for token in TOKENS))
        for field in typed_fields:
            if field not in record:
                continue
            value = record[field]
            expected = bool if field == "is_anonymized" else int if field == "id" else str
            valid = type(value) is expected if expected in (bool, int) else isinstance(value, str)
            if not valid:
                finding(row, record_id, "invalid_type", field, f"Expected {expected.__name__}; actual value is omitted.")
        label = record.get("sub_label")
        if isinstance(label, str) and label in classes:
            classes[label] += 1
        else:
            counts["unclassified_rows"] += 1
            if isinstance(label, str) and label.strip():
                finding(row, record_id, "unknown_label", "sub_label", "Value is outside the nine documented labels; value omitted.")
        language = record.get("language")
        if isinstance(language, str) and re.fullmatch(r"[a-z]{2,3}", language):
            languages[language] = languages.get(language, 0) + 1
        else:
            counts["invalid_or_missing_language_rows"] += 1
            if isinstance(language, str) and language.strip():
                finding(row, record_id, "invalid_language", "language", "Expected a lowercase two- or three-letter language code.")
        text = record.get("text")
        if isinstance(text, str):
            if text.strip():
                group = add_group(text_groups, text, row, record_id)
                if isinstance(label, str) and label.strip():
                    group.setdefault("labels", set()).add(label)
            for token in TOKENS:
                literal = f"[{token}]"
                field = f"фрагмент_{token}"
                present = literal in text
                if field not in record:
                    if present:
                        finding(row, record_id, "marker_fragment_missing", field, "Literal marker occurs in text but its fragment field is absent.")
                    continue
                fragment = record[field]
                if not isinstance(fragment, str):
                    continue  # The invalid-type rule covers this field.
                if not fragment.strip():
                    if present:
                        finding(row, record_id, "marker_fragment_empty", field, "Literal marker occurs in text but its fragment field is empty.")
                else:
                    if not present:
                        finding(row, record_id, "marker_not_in_text", field, "Fragment is non-empty but its literal marker is absent from text.")
                    if fragment != literal:
                        finding(row, record_id, "marker_fragment_value", field, "Non-empty fragment differs from its expected literal marker; value omitted.")
        for field in PII_FIELDS:
            value = record.get(field)
            if not isinstance(value, str) or not value:
                continue
            for rule in _pii_signals(value):
                pii_counts[rule] += 1
                pii_rows.add(row)
                finding(row, record_id, rule, field, "Possible PII-shaped content; heuristic only, not verified private data. Matched content omitted.")

    duplicates_id = []
    duplicates_text = []
    conflicts = []
    duplicate_id_total = duplicate_id_extra = duplicate_text_total = duplicate_text_extra = conflicts_total = 0
    for record_id, group in id_groups.items():
        if group["count"] <= 1:
            continue
        duplicate_id_total += 1
        duplicate_id_extra += group["count"] - 1
        if len(duplicates_id) < GROUP_LIMIT:
            duplicates_id.append({"record_id": _safe_id(record_id), **group})
    for group in text_groups.values():
        safe_group = {key: value for key, value in group.items() if key != "labels"}
        safe_group["group_id"] = f"text-{group['row_numbers'][0]}"
        if group["count"] > 1:
            duplicate_text_total += 1
            duplicate_text_extra += group["count"] - 1
            if len(duplicates_text) < GROUP_LIMIT:
                duplicates_text.append(safe_group)
        labels = group.get("labels", set())
        if len(labels) > 1:
            conflicts_total += 1
            if len(conflicts) < GROUP_LIMIT:
                conflicts.append({**safe_group, "sub_labels": [label for label in SUB_LABELS if label in labels],
                                  "unknown_label_count": sum(label not in SUB_LABELS for label in labels),
                                  "distinct_label_count": len(labels)})
    summary = {
        "object_rows": counts["object_rows"], "invalid_rows": counts["invalid_row"],
        "missing_core_fields": sum(field_missing.values()), "empty_core_fields": sum(field_empty.values()),
        "invalid_ids": counts["invalid_id"], "invalid_types": counts["invalid_type"],
        "unknown_labels": counts["unknown_label"], "invalid_languages": counts["invalid_language"],
        "unique_valid_ids": len(id_groups), "unique_exact_texts": len(text_groups),
        "unique_text_count": len(text_groups),
        "structural_issue_count": sum(counts[rule] for rule in STRUCTURAL_RULES),
        "structural_issue_rows": len(structural_rows),
        "duplicate_id_groups": duplicate_id_total, "duplicate_id_extra_rows": duplicate_id_extra,
        "exact_text_duplicate_groups": duplicate_text_total, "exact_text_extra_rows": duplicate_text_extra,
        "conflicting_label_groups": conflicts_total,
        "marker_issues": sum(value for rule, value in counts.items() if rule.startswith("marker_")),
        "possible_pii_signals": sum(pii_counts.values()), "possible_pii_rows": len(pii_rows),
        "possible_pii_records": len(pii_rows),
        "row_level_findings": sum(value for rule, value in counts.items() if rule in RULES),
        "rows_with_row_level_findings": len(rows_with_findings),
        "unclassified_rows": counts["unclassified_rows"] + counts["invalid_row"],
        "invalid_or_missing_language_rows": counts["invalid_or_missing_language_rows"] + counts["invalid_row"],
    }
    return {
        "schema_version": "1.0", "scope": scope, "record_count": len(records), "summary": summary,
        "required_fields": list(REQUIRED_FIELDS), "missing_core_fields": field_missing, "empty_core_fields": field_empty,
        "class_balance": classes, "language_balance": dict(sorted(languages.items())),
        "duplicate_id_groups": duplicates_id, "exact_text_duplicate_groups": duplicates_text,
        "conflicting_label_groups": conflicts, "possible_pii_by_rule": pii_counts,
        "findings": findings, "finding_counts_by_rule": {rule: counts[rule] for rule in RULES if rule not in {"duplicate_id", "exact_text_duplicate", "conflicting_label"}},
        "sampling": {"finding_limit": FINDING_LIMIT, "findings_omitted": max(0, summary["row_level_findings"] - len(findings)),
                     "group_limit_per_kind": GROUP_LIMIT, "group_sample_limit": SAMPLE_LIMIT,
                     "duplicate_id_groups_omitted": max(0, duplicate_id_total - len(duplicates_id)),
                     "exact_text_duplicate_groups_omitted": max(0, duplicate_text_total - len(duplicates_text)),
                     "conflicting_label_groups_omitted": max(0, conflicts_total - len(conflicts)),
                     "description": "All rows are inspected. Group samples contain the first row positions and corresponding IDs in input order. Repeated rows are aggregated, not emitted as per-row findings. CSV contains the bounded row-level findings only; JSON also includes aggregate groups and complete counts."},
        "pii_scan_fields": list(PII_FIELDS),
        "placeholder_policy": "Known [TOKEN], {TOKEN}, and <TOKEN> placeholders are removed before heuristic checks. Other bracketed content is still checked. Reserved illustrative email domains and generic handle placeholders are excluded. Fragment consistency uses case-sensitive literal [TOKEN] presence.",
        "count_definitions": {
            "structural_issue_count": "Sum of required_missing, required_empty, invalid_row, invalid_id, invalid_type, unknown_label and invalid_language rule occurrences. Multiple rules may describe one field/row; this is not a record count.",
            "structural_issue_rows": "Number of distinct input rows with at least one structural rule occurrence. Excludes duplicate groups, marker rules and PII heuristics.",
            "possible_pii_signals": "One occurrence per distinct heuristic category per row per scanned field, not the number of matching strings.",
            "possible_pii_records": "Number of distinct input rows with one or more possible-PII signals; same as possible_pii_rows.",
            "unclassified_rows": "Rows whose label is missing, empty, wrong-type or unknown, including malformed rows.",
            "balance": "Known labels and ru/en/kk are always included with zeros. Other valid language codes are included. Invalid labels/languages are counted separately without copying their raw values.",
            "row_level_findings": "Rule occurrences excluding aggregate duplicate-ID, exact-text duplicate, and label-conflict groups. Counts remain complete when detail is truncated.",
        },
        "rules": dict(RULES), "limitations": LIMITATION,
    }


def report_to_json(report: dict) -> bytes:
    """UTF-8, strict RFC-compatible JSON, with no NaN/Infinity escape hatch."""
    return (json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def findings_to_csv(report: dict) -> bytes:
    """UTF-8 BOM CSV of bounded row-level findings, with stable safe columns."""
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FINDING_COLUMNS, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    for finding in report.get("findings", []):
        writer.writerow({field: finding.get(field) for field in FINDING_COLUMNS})
    return stream.getvalue().encode("utf-8-sig")
