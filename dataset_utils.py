"""Offline helpers. Never perform network access or writes on import."""
from __future__ import annotations
import json
import re
from pathlib import Path
import pandas as pd

SUB_LABELS = ("DOXING", "DOXING_THREAT", "PHONE_DISCLOSURE", "ADDRESS_DISCLOSURE",
              "LOCATION_DISCLOSURE", "IDENTITY_DISCLOSURE", "PRIVATE_MESSAGE_LEAK",
              "INTIMATE_CONTENT_LEAK", "PERSONAL_DATA_REQUEST")
TOKENS = ("ИМЯ", "ТЕЛЕФОН", "АДРЕС", "EMAIL", "АККАУНТ", "ГЕОЛОКАЦИЯ")
BASE_FIELDS = ("id", "sub_label", "source", "text", "language", "is_anonymized")
FIELDS = ("id", "sub_label", "source", "text", *(f"фрагмент_{t}" for t in TOKENS),
          "language", "is_anonymized")
DERIVED_FIELDS = ("platform", "base_example_id", "origin_status")
# Exact prefixes in the original repository's augmentation scripts.
PREFIXES = {
    "ru": ("", "Срочно в сеть: ", "Внимание: ", "Очередной слив данных: ",
           "Найдено в открытом доступе: ", "Опубликовано анонимно: ", "Проверено по базам: "),
    "kk": ("", "Шұғыл ақпарат: ", "Баршаның назарына: ", "Желіге тараған мәлімет: ",
           "Анонимді түрде жарияланды: ", "Тексерілген дерек: ", "Чаттардан алынған ақпарат: "),
    "en": ("", "Urgent leak: ", "Attention: ", "Exposed publicly: ", "Fresh data dump: ", "OSINT alert: "),
}

class DatasetError(ValueError):
    """Invalid data must never be silently replaced."""

def validate_records(records: list[dict], *, require_fragments: bool = True) -> None:
    if not isinstance(records, list) or not records:
        raise DatasetError("Датасет пуст или не является списком записей.")
    seen = set()
    required = FIELDS if require_fragments else BASE_FIELDS
    for position, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise DatasetError(f"Запись {position}: ожидается объект JSON.")
        missing = set(required) - record.keys()
        if missing:
            raise DatasetError(f"Запись {position}: отсутствуют поля {', '.join(sorted(missing))}.")
        if type(record["id"]) is not int or record["id"] < 1 or record["id"] in seen:
            raise DatasetError(f"Запись {position}: id должен быть уникальным положительным целым.")
        seen.add(record["id"])
        for field in ("text", "source", "language", "sub_label"):
            if not isinstance(record[field], str) or not record[field].strip():
                raise DatasetError(f"Запись {position}: поле {field} пустое или не строка.")
        if record["sub_label"] not in SUB_LABELS:
            raise DatasetError(f"Запись {position}: неизвестный sub_label {record['sub_label']}.")
        if not re.fullmatch(r"[a-z]{2,3}", record["language"]):
            raise DatasetError(f"Запись {position}: language должен быть кодом языка, например ru.")
        if type(record["is_anonymized"]) is not bool:
            raise DatasetError(f"Запись {position}: is_anonymized должен быть true или false.")
        if require_fragments:
            for token in TOKENS:
                if not isinstance(record[f"фрагмент_{token}"], str):
                    raise DatasetError(f"Запись {position}: фрагмент_{token} должен быть строкой.")

def read_jsonl(path: str | Path) -> list[dict]:
    """Read canonical records, with no fallback to the 48-row seed."""
    records = []
    try:
        with Path(path).open(encoding="utf-8-sig") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise DatasetError(f"JSONL, строка {number}: некорректный JSON.") from exc
    except UnicodeError as exc:
        raise DatasetError("Файл должен быть в кодировке UTF-8.") from exc
    validate_records(records)
    return records

def read_seed(path: str | Path) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DatasetError("dataset_source.json повреждён или не в UTF-8.") from exc
    validate_records(data, require_fragments=False)
    return data

def platform_from_source(source: str) -> str:
    """One group per row; mixed descriptions remain mixed, aliases are merged."""
    head = str(source).split("(", 1)[0].strip()
    aliases = {"telegram": "Telegram", "вконтакте": "ВКонтакте", "vk": "ВКонтакте",
        "whatsapp": "WhatsApp", "reddit": "Reddit", "discord": "Discord",
        "x": "X / Twitter", "twitter": "X / Twitter", "instagram": "Instagram",
        "threads": "Threads", "tiktok": "TikTok", "twitch": "Twitch", "kick": "Kick",
        "linkedin": "LinkedIn", "4chan": "4chan", "хабр": "Хабр",
        "raidforums": "RaidForums", "breachforums": "BreachForums"}
    groups = set()
    for part in head.split("/"):
        part = part.strip().casefold()
        if part:
            groups.add(aliases.get(part, "Форумы" if "форум" in part or "борд" in part else "Не определена"))
    if not groups:
        return "Не определена"
    ordered = sorted(groups)
    return ordered[0] if len(ordered) == 1 else "Несколько платформ: " + " + ".join(ordered)

def provenance_lookup(seed: list[dict]) -> dict[tuple, set[int]]:
    lookup = {}
    for record in seed:
        for prefix in PREFIXES.get(record["language"], ("",)):
            key = (prefix + record["text"], record["source"], record["sub_label"], record["language"])
            lookup.setdefault(key, set()).add(record["id"])
    return lookup

def enrich_records(records: list[dict], seed: list[dict]) -> pd.DataFrame:
    """Preserve original values and derive exact template matches, not real provenance."""
    lookup = provenance_lookup(seed)
    enriched = []
    for record in records:
        collisions = set(DERIVED_FIELDS) & record.keys()
        if collisions:
            raise DatasetError("Производные поля уже присутствуют: " + ", ".join(sorted(collisions)))
        ids = lookup.get(tuple(record[k] for k in ("text", "source", "sub_label", "language")), set())
        enriched.append({**record, "platform": platform_from_source(record["source"]),
            "base_example_id": next(iter(ids)) if len(ids) == 1 else None,
            "origin_status": "template_match" if len(ids) == 1 else "unverified"})
    df = pd.DataFrame(enriched)
    df["base_example_id"] = pd.array(df["base_example_id"], dtype="Int64")
    return df

def filter_data(df: pd.DataFrame, *, languages=None, platforms=None, sources=None,
                sub_labels=None, query: str = "") -> pd.DataFrame:
    """None means unrestricted; [] deliberately selects zero rows."""
    mask = pd.Series(True, index=df.index)
    for field, values in (("language", languages), ("platform", platforms),
                           ("source", sources), ("sub_label", sub_labels)):
        if values is not None:
            mask &= df[field].isin(values)
    if query:
        mask &= df["text"].fillna("").astype(str).str.contains(query, case=False, regex=False, na=False)
    return df.loc[mask].copy()

def language_summary(df: pd.DataFrame) -> str:
    codes = sorted({str(x).strip() for x in df["language"].dropna() if str(x).strip()})
    return f"{len(codes)} ({', '.join(codes)})" if codes else "0"

def export_frame(df: pd.DataFrame, format_name: str, *, include_derived: bool = False) -> bytes:
    frame = df if include_derived else df.drop(columns=list(DERIVED_FIELDS), errors="ignore")
    if format_name == "jsonl":
        return frame.to_json(orient="records", lines=True, force_ascii=False).encode("utf-8") if len(frame) else b""
    if format_name not in ("csv", "excel"):
        raise ValueError("Unknown export format")
    text = frame.to_csv(index=False, sep=";" if format_name == "excel" else ",", lineterminator="\n")
    return text.encode("utf-8-sig" if format_name == "excel" else "utf-8")
