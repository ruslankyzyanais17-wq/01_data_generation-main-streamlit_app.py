"""Offline export of existing JSONL; never generate or collect new examples."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import pandas as pd
from dataset_utils import DatasetError, export_frame, read_jsonl

ROOT = Path(__file__).resolve().parent

def export_dataset(source: Path, output_dir: Path) -> int:
    records = read_jsonl(source)
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"Папка уже существует: {output_dir}. Выберите новую папку; перезапись запрещена.")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    frame = pd.DataFrame(records)
    stage = Path(tempfile.mkdtemp(prefix=".privacy-export-", dir=output_dir.parent))
    try:
        for name, kind in (("privacy_threat_dataset.csv", "csv"),
                           ("privacy_threat_dataset_excel.csv", "excel"),
                           ("privacy_threat_dataset.jsonl", "jsonl")):
            (stage / name).write_bytes(export_frame(frame, kind))
        (stage / "EXPORT_INFO.json").write_text(json.dumps({
            "source": source.name, "rows": len(records),
            "operation": "Offline serialization only. No records generated or collected."
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # Check again before publication; the source and existing directories are untouched.
        if output_dir.exists():
            raise FileExistsError(f"Папка уже существует: {output_dir}")
        stage.rename(output_dir)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return len(records)

def main(argv=None):
    parser = argparse.ArgumentParser(description="Сохранить существующие JSONL-записи в новую папку без сбора и размножения.")
    parser.add_argument("--source", type=Path, default=ROOT / "privacy_threat_dataset.jsonl")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "exports")
    args = parser.parse_args(argv)
    try:
        count = export_dataset(args.source, args.output_dir)
    except (OSError, DatasetError) as exc:
        parser.exit(1, f"Ошибка: {exc}\n")
    print(f"Экспортировано {count} существующих записей в {args.output_dir.resolve()}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
