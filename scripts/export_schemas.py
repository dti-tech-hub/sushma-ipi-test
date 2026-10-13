"""Emit JSON Schema (draft 2020-12) files for the on-disk corpora.

Run:  python -m scripts.export_schemas
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.attacks.models import AttackCorpus, AttackRecord  # noqa: E402
from backend.models.tasks import TaskCorpus, TaskDefinition  # noqa: E402
from backend.services.config import PROJECT_ROOT  # noqa: E402


def main() -> int:
    out_dir = PROJECT_ROOT / "corpus" / "schemas"
    out_dir.mkdir(parents=True, exist_ok=True)

    schemas = {
        "attack.schema.json": AttackRecord.model_json_schema(),
        "attack_corpus.schema.json": AttackCorpus.model_json_schema(),
        "task.schema.json": TaskDefinition.model_json_schema(),
        "task_corpus.schema.json": TaskCorpus.model_json_schema(),
    }
    for filename, schema in schemas.items():
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            **schema,
        }
        (out_dir / filename).write_text(
            json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"wrote corpus/schemas/{filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())