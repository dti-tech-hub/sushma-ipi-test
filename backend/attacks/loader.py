"""Corpus loading and validation (Module 2 / Module 24).

Both corpora are JSON on disk and validated against Pydantic schemas on load, so
a malformed record fails fast with a typed :class:`CorpusError` instead of
crashing mid-experiment.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from backend.attacks.models import AttackCorpus, AttackRecord
from backend.models.enums import AttackType, DeliveryChannel, Difficulty, Severity
from backend.models.errors import (
    AttackNotFoundError,
    CorpusError,
    DuplicateRecordError,
    TaskNotFoundError,
)
from backend.models.tasks import TaskCorpus, TaskDefinition
from backend.services.config import Settings, get_settings


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CorpusError(f"Corpus file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CorpusError(f"Malformed JSON in {path}: {exc}") from exc


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------


class AttackRepository:
    """Loads, validates and indexes the attack corpus."""

    def __init__(self, records: Iterable[AttackRecord], corpus_version: str = "1.0.0") -> None:
        self._records: dict[str, AttackRecord] = {}
        for record in records:
            if record.id in self._records:
                raise DuplicateRecordError(
                    f"Duplicate attack id {record.id!r}",
                    details={"attack_id": record.id},
                )
            self._records[record.id] = record
        self.corpus_version = corpus_version

    # -- loading ----------------------------------------------------------
    @classmethod
    def from_directory(cls, directory: Path) -> "AttackRepository":
        if not directory.exists():
            raise CorpusError(f"Attack corpus directory not found: {directory}")
        files = sorted(directory.glob("*.json"))
        if not files:
            raise CorpusError(f"No attack corpus files (*.json) in {directory}")
        records: list[AttackRecord] = []
        version = "1.0.0"
        for path in files:
            try:
                corpus = AttackCorpus.model_validate(_read_json(path))
            except CorpusError:
                raise
            except Exception as exc:
                raise CorpusError(
                    f"Attack corpus {path.name} failed validation", details={"error": str(exc)}
                ) from exc
            records.extend(corpus.attacks)
            version = corpus.corpus_version
        return cls(records, version)

    # -- access -----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self._records.values())

    def all(self) -> list[AttackRecord]:
        return list(self._records.values())

    def get(self, attack_id: str) -> AttackRecord:
        try:
            return self._records[attack_id]
        except KeyError as exc:
            raise AttackNotFoundError(
                f"Unknown attack id {attack_id!r}",
                details={"available_sample": sorted(self._records)[:10], "total": len(self._records)},
            ) from exc

    def by_type(self, attack_type: AttackType | str) -> list[AttackRecord]:
        wanted = AttackType.coerce(attack_type)
        return [r for r in self._records.values() if r.attack_type == wanted]

    def by_channel(self, channel: DeliveryChannel | str) -> list[AttackRecord]:
        wanted = DeliveryChannel.coerce(channel)
        return [r for r in self._records.values() if r.delivery_channel == wanted]

    def by_severity(self, severity: Severity | str) -> list[AttackRecord]:
        wanted = Severity.coerce(severity)
        return [r for r in self._records.values() if r.severity == wanted]

    def by_difficulty(self, difficulty: Difficulty | str) -> list[AttackRecord]:
        wanted = Difficulty.coerce(difficulty)
        return [r for r in self._records.values() if r.difficulty == wanted]

    def select(
        self,
        *,
        attack_ids: list[str] | None = None,
        attack_types: list[str] | None = None,
        severities: list[str] | None = None,
        difficulties: list[str] | None = None,
        delivery_channels: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> list[AttackRecord]:
        """Filter the corpus; every supplied filter is AND-combined."""
        records = list(self._records.values())
        if attack_ids:
            wanted_ids = set(attack_ids)
            missing = wanted_ids - set(self._records)
            if missing:
                raise AttackNotFoundError(
                    f"Unknown attack id(s): {sorted(missing)}", details={"missing": sorted(missing)}
                )
            records = [r for r in records if r.id in wanted_ids]
        if attack_types:
            wanted_types = {AttackType.coerce(t) for t in attack_types}
            records = [r for r in records if r.attack_type in wanted_types]
        if severities:
            wanted_sev = {Severity.coerce(s) for s in severities}
            records = [r for r in records if r.severity in wanted_sev]
        if difficulties:
            wanted_diff = {Difficulty.coerce(d) for d in difficulties}
            records = [r for r in records if r.difficulty in wanted_diff]
        if delivery_channels:
            wanted_channels = {DeliveryChannel.coerce(c) for c in delivery_channels}
            records = [r for r in records if r.delivery_channel in wanted_channels]
        if tags:
            wanted_tags = set(tags)
            records = [r for r in records if wanted_tags & set(r.tags)]
        return records

    def stats(self) -> dict[str, Any]:
        def tally(key) -> dict[str, int]:
            out: dict[str, int] = {}
            for record in self._records.values():
                value = getattr(record, key).value
                out[value] = out.get(value, 0) + 1
            return dict(sorted(out.items()))

        return {
            "total": len(self._records),
            "corpus_version": self.corpus_version,
            "by_attack_type": tally("attack_type"),
            "by_delivery_channel": tally("delivery_channel"),
            "by_severity": tally("severity"),
            "by_difficulty": tally("difficulty"),
            "by_injection_position": tally("injection_position"),
            "by_format": tally("format"),
            "unique_target_actions": len({r.target_action.key for r in self._records.values()}),
        }


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


class TaskRepository:
    """Loads and indexes the synthetic task corpus."""

    def __init__(self, records: Iterable[TaskDefinition], corpus_version: str = "1.0.0") -> None:
        self._records: dict[str, TaskDefinition] = {}
        for record in records:
            if record.task_id in self._records:
                raise DuplicateRecordError(f"Duplicate task id {record.task_id!r}")
            self._records[record.task_id] = record
        self.corpus_version = corpus_version

    @classmethod
    def from_file(cls, path: Path) -> "TaskRepository":
        try:
            corpus = TaskCorpus.model_validate(_read_json(path))
        except CorpusError:
            raise
        except Exception as exc:
            raise CorpusError(
                f"Task corpus {path} failed validation", details={"error": str(exc)}
            ) from exc
        return cls(corpus.tasks, corpus.corpus_version)

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self._records.values())

    def all(self) -> list[TaskDefinition]:
        return list(self._records.values())

    def get(self, task_id: str) -> TaskDefinition:
        try:
            return self._records[task_id]
        except KeyError as exc:
            raise TaskNotFoundError(
                f"Unknown task id {task_id!r}",
                details={"available": sorted(self._records)},
            ) from exc

    def select(self, task_ids: list[str] | None = None, tags: list[str] | None = None) -> list[TaskDefinition]:
        records = list(self._records.values())
        if task_ids:
            wanted = set(task_ids)
            missing = wanted - set(self._records)
            if missing:
                raise TaskNotFoundError(
                    f"Unknown task id(s): {sorted(missing)}", details={"missing": sorted(missing)}
                )
            records = [r for r in records if r.task_id in wanted]
        if tags:
            wanted_tags = set(tags)
            records = [r for r in records if wanted_tags & set(r.tags)]
        return records

    def supporting(self, attack: AttackRecord) -> list[TaskDefinition]:
        """Tasks this attack can be delivered into (channel match + explicit list)."""
        if attack.compatible_tasks:
            return [self.get(tid) for tid in attack.compatible_tasks if tid in self._records]
        matching = [
            t for t in self._records.values()
            if attack.delivery_channel in [c.value for c in t.channels]
            and any(c.value for c in t.channels)
        ]
        return matching or list(self._records.values())


# ---------------------------------------------------------------------------
# Cached accessors
# ---------------------------------------------------------------------------


def get_attacks(settings: Settings | None = None) -> AttackRepository:
    settings = settings or get_settings()
    return _cached_attacks(str(settings.attacks_dir))


@lru_cache(maxsize=8)
def _cached_attacks(directory: str) -> AttackRepository:
    return AttackRepository.from_directory(Path(directory))


def get_tasks(settings: Settings | None = None) -> TaskRepository:
    settings = settings or get_settings()
    return _cached_tasks(str(settings.tasks_dir / "tasks.json"))


@lru_cache(maxsize=8)
def _cached_tasks(path: str) -> TaskRepository:
    return TaskRepository.from_file(Path(path))


def clear_caches() -> None:
    _cached_attacks.cache_clear()
    _cached_tasks.cache_clear()


__all__ = [
    "AttackRepository",
    "TaskRepository",
    "get_attacks",
    "get_tasks",
    "clear_caches",
]