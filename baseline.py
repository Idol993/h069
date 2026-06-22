import json
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class BaselineEntry:
    fingerprint: str
    rule_id: str
    file_path: str
    line_number: int
    secret_value_masked: str
    first_seen_commit: str
    first_seen_author: str
    first_seen_date: str
    last_seen_commit: str = ""
    last_seen_author: str = ""
    last_seen_date: str = ""
    status: str = "existing"
    resolved_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class Baseline:
    def __init__(self, baseline_path: Optional[str] = None):
        self.baseline_path = Path(baseline_path) if baseline_path else None
        self.entries: Dict[str, BaselineEntry] = {}
        if self.baseline_path and self.baseline_path.exists():
            self.load()

    @staticmethod
    def compute_fingerprint(secret_value: str, file_path: str, rule_id: str) -> str:
        data = f"{secret_value}|{file_path}|{rule_id}"
        return hashlib.sha256(data.encode()).hexdigest()

    def load(self):
        if not self.baseline_path or not self.baseline_path.exists():
            return
        with open(self.baseline_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        entries_data = data.get("entries", [])
        for entry_data in entries_data:
            entry = BaselineEntry(**entry_data)
            self.entries[entry.fingerprint] = entry

    def save(self, output_path: Optional[str] = None):
        path = Path(output_path) if output_path else self.baseline_path
        if not path:
            raise ValueError("No baseline path specified")
        data = {
            "version": "1.0",
            "generated_at": datetime.now().isoformat(),
            "total_entries": len(self.entries),
            "entries": [entry.to_dict() for entry in self.entries.values()],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def add_entry(
        self,
        secret_value: str,
        file_path: str,
        rule_id: str,
        line_number: int,
        masked_value: str,
        commit_sha: str,
        author: str,
        date: str,
    ) -> BaselineEntry:
        fingerprint = self.compute_fingerprint(secret_value, file_path, rule_id)
        entry = BaselineEntry(
            fingerprint=fingerprint,
            rule_id=rule_id,
            file_path=file_path,
            line_number=line_number,
            secret_value_masked=masked_value,
            first_seen_commit=commit_sha,
            first_seen_author=author,
            first_seen_date=date,
            last_seen_commit=commit_sha,
            last_seen_author=author,
            last_seen_date=date,
        )
        self.entries[fingerprint] = entry
        return entry

    def update_entry_seen(
        self,
        secret_value: str,
        file_path: str,
        rule_id: str,
        commit_sha: str,
        author: str,
        date: str,
    ) -> Optional[BaselineEntry]:
        fingerprint = self.compute_fingerprint(secret_value, file_path, rule_id)
        entry = self.entries.get(fingerprint)
        if entry:
            entry.last_seen_commit = commit_sha
            entry.last_seen_author = author
            entry.last_seen_date = date
            entry.status = "existing"
            entry.resolved_at = ""
        return entry

    def contains(self, secret_value: str, file_path: str, rule_id: str) -> bool:
        fingerprint = self.compute_fingerprint(secret_value, file_path, rule_id)
        return fingerprint in self.entries

    def get_entry(self, secret_value: str, file_path: str, rule_id: str) -> Optional[BaselineEntry]:
        fingerprint = self.compute_fingerprint(secret_value, file_path, rule_id)
        return self.entries.get(fingerprint)

    def get_status(self, secret_value: str, file_path: str, rule_id: str) -> str:
        if self.contains(secret_value, file_path, rule_id):
            return "existing"
        return "new"

    def compare(self, current_fingerprints: Set[str]) -> Dict[str, List[BaselineEntry]]:
        result = {
            "new": [],
            "existing": [],
            "resolved": [],
        }
        for fp, entry in self.entries.items():
            if fp not in current_fingerprints:
                if entry.status != "resolved":
                    entry.status = "resolved"
                    entry.resolved_at = datetime.now().isoformat()
                result["resolved"].append(entry)
            else:
                entry.status = "existing"
                entry.resolved_at = ""
                result["existing"].append(entry)
        return result

    def mark_resolved(self, current_fingerprints: Set[str]) -> List[BaselineEntry]:
        resolved_entries = []
        for fp, entry in self.entries.items():
            if fp not in current_fingerprints and entry.status != "resolved":
                entry.status = "resolved"
                entry.resolved_at = datetime.now().isoformat()
                resolved_entries.append(entry)
        return resolved_entries

    def get_resolved_entries(self) -> List[BaselineEntry]:
        return [e for e in self.entries.values() if e.status == "resolved"]

    def get_existing_entries(self) -> List[BaselineEntry]:
        return [e for e in self.entries.values() if e.status == "existing"]

    def cleanup_resolved(self) -> int:
        to_remove = [fp for fp, e in self.entries.items() if e.status == "resolved"]
        for fp in to_remove:
            del self.entries[fp]
        return len(to_remove)

    def update_from_findings(self, findings: list):
        from reporter import ScanFinding
        for finding in findings:
            if not self.contains(finding.secret_value, finding.file_path, finding.rule_id):
                continue
            self.add_entry(
                secret_value=finding.secret_value,
                file_path=finding.file_path,
                rule_id=finding.rule_id,
                line_number=finding.line_number,
                masked_value=finding.masked_value,
                commit_sha=finding.commit_sha,
                author=finding.author_name,
                date=finding.commit_date,
            )
