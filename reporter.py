import json
import os
import sys
import re
from pathlib import Path
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime

try:
    from rich.console import Console, Group
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.style import Style
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from rules import RuleMatch, Rule
from history_walker import CommitInfo, FileContext
from remediator import RevertSuggestion
from entropy import HighEntropyMatch


@dataclass
class ScanFinding:
    rule_id: str
    rule_description: str
    severity: str
    secret_value: str
    masked_value: str
    file_path: str
    line_number: int
    commit_sha: str
    short_sha: str
    commit_number: int
    author_name: str
    author_email: str
    commit_date: str
    commit_message: str
    context_before: List[str]
    context_after: List[str]
    line_content: str
    start_offset: int
    end_offset: int
    entropy: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    revert_suggestion: Optional[RevertSuggestion] = None
    entropy_match: Optional[HighEntropyMatch] = None
    status: str = "new"
    ignored: bool = False
    ignore_reason: str = ""


@dataclass
class ExitPolicy:
    fail_on_severity: Optional[List[str]] = None
    fail_on_status: Optional[List[str]] = None
    fail_on_tags: Optional[List[str]] = None
    fail_on_new_only: bool = False

    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

    def _get_effective_severities(self) -> Optional[Set[str]]:
        if not self.fail_on_severity:
            return None
        if len(self.fail_on_severity) == 1:
            sev = self.fail_on_severity[0].lower()
            if sev in self.SEVERITY_ORDER:
                idx = self.SEVERITY_ORDER.index(sev)
                return set(self.SEVERITY_ORDER[:idx + 1])
        return {s.lower() for s in self.fail_on_severity}

    def is_threshold_mode(self) -> bool:
        if not self.fail_on_severity or len(self.fail_on_severity) != 1:
            return False
        return self.fail_on_severity[0].lower() in self.SEVERITY_ORDER

    def get_description(self) -> str:
        parts = []
        if self.fail_on_severity:
            if self.is_threshold_mode():
                sev = self.fail_on_severity[0].lower()
                parts.append(f"severity >= {sev}")
            else:
                parts.append(f"severity in [{','.join(self.fail_on_severity)}]")
        if self.fail_on_new_only:
            parts.append("new findings only")
        if self.fail_on_tags:
            parts.append(f"tags: {','.join(self.fail_on_tags)}")
        if self.fail_on_status:
            parts.append(f"status: {','.join(self.fail_on_status)}")
        return ", ".join(parts) if parts else "all active findings"

    def should_fail(self, findings: List[ScanFinding]) -> bool:
        return len(self.get_blocking_findings(findings)) > 0

    def get_blocking_findings(self, findings: List[ScanFinding]) -> List[ScanFinding]:
        blocking = [f for f in findings if not f.ignored]
        if not blocking:
            return []
        effective_severities = self._get_effective_severities()
        if effective_severities is not None:
            blocking = [f for f in blocking if f.severity.lower() in effective_severities]
        if self.fail_on_status:
            statuses = {s.lower() for s in self.fail_on_status}
            blocking = [f for f in blocking if f.status.lower() in statuses]
        if self.fail_on_tags:
            tags = {t.lower() for t in self.fail_on_tags}
            blocking = [f for f in blocking if any(t.lower() in tags for t in f.tags)]
        if self.fail_on_new_only:
            blocking = [f for f in blocking if f.status.lower() == "new"]
        return blocking


class Reporter:
    def __init__(
        self,
        output_format: str = "terminal",
        output_file: Optional[str] = None,
        repo_path: Optional[str] = None,
        exit_policy: Optional[ExitPolicy] = None,
    ):
        self.output_format = output_format
        self.output_file = output_file
        self.repo_path = Path(repo_path).resolve() if repo_path else None
        self.findings: List[ScanFinding] = []
        self.ignored_findings: List[ScanFinding] = []
        self.resolved_findings: List[ScanFinding] = []
        self.exit_policy = exit_policy or ExitPolicy()
        self._console = Console() if RICH_AVAILABLE else None
        self._known_secrets: Set[str] = set()
        self._sorted_secrets: Optional[List[str]] = None

    def _collect_known_secrets(self):
        if self._sorted_secrets is not None:
            return
        for f in self.findings + self.ignored_findings:
            if f.secret_value and len(f.secret_value) >= 4:
                self._known_secrets.add(f.secret_value)
        self._sorted_secrets = sorted(self._known_secrets, key=len, reverse=True)

    def mask_line_full(self, line: str) -> str:
        if not line:
            return line
        self._collect_known_secrets()
        result = line
        for secret in self._sorted_secrets:
            if len(secret) < 4:
                continue
            masked = self.mask_secret(secret)
            result = result.replace(secret, masked)
        return result

    def add_finding(self, finding: ScanFinding):
        self._sorted_secrets = None
        if finding.ignored:
            self.ignored_findings.append(finding)
        elif finding.status == "resolved":
            self.resolved_findings.append(finding)
        else:
            self.findings.append(finding)

    def add_resolved_from_baseline(self, baseline_entry):
        finding = ScanFinding(
            rule_id=baseline_entry.rule_id,
            rule_description=baseline_entry.rule_id,
            severity="medium",
            secret_value="",
            masked_value=baseline_entry.secret_value_masked,
            file_path=baseline_entry.file_path,
            line_number=baseline_entry.line_number,
            commit_sha=baseline_entry.last_seen_commit or baseline_entry.first_seen_commit,
            short_sha=(baseline_entry.last_seen_commit or baseline_entry.first_seen_commit)[:7],
            commit_number=0,
            author_name=baseline_entry.last_seen_author or baseline_entry.first_seen_author,
            author_email="",
            commit_date=baseline_entry.last_seen_date or baseline_entry.first_seen_date,
            commit_message="",
            context_before=[],
            context_after=[],
            line_content="",
            start_offset=0,
            end_offset=0,
            entropy=None,
            tags=[],
            status="resolved",
            ignored=False,
            ignore_reason="",
        )
        self.resolved_findings.append(finding)

    def mask_secret(self, secret: str, show_first: int = 2, show_last: int = 2) -> str:
        if len(secret) <= show_first + show_last:
            return "*" * len(secret)
        return secret[:show_first] + "*" * (len(secret) - show_first - show_last) + secret[-show_last:]

    def mask_line(self, line: str, start: int, end: int) -> str:
        if start < 0 or end > len(line) or start >= end:
            return line
        masked_part = "*" * (end - start)
        return line[:start] + masked_part + line[end:]

    def get_masked_context_before(self, finding: ScanFinding) -> List[str]:
        return [self.mask_line_full(line) for line in finding.context_before]

    def get_masked_line_content(self, finding: ScanFinding) -> str:
        if not finding.line_content:
            return ""
        line = self.mask_line(finding.line_content, finding.start_offset, finding.end_offset)
        return self.mask_line_full(line)

    def get_masked_context_after(self, finding: ScanFinding) -> List[str]:
        return [self.mask_line_full(line) for line in finding.context_after]

    def generate_vscode_link(self, file_path: str, line_number: int) -> str:
        if self.repo_path:
            abs_path = str((self.repo_path / file_path).resolve())
        else:
            abs_path = os.path.abspath(file_path)
        abs_path = abs_path.replace("\\", "/")
        return f"file:///{abs_path}#L{line_number}"

    def _get_severity_color(self, severity: str) -> str:
        severity = severity.lower()
        colors = {
            "critical": "bright_red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "green",
        }
        return colors.get(severity, "white")

    def _get_severity_sarif_level(self, severity: str) -> str:
        severity = severity.lower()
        levels = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        return levels.get(severity, "note")

    def _get_status_color(self, status: str) -> str:
        status = status.lower()
        colors = {
            "new": "bright_green",
            "existing": "yellow",
            "resolved": "dim",
            "ignored": "cyan",
        }
        return colors.get(status, "white")

    def render_terminal(self):
        if not RICH_AVAILABLE:
            self._render_plain_terminal()
            return
        console = self._console
        all_findings = self.findings + self.ignored_findings
        console.print(Panel.fit(
            Text("Git Secret Scanner Results", style="bold magenta"),
            border_style="magenta"
        ))
        if not all_findings and not self.resolved_findings:
            console.print("[green]No secrets found![/green]")
            return
        active_findings = self.findings
        active_findings.sort(key=lambda f: (
            {"new": 0, "existing": 1}.get(f.status.lower(), 2),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.lower(), 5)
        ))
        for i, finding in enumerate(active_findings, 1):
            color = self._get_severity_color(finding.severity)
            status_color = self._get_status_color(finding.status)
            vscode_link = self.generate_vscode_link(finding.file_path, finding.line_number)
            title = Text.assemble(
                (f"Finding #{i}: ", "bold"),
                (f"[{finding.status.upper()}] ", f"bold {status_color}"),
                (f"[{finding.severity.upper()}] ", f"bold {color}"),
                (finding.rule_description, "bold")
            )
            info_table = Table(show_header=False, border_style="dim", padding=(0, 2))
            info_table.add_column("Key", style="dim")
            info_table.add_column("Value")
            info_table.add_row("File", Text(f"{finding.file_path}:{finding.line_number}", style=Style(color="cyan", underline=True, link=vscode_link)))
            info_table.add_row("Commit", f"{finding.short_sha} (#{finding.commit_number})")
            info_table.add_row("Author", f"{finding.author_name} <{finding.author_email}>")
            info_table.add_row("Date", finding.commit_date)
            info_table.add_row("Secret", finding.masked_value)
            if finding.entropy:
                info_table.add_row("Entropy", f"{finding.entropy:.2f}")
            if finding.tags:
                info_table.add_row("Tags", ", ".join(finding.tags))
            if finding.revert_suggestion:
                info_table.add_row("Revert", f"[yellow]{finding.revert_suggestion.revert_command}[/yellow]")
            masked_line = self.get_masked_line_content(finding)
            masked_before = self.get_masked_context_before(finding)
            masked_after = self.get_masked_context_after(finding)
            context_lines = []
            ctx_start = finding.line_number - len(masked_before)
            for j, line in enumerate(masked_before):
                context_lines.append((ctx_start + j, line, "dim"))
            context_lines.append((finding.line_number, masked_line, color))
            for j, line in enumerate(masked_after):
                context_lines.append((finding.line_number + j + 1, line, "dim"))
            code_content = "\n".join(
                f"{ln:4d} | {line}" for ln, line, _ in context_lines
            )
            syntax = Syntax(
                code_content,
                "python",
                theme="monokai",
                line_numbers=False,
                word_wrap=True,
            )
            console.print(Panel(
                Group(info_table, "\n", syntax),
                title=title,
                border_style=color,
            ))
        if self.ignored_findings:
            console.print()
            ignored_title = Text(f"Ignored Findings ({len(self.ignored_findings)})", style="bold cyan")
            ignored_table = Table(title="", show_header=False, border_style="dim")
            ignored_table.add_column("Rule", style="dim")
            ignored_table.add_column("File", style="dim")
            ignored_table.add_column("Reason", style="dim")
            for f in self.ignored_findings:
                reason = f.ignore_reason or "allowlist"
                ignored_table.add_row(f.rule_id, f"{f.file_path}:{f.line_number}", reason)
            console.print(Panel(ignored_table, title=ignored_title, border_style="cyan"))
        if self.resolved_findings:
            console.print()
            resolved_title = Text(f"Resolved Findings ({len(self.resolved_findings)})", style="bold green")
            resolved_table = Table(title="", show_header=False, border_style="dim")
            resolved_table.add_column("Rule", style="dim")
            resolved_table.add_column("File", style="dim")
            resolved_table.add_column("Last Seen", style="dim")
            for f in self.resolved_findings:
                last_seen = f.commit_date or "unknown"
                resolved_table.add_row(f.rule_id, f"{f.file_path}:{f.line_number}", last_seen)
            console.print(Panel(resolved_table, title=resolved_title, border_style="green"))
        summary_table = Table(title="Summary", show_header=True, border_style="dim")
        summary_table.add_column("Category", style="bold")
        summary_table.add_column("Critical", justify="right")
        summary_table.add_column("High", justify="right")
        summary_table.add_column("Medium", justify="right")
        summary_table.add_column("Low", justify="right")
        summary_table.add_column("Total", justify="right")
        def count_by_severity(findings_list):
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
            for f in findings_list:
                sev = f.severity.lower()
                if sev in counts:
                    counts[sev] += 1
                counts["total"] += 1
            return counts
        new_counts = count_by_severity([f for f in self.findings if f.status == "new"])
        existing_counts = count_by_severity([f for f in self.findings if f.status == "existing"])
        ignored_counts = count_by_severity(self.ignored_findings)
        resolved_counts = count_by_severity(self.resolved_findings)
        total_active = count_by_severity(self.findings)
        summary_table.add_row(
            Text("New", style="bright_green"),
            str(new_counts["critical"]),
            str(new_counts["high"]),
            str(new_counts["medium"]),
            str(new_counts["low"]),
            str(new_counts["total"]),
        )
        summary_table.add_row(
            Text("Existing", style="yellow"),
            str(existing_counts["critical"]),
            str(existing_counts["high"]),
            str(existing_counts["medium"]),
            str(existing_counts["low"]),
            str(existing_counts["total"]),
        )
        summary_table.add_row(
            Text("Ignored", style="cyan"),
            str(ignored_counts["critical"]),
            str(ignored_counts["high"]),
            str(ignored_counts["medium"]),
            str(ignored_counts["low"]),
            str(ignored_counts["total"]),
        )
        summary_table.add_row(
            Text("Resolved", style="green"),
            str(resolved_counts["critical"]),
            str(resolved_counts["high"]),
            str(resolved_counts["medium"]),
            str(resolved_counts["low"]),
            str(resolved_counts["total"]),
        )
        summary_table.add_row(
            Text("TOTAL (active)", style="bold"),
            Text(str(total_active["critical"]), style="bold"),
            Text(str(total_active["high"]), style="bold"),
            Text(str(total_active["medium"]), style="bold"),
            Text(str(total_active["low"]), style="bold"),
            Text(str(total_active["total"]), style="bold"),
        )
        console.print(summary_table)
        blocking = self.exit_policy.get_blocking_findings(self.findings)
        if blocking:
            console.print()
            reason_text = self.exit_policy.get_description()
            console.print(Panel(
                Text(f"FAIL - {len(blocking)} blocking finding(s)", style="bold red"),
                subtitle=Text(f"Rule: {reason_text}", style="dim"),
                border_style="red",
            ))

    def _render_plain_terminal(self):
        print("Git Secret Scanner Results")
        print("=" * 50)
        all_findings = self.findings + self.ignored_findings
        if not all_findings and not self.resolved_findings:
            print("No secrets found!")
            return
        active_findings = sorted(self.findings, key=lambda f: (
            {"new": 0, "existing": 1}.get(f.status.lower(), 2),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.lower(), 5)
        ))
        for i, finding in enumerate(active_findings, 1):
            print(f"\nFinding #{i}: [{finding.status.upper()}] [{finding.severity.upper()}] {finding.rule_description}")
            print(f"  File: {finding.file_path}:{finding.line_number}")
            print(f"  Commit: {finding.short_sha} (#{finding.commit_number})")
            print(f"  Author: {finding.author_name} <{finding.author_email}>")
            print(f"  Secret: {finding.masked_value}")
            if finding.entropy:
                print(f"  Entropy: {finding.entropy:.2f}")
            if finding.tags:
                print(f"  Tags: {', '.join(finding.tags)}")
            if finding.revert_suggestion:
                print(f"  Revert: {finding.revert_suggestion.revert_command}")
            print("  Context:")
            masked_before = self.get_masked_context_before(finding)
            masked_after = self.get_masked_context_after(finding)
            ctx_start = finding.line_number - len(masked_before)
            for j, line in enumerate(masked_before):
                print(f"    {ctx_start + j:4d}: {line}")
            masked_line = self.get_masked_line_content(finding)
            print(f"    {finding.line_number:4d}: {masked_line}")
            for j, line in enumerate(masked_after):
                print(f"    {finding.line_number + j + 1:4d}: {line}")
        if self.ignored_findings:
            print(f"\nIgnored findings: {len(self.ignored_findings)}")
            for f in self.ignored_findings:
                reason = f.ignore_reason or "allowlist"
                print(f"  - {f.rule_id}: {f.file_path}:{f.line_number} ({reason})")
        if self.resolved_findings:
            print(f"\nResolved findings: {len(self.resolved_findings)}")
            for f in self.resolved_findings:
                last_seen = f.commit_date or "unknown"
                print(f"  - {f.rule_id}: {f.file_path}:{f.line_number} (last seen: {last_seen})")
        new_count = sum(1 for f in self.findings if f.status == "new")
        existing_count = sum(1 for f in self.findings if f.status == "existing")
        print(f"\nSummary: {len(self.findings)} active (new: {new_count}, existing: {existing_count}), {len(self.ignored_findings)} ignored, {len(self.resolved_findings)} resolved")
        blocking = self.exit_policy.get_blocking_findings(self.findings)
        if blocking:
            print(f"Blocking findings: {len(blocking)} (would fail CI)")

    def render_json(self) -> str:
        findings_data = []
        all_findings = self.findings + self.ignored_findings + self.resolved_findings
        for finding in all_findings:
            masked_line = self.get_masked_line_content(finding) if finding.line_content else ""
            masked_before = self.get_masked_context_before(finding)
            masked_after = self.get_masked_context_after(finding)
            data = {
                "rule_id": finding.rule_id,
                "rule_description": finding.rule_description,
                "severity": finding.severity,
                "status": finding.status,
                "ignored": finding.ignored,
                "ignore_reason": finding.ignore_reason,
                "secret_value_masked": finding.masked_value,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "commit_sha": finding.commit_sha,
                "short_sha": finding.short_sha,
                "commit_number": finding.commit_number,
                "author_name": finding.author_name,
                "author_email": finding.author_email,
                "commit_date": finding.commit_date,
                "commit_message": finding.commit_message,
                "line_content_masked": masked_line,
                "context_before_masked": masked_before,
                "context_after_masked": masked_after,
                "start_offset": finding.start_offset,
                "end_offset": finding.end_offset,
                "entropy": finding.entropy,
                "tags": finding.tags,
            }
            if finding.revert_suggestion:
                data["revert_command"] = finding.revert_suggestion.revert_command
            findings_data.append(data)
        blocking = self.exit_policy.get_blocking_findings(self.findings)
        summary = {
            "total_active": len(self.findings),
            "total_ignored": len(self.ignored_findings),
            "total_resolved": len(self.resolved_findings),
            "new": sum(1 for f in self.findings if f.status == "new"),
            "existing": sum(1 for f in self.findings if f.status == "existing"),
            "resolved": len(self.resolved_findings),
            "blocking": len(blocking),
            "by_severity": {},
        }
        for f in self.findings:
            sev = f.severity.lower()
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
        output = {
            "scan_date": datetime.now().isoformat(),
            "summary": summary,
            "findings": findings_data,
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    def render_sarif(self) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Git Secret Scanner",
                            "version": "1.0.0",
                            "informationUri": "https://example.com/git-secret-scanner",
                            "rules": self._get_sarif_rules(),
                        }
                    },
                    "results": self._get_sarif_results(),
                }
            ],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _get_sarif_rules(self) -> List[Dict[str, Any]]:
        rules_seen = {}
        all_findings = self.findings + self.ignored_findings + self.resolved_findings
        for finding in all_findings:
            if finding.rule_id not in rules_seen:
                rules_seen[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_description,
                    "shortDescription": {
                        "text": finding.rule_description
                    },
                    "fullDescription": {
                        "text": finding.rule_description
                    },
                    "defaultConfiguration": {
                        "level": self._get_severity_sarif_level(finding.severity)
                    },
                    "properties": {
                        "tags": finding.tags,
                    },
                }
        return list(rules_seen.values())

    def _get_sarif_results(self) -> List[Dict[str, Any]]:
        results = []
        all_findings = self.findings + self.ignored_findings + self.resolved_findings
        for finding in all_findings:
            masked_line = self.get_masked_line_content(finding) if finding.line_content else ""
            if finding.status == "new":
                kind = "fail"
            elif finding.status == "existing":
                kind = "pass"
            elif finding.status == "resolved":
                kind = "notApplicable"
            else:
                kind = "open"
            level = self._get_severity_sarif_level(finding.severity)
            if finding.ignored:
                level = "note"
                kind = "notApplicable"
            if finding.status == "resolved":
                level = "note"
            suppressions = []
            if finding.ignored:
                suppressions.append({
                    "kind": "inSource",
                    "justification": finding.ignore_reason or "allowlist",
                })
            if finding.status == "resolved":
                suppressions.append({
                    "kind": "external",
                    "justification": "resolved - secret no longer present in codebase",
                })
            result = {
                "ruleId": finding.rule_id,
                "level": level,
                "kind": kind,
                "message": {
                    "text": f"[{finding.status.upper()}] {finding.rule_description} in {finding.file_path}:{finding.line_number}. "
                            f"Secret: {finding.masked_value}. "
                            f"Commit: {finding.short_sha} by {finding.author_name}."
                            + (f" Line: {masked_line}" if masked_line else "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path,
                            },
                            "region": {
                                "startLine": finding.line_number,
                                "startColumn": finding.start_offset + 1,
                                "endColumn": finding.end_offset + 1,
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "commitSha": finding.commit_sha,
                    "primaryLocationLineHash": str(hash(f"{finding.file_path}:{finding.line_number}:{finding.masked_value[:10]}")),
                },
                "properties": {
                    "status": finding.status,
                    "ignored": finding.ignored,
                    "ignore_reason": finding.ignore_reason,
                    "commit_sha": finding.commit_sha,
                    "commit_number": finding.commit_number,
                    "author_name": finding.author_name,
                    "author_email": finding.author_email,
                    "commit_date": finding.commit_date,
                    "entropy": finding.entropy,
                    "tags": finding.tags,
                },
            }
            if finding.line_content:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": masked_line,
                }
            if suppressions:
                result["suppressions"] = suppressions
            if finding.revert_suggestion:
                result["properties"]["revert_command"] = finding.revert_suggestion.revert_command
            results.append(result)
        return results

    def render(self) -> Optional[str]:
        if self.output_format == "json":
            output = self.render_json()
        elif self.output_format == "sarif":
            output = self.render_sarif()
        elif self.output_format == "terminal":
            self.render_terminal()
            return None
        else:
            raise ValueError(f"Unknown output format: {self.output_format}")
        if self.output_file:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(output)
        else:
            print(output)
        return output
