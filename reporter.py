import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Optional, Any
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


class Reporter:
    def __init__(self, output_format: str = "terminal", output_file: Optional[str] = None):
        self.output_format = output_format
        self.output_file = output_file
        self.findings: List[ScanFinding] = []
        self._console = Console() if RICH_AVAILABLE else None

    def add_finding(self, finding: ScanFinding):
        self.findings.append(finding)

    def mask_secret(self, secret: str, show_first: int = 2, show_last: int = 2) -> str:
        if len(secret) <= show_first + show_last:
            return "*" * len(secret)
        return secret[:show_first] + "*" * (len(secret) - show_first - show_last) + secret[-show_last:]

    def generate_vscode_link(self, file_path: str, line_number: int) -> str:
        abs_path = os.path.abspath(file_path)
        return f"file://{abs_path}#L{line_number}"

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

    def render_terminal(self):
        if not RICH_AVAILABLE:
            self._render_plain_terminal()
            return
        console = self._console
        console.print(Panel.fit(
            Text("Git Secret Scanner Results", style="bold magenta"),
            border_style="magenta"
        ))
        if not self.findings:
            console.print("[green]No secrets found![/green]")
            return
        self.findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.lower(), 5))
        for i, finding in enumerate(self.findings, 1):
            color = self._get_severity_color(finding.severity)
            vscode_link = self.generate_vscode_link(finding.file_path, finding.line_number)
            title = Text.assemble(
                (f"Finding #{i}: ", "bold"),
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
            if finding.revert_suggestion:
                info_table.add_row("Revert", f"[yellow]{finding.revert_suggestion.revert_command}[/yellow]")
            context_lines = []
            ctx_start = finding.line_number - len(finding.context_before)
            for j, line in enumerate(finding.context_before):
                context_lines.append((ctx_start + j, line, "dim"))
            context_lines.append((finding.line_number, finding.line_content, color))
            for j, line in enumerate(finding.context_after):
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
        summary_table = Table(title="Summary", show_header=True, border_style="dim")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        severity_counts = {}
        for f in self.findings:
            sev = f.severity.upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in severity_counts:
                color = self._get_severity_color(sev.lower())
                summary_table.add_row(
                    Text(sev, style=color),
                    str(severity_counts[sev])
                )
        summary_table.add_row("TOTAL", str(len(self.findings)), style="bold")
        console.print(summary_table)

    def _render_plain_terminal(self):
        print("Git Secret Scanner Results")
        print("=" * 50)
        if not self.findings:
            print("No secrets found!")
            return
        self.findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.lower(), 5))
        for i, finding in enumerate(self.findings, 1):
            print(f"\nFinding #{i}: [{finding.severity.upper()}] {finding.rule_description}")
            print(f"  File: {finding.file_path}:{finding.line_number}")
            print(f"  Commit: {finding.short_sha} (#{finding.commit_number})")
            print(f"  Author: {finding.author_name} <{finding.author_email}>")
            print(f"  Secret: {finding.masked_value}")
            if finding.entropy:
                print(f"  Entropy: {finding.entropy:.2f}")
            if finding.revert_suggestion:
                print(f"  Revert: {finding.revert_suggestion.revert_command}")
            print("  Context:")
            ctx_start = finding.line_number - len(finding.context_before)
            for j, line in enumerate(finding.context_before):
                print(f"    {ctx_start + j:4d}: {line}")
            print(f"    {finding.line_number:4d}: {finding.line_content}")
            for j, line in enumerate(finding.context_after):
                print(f"    {finding.line_number + j + 1:4d}: {line}")
        print(f"\nTotal findings: {len(self.findings)}")

    def render_json(self) -> str:
        findings_data = []
        for finding in self.findings:
            data = {
                "rule_id": finding.rule_id,
                "rule_description": finding.rule_description,
                "severity": finding.severity,
                "secret_value": finding.masked_value,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "commit_sha": finding.commit_sha,
                "short_sha": finding.short_sha,
                "commit_number": finding.commit_number,
                "author_name": finding.author_name,
                "author_email": finding.author_email,
                "commit_date": finding.commit_date,
                "commit_message": finding.commit_message,
                "line_content": finding.line_content,
                "context_before": finding.context_before,
                "context_after": finding.context_after,
                "entropy": finding.entropy,
                "tags": finding.tags,
            }
            if finding.revert_suggestion:
                data["revert_command"] = finding.revert_suggestion.revert_command
            findings_data.append(data)
        output = {
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(self.findings),
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
        for finding in self.findings:
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
                }
        return list(rules_seen.values())

    def _get_sarif_results(self) -> List[Dict[str, Any]]:
        results = []
        for finding in self.findings:
            result = {
                "ruleId": finding.rule_id,
                "level": self._get_severity_sarif_level(finding.severity),
                "message": {
                    "text": f"Found {finding.rule_description} in {finding.file_path}:{finding.line_number}. "
                            f"Secret: {finding.masked_value}. "
                            f"Commit: {finding.short_sha} by {finding.author_name}."
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
                    "secretHash": str(hash(finding.secret_value)),
                },
                "properties": {
                    "commit_sha": finding.commit_sha,
                    "commit_number": finding.commit_number,
                    "author_name": finding.author_name,
                    "author_email": finding.author_email,
                    "commit_date": finding.commit_date,
                    "entropy": finding.entropy,
                },
            }
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
