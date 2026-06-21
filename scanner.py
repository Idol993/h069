import sys
import os
import time
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
import hashlib

try:
    import click
except ImportError:
    click = None

from entropy import calculate_entropy, extract_potential_secrets, is_high_entropy_string
from rules import load_all_rules, match_rules, Rule, RuleMatch
from history_walker import HistoryWalker, DiffResult, DiffHunk, FileContext
from reporter import Reporter, ScanFinding
from remediator import Remediator


class GitSecretScanner:
    def __init__(
        self,
        repo_path: str,
        rules: Optional[List[Rule]] = None,
        custom_rules_path: Optional[str] = None,
        entropy_threshold: float = 4.5,
        min_entropy_length: int = 32,
        context_lines: int = 5,
        max_commits: Optional[int] = None,
        since_commit: Optional[str] = None,
        enable_entropy_scan: bool = True,
    ):
        self.repo_path = Path(repo_path).resolve()
        self.entropy_threshold = entropy_threshold
        self.min_entropy_length = min_entropy_length
        self.context_lines = context_lines
        self.max_commits = max_commits
        self.since_commit = since_commit
        self.enable_entropy_scan = enable_entropy_scan
        self.walker = HistoryWalker(str(self.repo_path), max_commits)
        self.rules = rules if rules else load_all_rules(custom_rules_path)
        self.remediator = Remediator(str(self.repo_path))
        self._seen_secrets: Set[str] = set()

    def _get_secret_hash(self, secret: str, file_path: str, rule_id: str) -> str:
        data = f"{secret}|{file_path}|{rule_id}"
        return hashlib.sha256(data.encode()).hexdigest()

    def scan_line(
        self,
        line: str,
        line_number: int,
        file_path: str,
        commit: 'CommitInfo',
    ) -> List[ScanFinding]:
        findings = []
        rule_matches = match_rules(line, line_number, self.rules)
        for rm in rule_matches:
            if rm.rule.entropy_check and rm.value:
                if not is_high_entropy_string(rm.value, self.entropy_threshold, min(self.min_entropy_length, len(rm.value))):
                    continue
            entropy = calculate_entropy(rm.value) if rm.value else None
            secret_hash = self._get_secret_hash(rm.value, file_path, rm.rule.id)
            if secret_hash in self._seen_secrets:
                continue
            self._seen_secrets.add(secret_hash)
            file_ctx = self.walker.get_file_context(
                file_path, line_number, commit.sha, self.context_lines
            )
            masked = self._mask_secret(rm.value)
            revert_suggestion = self.remediator.generate_revert_suggestion(
                commit, rm.value, rm.rule.id
            )
            findings.append(ScanFinding(
                rule_id=rm.rule.id,
                rule_description=rm.rule.description,
                severity=rm.rule.severity,
                secret_value=rm.value,
                masked_value=masked,
                file_path=file_path,
                line_number=line_number,
                commit_sha=commit.sha,
                short_sha=commit.short_sha,
                commit_number=commit.commit_number,
                author_name=commit.author_name,
                author_email=commit.author_email,
                commit_date=commit.date.isoformat(),
                commit_message=commit.message,
                context_before=file_ctx.context_before,
                context_after=file_ctx.context_after,
                line_content=file_ctx.line_content,
                start_offset=rm.start,
                end_offset=rm.end,
                entropy=entropy,
                tags=rm.rule.tags,
                revert_suggestion=revert_suggestion,
            ))
        if self.enable_entropy_scan:
            entropy_matches = extract_potential_secrets(
                line, self.entropy_threshold, self.min_entropy_length
            )
            for em in entropy_matches:
                already_found = any(
                    rm.start <= em.start < rm.end or rm.start < em.end <= rm.end
                    for rm in rule_matches
                )
                if already_found:
                    continue
                secret_hash = self._get_secret_hash(em.value, file_path, "high-entropy")
                if secret_hash in self._seen_secrets:
                    continue
                self._seen_secrets.add(secret_hash)
                file_ctx = self.walker.get_file_context(
                    file_path, line_number, commit.sha, self.context_lines
                )
                masked = self._mask_secret(em.value)
                revert_suggestion = self.remediator.generate_revert_suggestion(
                    commit, em.value, "high-entropy"
                )
                findings.append(ScanFinding(
                    rule_id="high-entropy",
                    rule_description=f"High entropy string (entropy: {em.entropy:.2f})",
                    severity="medium",
                    secret_value=em.value,
                    masked_value=masked,
                    file_path=file_path,
                    line_number=line_number,
                    commit_sha=commit.sha,
                    short_sha=commit.short_sha,
                    commit_number=commit.commit_number,
                    author_name=commit.author_name,
                    author_email=commit.author_email,
                    commit_date=commit.date.isoformat(),
                    commit_message=commit.message,
                    context_before=file_ctx.context_before,
                    context_after=file_ctx.context_after,
                    line_content=file_ctx.line_content,
                    start_offset=em.start,
                    end_offset=em.end,
                    entropy=em.entropy,
                    tags=["entropy"],
                    revert_suggestion=revert_suggestion,
                ))
        return findings

    def _mask_secret(self, secret: str, show_first: int = 2, show_last: int = 2) -> str:
        if len(secret) <= show_first + show_last:
            return "*" * len(secret)
        return secret[:show_first] + "*" * (len(secret) - show_first - show_last) + secret[-show_last:]

    def scan_hunk(
        self,
        hunk: DiffHunk,
        commit: 'CommitInfo',
    ) -> List[ScanFinding]:
        findings = []
        for i, line in enumerate(hunk.new_lines):
            line_num = hunk.new_line_start + i
            if line_num < 1:
                continue
            findings.extend(self.scan_line(line, line_num, hunk.file_path, commit))
        return findings

    def scan_commit(
        self,
        diff_result: DiffResult,
    ) -> List[ScanFinding]:
        findings = []
        for hunk in diff_result.hunks:
            findings.extend(self.scan_hunk(hunk, diff_result.commit))
        return findings

    def scan_repository(
        self,
        reporter: Optional[Reporter] = None,
        progress_callback=None,
    ) -> Reporter:
        if reporter is None:
            reporter = Reporter(output_format="terminal")
        total_commits = 0
        start_time = time.time()
        for diff_result in self.walker.walk_commits(self.since_commit):
            total_commits += 1
            if progress_callback:
                progress_callback(total_commits)
            findings = self.scan_commit(diff_result)
            for finding in findings:
                reporter.add_finding(finding)
        elapsed = time.time() - start_time
        return reporter


if click is not None:
    @click.group()
    @click.version_option(version="1.0.0", prog_name="git-secret-scanner")
    def cli():
        pass

    @cli.command()
    @click.argument('repo_path', default='.')
    @click.option('--rules', '-r', 'rules_path', type=click.Path(exists=True, dir_okay=False),
                  help='Path to custom rules YAML file')
    @click.option('--format', '-f', 'output_format', type=click.Choice(['terminal', 'json', 'sarif']),
                  default='terminal', help='Output format')
    @click.option('--output', '-o', 'output_file', type=click.Path(dir_okay=False, writable=True),
                  help='Output file path')
    @click.option('--entropy-threshold', type=float, default=4.5,
                  help='Entropy threshold for high-entropy detection')
    @click.option('--min-entropy-length', type=int, default=32,
                  help='Minimum length for high-entropy string detection')
    @click.option('--context-lines', type=int, default=5,
                  help='Number of context lines to show before and after')
    @click.option('--max-commits', type=int, default=None,
                  help='Maximum number of commits to scan')
    @click.option('--since-commit', type=str, default=None,
                  help='Start scanning from this commit SHA')
    @click.option('--no-entropy', is_flag=True, default=False,
                  help='Disable high-entropy string scanning')
    @click.option('--exit-code', is_flag=True, default=False,
                  help='Exit with non-zero code if secrets are found')
    def scan(
        repo_path,
        rules_path,
        output_format,
        output_file,
        entropy_threshold,
        min_entropy_length,
        context_lines,
        max_commits,
        since_commit,
        no_entropy,
        exit_code,
    ):
        try:
            scanner = GitSecretScanner(
                repo_path=repo_path,
                custom_rules_path=rules_path,
                entropy_threshold=entropy_threshold,
                min_entropy_length=min_entropy_length,
                context_lines=context_lines,
                max_commits=max_commits,
                since_commit=since_commit,
                enable_entropy_scan=not no_entropy,
            )
            reporter = Reporter(output_format=output_format, output_file=output_file)
            with click.progressbar(label='Scanning commits', length=0) as bar:
                def progress(count):
                    bar.length = count
                    bar.update(1)
                reporter = scanner.scan_repository(reporter, progress_callback=progress)
            reporter.render()
            if exit_code and len(reporter.findings) > 0:
                sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    @cli.command()
    @click.option('--path', '-p', 'config_path', type=click.Path(dir_okay=False, writable=True),
                  default='.gitleaks.yaml', help='Output path for the rule file')
    def init_rules(config_path):
        default_rules = """# Git Secret Scanner Rules
# This file is compatible with gitleaks format
# Add your custom rules here

rules:
  - id: company-internal-token
    description: Company Internal API Token
    regex: 'COMPANY-[A-Z0-9]{24}'
    severity: high
    tags: [company, api-key]
    entropy_check: true

  - id: internal-database-uri
    description: Internal Database Connection URI
    regex: 'company-db://[^\\s]+'
    severity: critical
    tags: [database, company]
"""
        path = Path(config_path)
        if path.exists():
            if not click.confirm(f"File {config_path} already exists. Overwrite?"):
                return
        with open(path, 'w') as f:
            f.write(default_rules)
        click.echo(f"Created sample rules file at {config_path}")


def main():
    if click is None:
        print("Error: Click is required. Install with: pip install click", file=sys.stderr)
        sys.exit(1)
    cli()


if __name__ == "__main__":
    main()
