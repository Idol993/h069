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
from rules import load_all_rules, load_all_allowlists, match_rules, Rule, RuleMatch, Allowlist
from history_walker import HistoryWalker, DiffResult, DiffHunk, FileContext
from reporter import Reporter, ScanFinding, ExitPolicy
from remediator import Remediator
from baseline import Baseline


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
        baseline: Optional[Baseline] = None,
        allowlist: Optional[Allowlist] = None,
    ):
        self.repo_path = Path(repo_path).resolve()
        self.entropy_threshold = entropy_threshold
        self.min_entropy_length = min_entropy_length
        self.context_lines = context_lines
        self.max_commits = max_commits
        self.since_commit = since_commit
        self.enable_entropy_scan = enable_entropy_scan
        self.walker = HistoryWalker(str(self.repo_path), max_commits)
        self.rules = rules if rules else load_all_rules(custom_rules_path, repo_path=str(self.repo_path))
        self.allowlist = allowlist if allowlist is not None else load_all_allowlists(custom_rules_path, repo_path=str(self.repo_path))
        self.baseline = baseline
        self.remediator = Remediator(str(self.repo_path))
        self._seen_secrets: Set[str] = set()

    def _get_secret_hash(self, secret: str, file_path: str, rule_id: str) -> str:
        data = f"{secret}|{file_path}|{rule_id}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _check_allowlist(
        self,
        secret_value: str,
        file_path: str,
        commit_sha: str,
        author: str,
        rule_id: str,
        line_content: str,
    ) -> Optional[str]:
        if self.allowlist.is_allowed(
            secret_value=secret_value,
            file_path=file_path,
            commit_sha=commit_sha,
            author=author,
            rule_id=rule_id,
            line_content=line_content,
        ):
            return "allowlist"
        return None

    def _get_baseline_status(self, secret_value: str, file_path: str, rule_id: str) -> str:
        if self.baseline is None:
            return "new"
        return self.baseline.get_status(secret_value, file_path, rule_id)

    def scan_line(
        self,
        line: str,
        line_number: int,
        file_path: str,
        commit: 'CommitInfo',
        hunk_info: Optional['DiffHunk'] = None,
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
            ignore_reason = self._check_allowlist(
                secret_value=rm.value,
                file_path=file_path,
                commit_sha=commit.sha,
                author=commit.author_name,
                rule_id=rm.rule.id,
                line_content=line,
            )
            is_ignored = ignore_reason is not None
            status = self._get_baseline_status(rm.value, file_path, rm.rule.id)
            file_ctx = self.walker.get_file_context(
                file_path, line_number, commit.sha, self.context_lines
            )
            masked = self._mask_secret(rm.value)
            revert_suggestion = self.remediator.generate_revert_suggestion(
                commit, rm.value, rm.rule.id
            )
            finding_kwargs = dict(
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
                status=status,
                ignored=is_ignored,
                ignore_reason=ignore_reason or "",
            )
            if hunk_info:
                finding_kwargs.update(dict(
                    hunk_file=hunk_info.file_path,
                    hunk_new_start=hunk_info.new_line_start,
                    hunk_new_end=hunk_info.new_line_end,
                    hunk_old_start=hunk_info.old_line_start,
                    hunk_old_end=hunk_info.old_line_end,
                ))
            findings.append(ScanFinding(**finding_kwargs))
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
                ignore_reason = self._check_allowlist(
                    secret_value=em.value,
                    file_path=file_path,
                    commit_sha=commit.sha,
                    author=commit.author_name,
                    rule_id="high-entropy",
                    line_content=line,
                )
                is_ignored = ignore_reason is not None
                status = self._get_baseline_status(em.value, file_path, "high-entropy")
                file_ctx = self.walker.get_file_context(
                    file_path, line_number, commit.sha, self.context_lines
                )
                masked = self._mask_secret(em.value)
                revert_suggestion = self.remediator.generate_revert_suggestion(
                    commit, em.value, "high-entropy"
                )
                entropy_finding_kwargs = dict(
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
                    status=status,
                    ignored=is_ignored,
                    ignore_reason=ignore_reason or "",
                )
                if hunk_info:
                    entropy_finding_kwargs.update(dict(
                        hunk_file=hunk_info.file_path,
                        hunk_new_start=hunk_info.new_line_start,
                        hunk_new_end=hunk_info.new_line_end,
                        hunk_old_start=hunk_info.old_line_start,
                        hunk_old_end=hunk_info.old_line_end,
                    ))
                findings.append(ScanFinding(**entropy_finding_kwargs))
        return findings

    def _mask_secret(self, secret: str, show_first: int = 2, show_last: int = 2) -> str:
        if len(secret) <= show_first + show_last:
            return "*" * len(secret)
        return secret[:show_first] + "*" * (len(secret) - show_first - show_last) + secret[-show_last:]

    def scan_hunk(
        self,
        hunk: DiffHunk,
        commit: 'CommitInfo',
        diff_mode: bool = False,
    ) -> List[ScanFinding]:
        findings = []
        for i, line in enumerate(hunk.new_lines):
            if diff_mode:
                if i < len(hunk.new_line_types) and hunk.new_line_types[i] != "added":
                    continue
            line_num = hunk.new_line_start + i
            if line_num < 1:
                continue
            findings.extend(self.scan_line(line, line_num, hunk.file_path, commit, hunk_info=hunk))
        return findings

    def scan_commit(
        self,
        diff_result: DiffResult,
        diff_mode: bool = False,
    ) -> List[ScanFinding]:
        findings = []
        for hunk in diff_result.hunks:
            findings.extend(self.scan_hunk(hunk, diff_result.commit, diff_mode=diff_mode))
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
                if self.baseline is not None and not finding.ignored:
                    self.baseline.update_entry_seen(
                        secret_value=finding.secret_value,
                        file_path=finding.file_path,
                        rule_id=finding.rule_id,
                        commit_sha=finding.commit_sha,
                        author=finding.author_name,
                        date=finding.commit_date,
                    )
        if self.baseline is not None:
            current_fps = set()
            for finding in reporter.findings:
                if not finding.ignored:
                    fp = Baseline.compute_fingerprint(
                        finding.secret_value, finding.file_path, finding.rule_id
                    )
                    current_fps.add(fp)
            self.baseline.mark_resolved(current_fps)
            resolved_entries = self.baseline.get_resolved_entries()
            for entry in resolved_entries:
                reporter.add_resolved_from_baseline(entry)
        elapsed = time.time() - start_time
        return reporter

    def scan_diff(
        self,
        base_ref: str,
        head_ref: str,
        reporter: Optional[Reporter] = None,
        progress_callback=None,
    ) -> Reporter:
        if reporter is None:
            reporter = Reporter(output_format="terminal")
        total_commits = 0
        start_time = time.time()
        for diff_result in self.walker.walk_commits_range(base_ref, head_ref):
            total_commits += 1
            if progress_callback:
                progress_callback(total_commits)
            findings = self.scan_commit(diff_result, diff_mode=True)
            for finding in findings:
                reporter.add_finding(finding)
                if self.baseline is not None and not finding.ignored:
                    self.baseline.update_entry_seen(
                        secret_value=finding.secret_value,
                        file_path=finding.file_path,
                        rule_id=finding.rule_id,
                        commit_sha=finding.commit_sha,
                        author=finding.author_name,
                        date=finding.commit_date,
                    )
        if self.baseline is not None:
            current_fps = set()
            for finding in reporter.findings:
                if not finding.ignored:
                    fp = Baseline.compute_fingerprint(
                        finding.secret_value, finding.file_path, finding.rule_id
                    )
                    current_fps.add(fp)
            self.baseline.mark_resolved(current_fps)
            resolved_entries = self.baseline.get_resolved_entries()
            for entry in resolved_entries:
                reporter.add_resolved_from_baseline(entry)
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
    @click.option('--baseline', '-b', 'baseline_path', type=click.Path(dir_okay=False),
                  help='Path to baseline file for comparing results')
    @click.option('--fail-on-severity', 'fail_on_severity', type=str, default=None,
                  help='Comma-separated list of severities to fail on (e.g. critical,high)')
    @click.option('--fail-on-new-only', is_flag=True, default=False,
                  help='Only fail on new findings (not existing in baseline)')
    @click.option('--fail-on-tags', 'fail_on_tags', type=str, default=None,
                  help='Comma-separated list of tags to fail on')
    @click.option('--exit-code', is_flag=True, default=False,
                  help='Exit with non-zero code if blocking secrets are found')
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
        baseline_path,
        fail_on_severity,
        fail_on_new_only,
        fail_on_tags,
        exit_code,
    ):
        try:
            baseline = Baseline(baseline_path) if baseline_path else None
            exit_policy = ExitPolicy()
            if fail_on_severity:
                exit_policy.fail_on_severity = [s.strip() for s in fail_on_severity.split(',')]
            if fail_on_new_only:
                exit_policy.fail_on_new_only = True
            if fail_on_tags:
                exit_policy.fail_on_tags = [t.strip() for t in fail_on_tags.split(',')]
            scanner = GitSecretScanner(
                repo_path=repo_path,
                custom_rules_path=rules_path,
                entropy_threshold=entropy_threshold,
                min_entropy_length=min_entropy_length,
                context_lines=context_lines,
                max_commits=max_commits,
                since_commit=since_commit,
                enable_entropy_scan=not no_entropy,
                baseline=baseline,
            )
            reporter = Reporter(
                output_format=output_format,
                output_file=output_file,
                repo_path=str(scanner.repo_path),
                exit_policy=exit_policy,
            )
            with click.progressbar(label='Scanning commits', length=0) as bar:
                def progress(count):
                    bar.length = count
                    bar.update(1)
                reporter = scanner.scan_repository(reporter, progress_callback=progress)
            reporter.render()
            if exit_code and exit_policy.should_fail(reporter.findings):
                sys.exit(1)
        except Exception as e:
            import traceback
            traceback.print_exc()
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    @cli.command('diff')
    @click.argument('base_ref')
    @click.argument('head_ref')
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
    @click.option('--no-entropy', is_flag=True, default=False,
                  help='Disable high-entropy string scanning')
    @click.option('--baseline', '-b', 'baseline_path', type=click.Path(dir_okay=False),
                  help='Path to baseline file for comparing results')
    @click.option('--fail-on-severity', 'fail_on_severity', type=str, default=None,
                  help='Comma-separated list of severities to fail on (e.g. critical,high). Single value acts as threshold (>= severity)')
    @click.option('--fail-on-new-only', is_flag=True, default=False,
                  help='Only fail on new findings (not existing in baseline)')
    @click.option('--fail-on-tags', 'fail_on_tags', type=str, default=None,
                  help='Comma-separated list of tags to fail on')
    @click.option('--exit-code', is_flag=True, default=False,
                  help='Exit with non-zero code if blocking secrets are found')
    def scan_diff(
        base_ref,
        head_ref,
        repo_path,
        rules_path,
        output_format,
        output_file,
        entropy_threshold,
        min_entropy_length,
        context_lines,
        no_entropy,
        baseline_path,
        fail_on_severity,
        fail_on_new_only,
        fail_on_tags,
        exit_code,
    ):
        try:
            baseline = Baseline(baseline_path) if baseline_path else None
            exit_policy = ExitPolicy()
            if fail_on_severity:
                exit_policy.fail_on_severity = [s.strip() for s in fail_on_severity.split(',')]
            if fail_on_new_only:
                exit_policy.fail_on_new_only = True
            if fail_on_tags:
                exit_policy.fail_on_tags = [t.strip() for t in fail_on_tags.split(',')]
            scanner = GitSecretScanner(
                repo_path=repo_path,
                custom_rules_path=rules_path,
                entropy_threshold=entropy_threshold,
                min_entropy_length=min_entropy_length,
                context_lines=context_lines,
                enable_entropy_scan=not no_entropy,
                baseline=baseline,
            )
            reporter = Reporter(
                output_format=output_format,
                output_file=output_file,
                repo_path=str(scanner.repo_path),
                exit_policy=exit_policy,
            )
            with click.progressbar(label=f'Scanning {base_ref}..{head_ref}', length=0) as bar:
                def progress(count):
                    bar.length = count
                    bar.update(1)
                reporter = scanner.scan_diff(base_ref, head_ref, reporter, progress_callback=progress)
            reporter.render()
            if exit_code and exit_policy.should_fail(reporter.findings):
                sys.exit(1)
        except Exception as e:
            import traceback
            traceback.print_exc()
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    @cli.group()
    def baseline():
        pass

    @baseline.command('create')
    @click.argument('repo_path', default='.')
    @click.option('--output', '-o', 'output_file', type=click.Path(dir_okay=False, writable=True),
                  default='.git-secret-baseline.json', help='Output baseline file path')
    @click.option('--rules', '-r', 'rules_path', type=click.Path(exists=True, dir_okay=False),
                  help='Path to custom rules YAML file')
    @click.option('--no-entropy', is_flag=True, default=False,
                  help='Disable high-entropy string scanning')
    @click.option('--max-commits', type=int, default=None,
                  help='Maximum number of commits to scan')
    def baseline_create(repo_path, output_file, rules_path, no_entropy, max_commits):
        try:
            scanner = GitSecretScanner(
                repo_path=repo_path,
                custom_rules_path=rules_path,
                enable_entropy_scan=not no_entropy,
                max_commits=max_commits,
            )
            baseline_obj = Baseline()
            reporter = Reporter(repo_path=str(scanner.repo_path))
            with click.progressbar(label='Scanning for baseline', length=0) as bar:
                def progress(count):
                    bar.length = count
                    bar.update(1)
                reporter = scanner.scan_repository(reporter, progress_callback=progress)
            for finding in reporter.findings:
                if finding.ignored:
                    continue
                baseline_obj.add_entry(
                    secret_value=finding.secret_value,
                    file_path=finding.file_path,
                    rule_id=finding.rule_id,
                    line_number=finding.line_number,
                    masked_value=finding.masked_value,
                    commit_sha=finding.commit_sha,
                    author=finding.author_name,
                    date=finding.commit_date,
                )
            baseline_obj.save(output_file)
            click.echo(f"Baseline created with {len(baseline_obj.entries)} entries at {output_file}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    @baseline.command('update')
    @click.argument('repo_path', default='.')
    @click.option('--baseline', '-b', 'baseline_path', type=click.Path(dir_okay=False, exists=True),
                  default='.git-secret-baseline.json', help='Baseline file to update')
    @click.option('--rules', '-r', 'rules_path', type=click.Path(exists=True, dir_okay=False),
                  help='Path to custom rules YAML file')
    @click.option('--no-entropy', is_flag=True, default=False,
                  help='Disable high-entropy string scanning')
    @click.option('--keep-resolved/--clean-resolved', default=True,
                  help='Keep resolved entries in baseline (for trend tracking) or clean them out')
    def baseline_update(repo_path, baseline_path, rules_path, no_entropy, keep_resolved):
        try:
            baseline_obj = Baseline(baseline_path)
            scanner = GitSecretScanner(
                repo_path=repo_path,
                custom_rules_path=rules_path,
                enable_entropy_scan=not no_entropy,
                baseline=baseline_obj,
            )
            reporter = Reporter(repo_path=str(scanner.repo_path))
            with click.progressbar(label='Scanning to update baseline', length=0) as bar:
                def progress(count):
                    bar.length = count
                    bar.update(1)
                reporter = scanner.scan_repository(reporter, progress_callback=progress)
            current_fps = set()
            added = 0
            for finding in reporter.findings:
                if finding.ignored:
                    continue
                fp = Baseline.compute_fingerprint(finding.secret_value, finding.file_path, finding.rule_id)
                current_fps.add(fp)
                if fp not in baseline_obj.entries:
                    baseline_obj.add_entry(
                        secret_value=finding.secret_value,
                        file_path=finding.file_path,
                        rule_id=finding.rule_id,
                        line_number=finding.line_number,
                        masked_value=finding.masked_value,
                        commit_sha=finding.commit_sha,
                        author=finding.author_name,
                        date=finding.commit_date,
                    )
                    added += 1
            if keep_resolved:
                baseline_obj.mark_resolved(current_fps)
                resolved_count = len(baseline_obj.get_resolved_entries())
                removed = 0
            else:
                removed = baseline_obj.cleanup_resolved()
                resolved_count = 0
            baseline_obj.save()
            click.echo(f"Baseline updated: {len(baseline_obj.entries)} entries "
                       f"(added: {added}, resolved: {resolved_count}, removed: {removed})")
        except Exception as e:
            import traceback
            traceback.print_exc()
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

# Allowlist - secrets matching these will be ignored in failure exit code
# They will still appear in reports with "ignored" status for audit
allowlist:
  # Path patterns to ignore (regex matched against file path)
  paths:
    - 'test_.*\\.py$'
    - '\\.example$'
    - 'fixtures/'

  # Specific commit SHAs to ignore entirely
  commits: []

  # Author names or emails to ignore
  authors: []

  # Regex patterns to match against the line content
  regexes:
    - 'example.*key'
    - 'dummy.*password'
    - 'TEST_.*SECRET'

  # Specific secret fingerprints (SHA256 of the secret value)
  # Use: echo -n "secret_value" | sha256sum
  fingerprints: []

  # Specific rule IDs to completely ignore
  rules: []
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
