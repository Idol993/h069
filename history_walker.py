import subprocess
import os
import re
from pathlib import Path
from typing import List, Dict, Optional, Generator, Tuple
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CommitInfo:
    sha: str
    short_sha: str
    author_name: str
    author_email: str
    date: datetime
    message: str
    parent_sha: Optional[str] = None
    commit_number: int = 0


@dataclass
class DiffHunk:
    file_path: str
    old_line_start: int
    new_line_start: int
    old_lines: List[str]
    new_lines: List[str]
    is_binary: bool = False


@dataclass
class DiffResult:
    commit: CommitInfo
    hunks: List[DiffHunk]


@dataclass
class FileContext:
    file_path: str
    line_number: int
    context_before: List[str]
    context_after: List[str]
    line_content: str


class HistoryWalker:
    def __init__(self, repo_path: str, max_commits: Optional[int] = None):
        self.repo_path = Path(repo_path).resolve()
        self.max_commits = max_commits
        self._git_dir = self._find_git_dir()
        self._commit_cache: Dict[str, CommitInfo] = {}
        self._commit_number_counter = 0

    def _find_git_dir(self) -> Path:
        git_dir = self.repo_path / ".git"
        if git_dir.exists():
            return git_dir.resolve()
        parent = self.repo_path.parent
        while parent != parent.parent:
            git_dir = parent / ".git"
            if git_dir.exists():
                return git_dir.resolve()
            parent = parent.parent
        raise ValueError(f"Not a git repository (or any parent directories): {self.repo_path}")

    def _run_git(self, args: List[str], env: Optional[Dict[str, str]] = None) -> str:
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        git_dir = str(self._git_dir).replace('\\', '/')
        work_tree = str(self.repo_path).replace('\\', '/')
        full_env["GIT_DIR"] = git_dir
        full_env["GIT_WORK_TREE"] = work_tree
        result = subprocess.run(
            ["git"] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=full_env,
            cwd=str(self.repo_path),
        )
        return result.stdout

    def get_all_branches(self) -> List[str]:
        output = self._run_git(["for-each-ref", "--format=%(refname)", "refs/heads/"])
        branches = [line.strip() for line in output.strip().split("\n") if line.strip()]
        return branches

    def get_all_commits(self) -> List[str]:
        args = ["rev-list", "--all", "--reverse"]
        if self.max_commits:
            args.extend(["--max-count", str(self.max_commits)])
        output = self._run_git(args)
        commits = [line.strip() for line in output.strip().split("\n") if line.strip()]
        return commits

    def get_commit_info(self, sha: str) -> CommitInfo:
        if sha in self._commit_cache:
            return self._commit_cache[sha]
        format_str = "%H|%h|%an|%ae|%aI|%s|%P"
        output = self._run_git(["show", "-s", f"--format={format_str}", sha]).strip()
        parts = output.split("|", 6)
        if len(parts) < 7:
            parts.extend([""] * (7 - len(parts)))
        full_sha, short_sha, author_name, author_email, date_str, message, parents = parts
        try:
            date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            date = datetime.now()
        parent_sha = parents.split()[0] if parents.strip() else None
        self._commit_number_counter += 1
        commit = CommitInfo(
            sha=full_sha,
            short_sha=short_sha,
            author_name=author_name,
            author_email=author_email,
            date=date,
            message=message,
            parent_sha=parent_sha,
            commit_number=self._commit_number_counter,
        )
        self._commit_cache[sha] = commit
        return commit

    def parse_diff_tree(self, commit_sha: str, parent_sha: Optional[str]) -> List[DiffHunk]:
        hunks = []
        if parent_sha is None:
            args = ["diff-tree", "-p", "--root", "--no-commit-id", "-r", commit_sha]
        else:
            args = ["diff-tree", "-p", "--no-commit-id", "-r", f"{parent_sha}..{commit_sha}"]
        output = self._run_git(args)
        if not output.strip():
            return hunks
        current_file = None
        current_hunk = None
        old_line_start = 0
        new_line_start = 0
        old_lines = []
        new_lines = []
        is_binary = False
        for line in output.split("\n"):
            if line.startswith("diff --git"):
                if current_file and not is_binary:
                    if old_lines or new_lines:
                        hunks.append(DiffHunk(
                            file_path=current_file,
                            old_line_start=old_line_start,
                            new_line_start=new_line_start,
                            old_lines=old_lines.copy(),
                            new_lines=new_lines.copy(),
                        ))
                parts = line.split(" b/")
                if len(parts) == 2:
                    current_file = parts[1]
                old_lines = []
                new_lines = []
                is_binary = False
            elif line.startswith("Binary files"):
                is_binary = True
            elif line.startswith("@@"):
                if current_file and not is_binary and (old_lines or new_lines):
                    hunks.append(DiffHunk(
                        file_path=current_file,
                        old_line_start=old_line_start,
                        new_line_start=new_line_start,
                        old_lines=old_lines.copy(),
                        new_lines=new_lines.copy(),
                    ))
                old_lines = []
                new_lines = []
                match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
                if match:
                    old_line_start = int(match.group(1))
                    new_line_start = int(match.group(3))
            elif line.startswith("---") or line.startswith("+++"):
                continue
            elif line.startswith("-"):
                old_lines.append(line[1:])
            elif line.startswith("+"):
                new_lines.append(line[1:])
            elif line.startswith(" "):
                old_lines.append(line[1:])
                new_lines.append(line[1:])
        if current_file and not is_binary and (old_lines or new_lines):
            hunks.append(DiffHunk(
                file_path=current_file,
                old_line_start=old_line_start,
                new_line_start=new_line_start,
                old_lines=old_lines.copy(),
                new_lines=new_lines.copy(),
                is_binary=is_binary,
            ))
        return hunks

    def walk_commits(self, since_commit: Optional[str] = None) -> Generator[DiffResult, None, None]:
        commits = self.get_all_commits()
        if since_commit:
            try:
                idx = commits.index(since_commit)
                commits = commits[idx:]
            except ValueError:
                pass
        for sha in commits:
            try:
                commit_info = self.get_commit_info(sha)
                hunks = self.parse_diff_tree(sha, commit_info.parent_sha)
                if hunks:
                    yield DiffResult(commit=commit_info, hunks=hunks)
            except Exception:
                continue

    def get_file_context(self, file_path: str, line_number: int, commit_sha: str, context_lines: int = 5) -> FileContext:
        try:
            output = self._run_git(["show", f"{commit_sha}:{file_path}"])
            lines = output.split("\n")
        except Exception:
            lines = []
        if not lines:
            return FileContext(
                file_path=file_path,
                line_number=line_number,
                context_before=[],
                context_after=[],
                line_content="",
            )
        idx = line_number - 1
        if idx < 0 or idx >= len(lines):
            idx = max(0, min(idx, len(lines) - 1))
        start_before = max(0, idx - context_lines)
        end_after = min(len(lines), idx + context_lines + 1)
        return FileContext(
            file_path=file_path,
            line_number=line_number,
            context_before=lines[start_before:idx],
            context_after=lines[idx + 1:end_after],
            line_content=lines[idx] if idx < len(lines) else "",
        )
