from typing import List, Dict, Optional
from dataclasses import dataclass, field
from history_walker import CommitInfo


@dataclass
class RevertSuggestion:
    commit_sha: str
    short_sha: str
    commit_number: int
    author: str
    email: str
    message: str
    date: str
    revert_command: str
    affected_secrets: List[str] = field(default_factory=list)
    is_merge_commit: bool = False


class Remediator:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def generate_revert_suggestion(
        self,
        commit: CommitInfo,
        secret_value: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> RevertSuggestion:
        affected_secrets = []
        if secret_value:
            masked = self._mask_secret(secret_value)
            affected_secrets.append(f"{rule_id or 'unknown'}: {masked}")
        is_merge = self._is_merge_commit(commit)
        revert_command = self._build_revert_command(commit, is_merge)
        return RevertSuggestion(
            commit_sha=commit.sha,
            short_sha=commit.short_sha,
            commit_number=commit.commit_number,
            author=commit.author_name,
            email=commit.author_email,
            message=commit.message,
            date=commit.date.isoformat(),
            revert_command=revert_command,
            affected_secrets=affected_secrets,
            is_merge_commit=is_merge,
        )

    def _mask_secret(self, secret: str, show_first: int = 4, show_last: int = 4) -> str:
        if len(secret) <= show_first + show_last:
            return "*" * len(secret)
        return secret[:show_first] + "*" * (len(secret) - show_first - show_last) + secret[-show_last:]

    def _is_merge_commit(self, commit: CommitInfo) -> bool:
        import subprocess
        try:
            result = subprocess.run(
                ["git", "rev-list", "--parents", "-n", "1", commit.sha],
                capture_output=True,
                text=True,
                cwd=self.repo_path,
            )
            parts = result.stdout.strip().split()
            return len(parts) > 2
        except Exception:
            return False

    def _build_revert_command(self, commit: CommitInfo, is_merge: bool) -> str:
        if is_merge:
            return f"git revert -m 1 {commit.sha}"
        return f"git revert {commit.sha}"

    def generate_bfg_commands(self, commit: CommitInfo, file_path: str) -> List[str]:
        return [
            f"bfg --delete-files {file_path}",
            f"bfg --replace-text replacements.txt",
            "git reflog expire --expire=now --all && git gc --prune=now --aggressive",
        ]

    def generate_filter_branch_command(self, secret_value: str) -> str:
        escaped = secret_value.replace("'", "'\\''")
        return (
            f"git filter-branch --force --index-filter "
            f"'git rm --cached --ignore-unmatch -r .' "
            f"--prune-empty --tag-name-filter cat -- --all"
        )
