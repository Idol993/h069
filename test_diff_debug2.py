import sys
sys.path.insert(0, 'd:/work/twpw/h069')

from history_walker import HistoryWalker
from pathlib import Path

repo_path = Path('d:/work/twpw/h069/test_repo2')
walker = HistoryWalker(str(repo_path))

all_commits = walker.get_all_commits()
print("All commits:", [c[:7] for c in all_commits])

base = all_commits[0]
head = all_commits[-1]
print(f"\nbase: {base[:7]}, head: {head[:7]}")

between = walker.get_commits_between(base, head)
print(f"Commits between: {[c[:7] for c in between]}")

print("\nWalking diffs:")
for diff in walker.walk_commits_range(base, head):
    print(f"  Commit {diff.commit.short_sha}: {len(diff.hunks)} hunks")
    for hunk in diff.hunks:
        print(f"    File: {hunk.file_path}")
        print(f"    New lines: {hunk.new_lines[:3]}...")
