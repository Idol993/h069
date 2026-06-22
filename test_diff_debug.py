import sys
sys.path.insert(0, 'd:/work/twpw/h069')

from history_walker import HistoryWalker
from pathlib import Path

repo_path = Path('d:/work/twpw/h069/test_repo_diff')
walker = HistoryWalker(str(repo_path))

print("All commits:")
all_commits = walker.get_all_commits()
for i, c in enumerate(all_commits):
    info = walker.get_commit_info(c)
    print(f"  {i+1}. {info.short_sha} - {info.message}")

print(f"\nTotal commits: {len(all_commits)}")

if len(all_commits) >= 3:
    base = all_commits[0]
    head = all_commits[-1]
    print(f"\nTesting get_commits_between({base[:7]}.., {head[:7]})")
    between = walker.get_commits_between(base, head)
    print(f"Found {len(between)} commits between base and head")
    for c in between:
        info = walker.get_commit_info(c)
        print(f"  - {info.short_sha} - {info.message}")

print("\nTesting walk_commits_range:")
count = 0
for diff in walker.walk_commits_range(all_commits[0], all_commits[-1]):
    count += 1
    print(f"  Commit {diff.commit.short_sha}: {len(diff.hunks)} hunks")
    for hunk in diff.hunks:
        print(f"    File: {hunk.file_path}")
print(f"Total diff results: {count}")
