import sys
sys.path.insert(0, 'd:/work/twpw/h069')

from history_walker import HistoryWalker
from pathlib import Path

repo_path = Path('d:/work/twpw/h069/test_repo2')
walker = HistoryWalker(str(repo_path))

print("All commits in test_repo2:")
all_commits = walker.get_all_commits()
for i, c in enumerate(all_commits):
    info = walker.get_commit_info(c)
    print(f"  {i+1}. {info.short_sha} - {info.message}")

print(f"\nTotal commits: {len(all_commits)}")

if len(all_commits) >= 1:
    print("\nTesting walk_commits (full scan):")
    count = 0
    for diff in walker.walk_commits():
        count += 1
        print(f"  Commit {diff.commit.short_sha}: {len(diff.hunks)} hunks")
    print(f"Total diff results: {count}")
