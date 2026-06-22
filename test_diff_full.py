import sys
sys.path.insert(0, 'd:/work/twpw/h069')

from scanner import GitSecretScanner
from reporter import Reporter
from baseline import Baseline
from pathlib import Path

repo_path = Path('d:/work/twpw/h069/test_repo2')

print("=== Full scan (for reference) ===")
scanner = GitSecretScanner(
    repo_path=str(repo_path),
    enable_entropy_scan=False,
)
reporter = Reporter(output_format='json', repo_path=str(repo_path))
reporter = scanner.scan_repository(reporter)
import json
data = json.loads(reporter.render_json())
print(f"Full scan findings: {data['summary']['total_active']} active, {data['summary']['total_ignored']} ignored")
print(f"  by severity: {data['summary']['by_severity']}")

print("\n=== Diff scan (commit 1 to commit 3) ===")
all_commits = scanner.walker.get_all_commits()
print(f"Commits: {[c[:7] for c in all_commits]}")

scanner2 = GitSecretScanner(
    repo_path=str(repo_path),
    enable_entropy_scan=False,
)
reporter2 = Reporter(output_format='json', repo_path=str(repo_path))
reporter2 = scanner2.scan_diff(all_commits[0], all_commits[-1], reporter2)
data2 = json.loads(reporter2.render_json())
print(f"Diff scan findings: {data2['summary']['total_active']} active")

print("\n=== Diff scan (commit 2 to commit 3) ===")
scanner3 = GitSecretScanner(
    repo_path=str(repo_path),
    enable_entropy_scan=False,
)
reporter3 = Reporter(output_format='json', repo_path=str(repo_path))
reporter3 = scanner3.scan_diff(all_commits[1], all_commits[-1], reporter3)
data3 = json.loads(reporter3.render_json())
print(f"Diff scan findings (commit 2-3): {data3['summary']['total_active']} active")

print("\nAll diff scans completed successfully!")
