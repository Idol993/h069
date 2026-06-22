import subprocess
import os
import sys
from pathlib import Path

test_dir = Path("d:/work/twpw/h069/test_repo_diff")
if test_dir.exists():
    import shutil
    shutil.rmtree(test_dir)
test_dir.mkdir(parents=True, exist_ok=True)

os.chdir(str(test_dir))

subprocess.run(["git", "init"], capture_output=True)
subprocess.run(["git", "config", "user.name", "Test User"], capture_output=True)
subprocess.run(["git", "config", "user.email", "test@example.com"], capture_output=True)

Path("README.md").write_text("# Test Repo\nInitial commit\n")
subprocess.run(["git", "add", "."], capture_output=True)
subprocess.run(["git", "commit", "-m", "Initial commit"], capture_output=True)

Path("config.py").write_text('''# Config file
API_KEY = "sk-1234567890abcdef1234567890abcdef1234567890"
DEBUG = True
''')
subprocess.run(["git", "add", "."], capture_output=True)
subprocess.run(["git", "commit", "-m", "Add config with API key"], capture_output=True)

Path("db.py").write_text('''# Database config
DB_PASSWORD = "mySuperSecretPass123!"
DB_URL = "postgresql://admin:mySuperSecretPass123!@localhost:5432/mydb"
''')
subprocess.run(["git", "add", "."], capture_output=True)
subprocess.run(["git", "commit", "-m", "Add database config"], capture_output=True)

result = subprocess.run(["git", "log", "--oneline"], capture_output=True, text=True)
print("Commits:")
print(result.stdout)

os.chdir("d:/work/twpw/h069")
print("\nDone! Test repo created at:", test_dir)
