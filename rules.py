import re
import os
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Pattern
from dataclasses import dataclass, field

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class Rule:
    id: str
    description: str
    regex: Pattern
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    entropy_check: bool = False
    secret_group: Optional[int] = None


@dataclass
class RuleMatch:
    rule: Rule
    value: str
    start: int
    end: int
    line_number: int
    entropy: Optional[float] = None


@dataclass
class Allowlist:
    paths: List[Pattern] = field(default_factory=list)
    commits: List[str] = field(default_factory=list)
    authors: List[str] = field(default_factory=list)
    regexes: List[Pattern] = field(default_factory=list)
    fingerprints: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)

    def is_allowed(
        self,
        secret_value: str,
        file_path: str,
        commit_sha: str = "",
        author: str = "",
        rule_id: str = "",
        line_content: str = "",
    ) -> bool:
        if not self.paths and not self.commits and not self.authors and not self.regexes and not self.fingerprints and not self.rules:
            return False
        if rule_id and rule_id in self.rules:
            return True
        if commit_sha and commit_sha in self.commits:
            return True
        if author and author in self.authors:
            return True
        fingerprint = hashlib.sha256(secret_value.encode()).hexdigest()
        if fingerprint in self.fingerprints:
            return True
        if file_path:
            for pattern in self.paths:
                if pattern.search(file_path):
                    return True
        if line_content:
            for pattern in self.regexes:
                if pattern.search(line_content):
                    return True
        return False


BUILTIN_RULES = [
    {
        "id": "aws-secret-access-key",
        "description": "AWS Secret Access Key",
        "regex": r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "critical",
        "tags": ["aws", "secret-key"],
        "entropy_check": True,
        "secret_group": 1,
    },
    {
        "id": "aws-access-key-id",
        "description": "AWS Access Key ID",
        "regex": r"(?i)aws[_-]?access[_-]?key[_-]?id['\"]?\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?",
        "severity": "high",
        "tags": ["aws", "access-key"],
        "secret_group": 1,
    },
    {
        "id": "private-key-rsa",
        "description": "RSA Private Key",
        "regex": r"-----BEGIN (RSA|OPENSSH|PGP|EC|DSA) PRIVATE KEY-----",
        "severity": "critical",
        "tags": ["private-key", "rsa"],
    },
    {
        "id": "private-key-putty",
        "description": "PuTTY Private Key",
        "regex": r"PuTTY-User-Key-File-2:",
        "severity": "critical",
        "tags": ["private-key", "putty"],
    },
    {
        "id": "generic-api-key",
        "description": "Generic API Key",
        "regex": r"(?i)(api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        "severity": "high",
        "tags": ["api-key", "generic"],
        "entropy_check": True,
        "secret_group": 2,
    },
    {
        "id": "database-connection-string",
        "description": "Database Connection String",
        "regex": r"(?i)(mysql|postgresql|postgres|mongodb|redis|mssql|oracle)://[^\s\"'>]+",
        "severity": "critical",
        "tags": ["database", "connection-string"],
    },
    {
        "id": "jwt-token",
        "description": "JSON Web Token (JWT)",
        "regex": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "severity": "high",
        "tags": ["jwt", "token"],
    },
    {
        "id": "github-token",
        "description": "GitHub Personal Access Token",
        "regex": r"(?i)gh[pousr]_[A-Za-z0-9]{36}",
        "severity": "high",
        "tags": ["github", "token"],
    },
    {
        "id": "slack-token",
        "description": "Slack Token",
        "regex": r"(?i)(xox[baprs]-[A-Za-z0-9]{10,48})",
        "severity": "high",
        "tags": ["slack", "token"],
        "secret_group": 1,
    },
    {
        "id": "google-api-key",
        "description": "Google API Key",
        "regex": r"AIza[0-9A-Za-z_\-]{35}",
        "severity": "high",
        "tags": ["google", "api-key"],
    },
    {
        "id": "stripe-api-key",
        "description": "Stripe API Key",
        "regex": r"(?i)sk_(test|live)_[0-9A-Za-z]{24,}",
        "severity": "critical",
        "tags": ["stripe", "api-key"],
    },
    {
        "id": "twilio-api-key",
        "description": "Twilio API Key",
        "regex": r"(?i)SK[0-9a-fA-F]{32}",
        "severity": "high",
        "tags": ["twilio", "api-key"],
    },
    {
        "id": "mailchimp-api-key",
        "description": "Mailchimp API Key",
        "regex": r"(?i)[0-9a-f]{32}-us[0-9]{1,2}",
        "severity": "high",
        "tags": ["mailchimp", "api-key"],
    },
    {
        "id": "password-in-url",
        "description": "Password in URL",
        "regex": r"(?i)[a-z][a-z0-9+.-]*://[^:\s\"'>]+:([^@\s\"'>]+)@",
        "severity": "critical",
        "tags": ["password", "url"],
        "secret_group": 1,
    },
    {
        "id": "hardcoded-password",
        "description": "Hardcoded Password",
        "regex": r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^'\"]{6,})['\"]?",
        "severity": "high",
        "tags": ["password", "hardcoded"],
        "entropy_check": True,
        "secret_group": 2,
    },
]


def compile_rule(rule_dict: Dict) -> Rule:
    regex = re.compile(rule_dict["regex"])
    return Rule(
        id=rule_dict["id"],
        description=rule_dict["description"],
        regex=regex,
        severity=rule_dict.get("severity", "medium"),
        tags=rule_dict.get("tags", []),
        entropy_check=rule_dict.get("entropy_check", False),
        secret_group=rule_dict.get("secret_group"),
    )


def load_builtin_rules() -> List[Rule]:
    return [compile_rule(r) for r in BUILTIN_RULES]


def load_rules_from_yaml(filepath: str) -> List[Rule]:
    if yaml is None:
        raise ImportError("PyYAML is required to load YAML rule files. Install with: pip install pyyaml")
    path = Path(filepath)
    if not path.exists():
        return []
    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}
    rules_data = data.get("rules", [])
    rules = []
    for rule_data in rules_data:
        if "id" in rule_data and "regex" in rule_data:
            if "description" not in rule_data:
                rule_data["description"] = rule_data["id"]
            rules.append(compile_rule(rule_data))
    return rules


def load_allowlist_from_yaml(filepath: str) -> Allowlist:
    if yaml is None:
        return Allowlist()
    path = Path(filepath)
    if not path.exists():
        return Allowlist()
    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}
    allowlist_data = data.get("allowlist", {})
    if not allowlist_data:
        return Allowlist()
    paths = [re.compile(p) for p in allowlist_data.get("paths", [])]
    commits = allowlist_data.get("commits", [])
    authors = allowlist_data.get("authors", [])
    regexes = [re.compile(r) for r in allowlist_data.get("regexes", [])]
    fingerprints = allowlist_data.get("fingerprints", [])
    rules = allowlist_data.get("rules", [])
    return Allowlist(
        paths=paths,
        commits=commits,
        authors=authors,
        regexes=regexes,
        fingerprints=fingerprints,
        rules=rules,
    )


def get_default_rule_paths(repo_path: Optional[str] = None) -> List[str]:
    paths = []
    if repo_path:
        repo_config = Path(repo_path) / ".gitleaks.yaml"
        if repo_config.exists():
            paths.append(str(repo_config.resolve()))
    cwd = Path.cwd()
    if repo_path:
        cwd_config = cwd / ".gitleaks.yaml"
        if cwd_config.exists() and str(cwd_config.resolve()) not in [str(Path(p).resolve()) for p in paths]:
            paths.append(str(cwd_config.resolve()))
    else:
        project_config = cwd / ".gitleaks.yaml"
        if project_config.exists():
            paths.append(str(project_config))
    home = Path.home()
    user_config = home / ".gitleaks.yaml"
    if user_config.exists():
        paths.append(str(user_config))
    return paths


def load_all_rules(custom_path: Optional[str] = None, repo_path: Optional[str] = None) -> List[Rule]:
    rules = load_builtin_rules()
    paths = get_default_rule_paths(repo_path)
    if custom_path:
        paths.insert(0, custom_path)
    for path in paths:
        try:
            custom_rules = load_rules_from_yaml(path)
            existing_ids = {r.id for r in rules}
            for r in custom_rules:
                if r.id not in existing_ids:
                    rules.append(r)
        except Exception:
            pass
    return rules


def load_all_allowlists(custom_path: Optional[str] = None, repo_path: Optional[str] = None) -> Allowlist:
    combined = Allowlist()
    paths = get_default_rule_paths(repo_path)
    if custom_path:
        paths.insert(0, custom_path)
    for path in paths:
        try:
            al = load_allowlist_from_yaml(path)
            combined.paths.extend(al.paths)
            combined.commits.extend(al.commits)
            combined.authors.extend(al.authors)
            combined.regexes.extend(al.regexes)
            combined.fingerprints.extend(al.fingerprints)
            combined.rules.extend(al.rules)
        except Exception:
            pass
    return combined


def match_rules(content: str, line_number: int, rules: List[Rule]) -> List[RuleMatch]:
    matches = []
    for rule in rules:
        for m in rule.regex.finditer(content):
            if rule.secret_group is not None:
                try:
                    value = m.group(rule.secret_group)
                    start = m.start(rule.secret_group)
                    end = m.end(rule.secret_group)
                except IndexError:
                    value = m.group()
                    start = m.start()
                    end = m.end()
            else:
                value = m.group()
                start = m.start()
                end = m.end()
            matches.append(RuleMatch(
                rule=rule,
                value=value,
                start=start,
                end=end,
                line_number=line_number,
            ))
    return matches
