import math
import re
from typing import List, Tuple
from dataclasses import dataclass


@dataclass
class HighEntropyMatch:
    value: str
    entropy: float
    start: int
    end: int


BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
HEX_CHARS = set('0123456789abcdefABCDEF')


def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    char_freq = {}
    for char in data:
        char_freq[char] = char_freq.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in char_freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def is_high_entropy_string(s: str, threshold: float = 4.5, min_length: int = 32) -> bool:
    if len(s) < min_length:
        return False
    return calculate_entropy(s) >= threshold


def extract_potential_secrets(content: str, threshold: float = 4.5, min_length: int = 32) -> List[HighEntropyMatch]:
    matches = []
    patterns = [
        r'[A-Za-z0-9+/=]{' + str(min_length) + r',}',
        r'[0-9a-fA-F]{' + str(min_length) + r',}',
        r'[A-Za-z0-9_\-]{' + str(min_length) + r',}',
    ]
    for pattern in patterns:
        for m in re.finditer(pattern, content):
            value = m.group()
            if is_high_entropy_string(value, threshold, min_length):
                entropy = calculate_entropy(value)
                matches.append(HighEntropyMatch(
                    value=value,
                    entropy=entropy,
                    start=m.start(),
                    end=m.end()
                ))
    seen = set()
    unique_matches = []
    for m in matches:
        key = (m.start, m.end)
        if key not in seen:
            seen.add(key)
            unique_matches.append(m)
    return unique_matches


def scan_line_for_entropy(line: str, line_num: int, threshold: float = 4.5, min_length: int = 32) -> List[Tuple[int, int, str, float]]:
    results = []
    for m in extract_potential_secrets(line, threshold, min_length):
        results.append((line_num, m.start, m.value, m.entropy))
    return results
