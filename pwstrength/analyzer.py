"""Core password strength analysis.

The rule set is intentionally small for now: length, a short list of known-bad
passwords, repeated character runs, sequential runs (abcd, 4321), and keyboard-
adjacent runs (qwerty, asdf). Each rule reports the exact character range it
objects to, so a diagnostic can point at that range directly instead of
leaving the caller to guess which part of a long password is the problem.
"""

import string

from .diagnostics import Finding, Report

MIN_LENGTH = 8
MIN_RUN_LENGTH = 4

# A handful of passwords that show up at the top of every leaked-password
# list. Deliberately short -- swapping in a real breach corpus is later work,
# not something to fake here.
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "letmein",
    "111111", "iloveyou", "admin", "welcome", "monkey",
}

_KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

_KEYBOARD_ADJACENCY: dict[str, set[str]] = {}
for _row in _KEYBOARD_ROWS:
    for _a, _b in zip(_row, _row[1:]):
        _KEYBOARD_ADJACENCY.setdefault(_a, set()).add(_b)
        _KEYBOARD_ADJACENCY.setdefault(_b, set()).add(_a)


def _find_repeated_runs(password: str) -> list[Finding]:
    findings = []
    i = 0
    n = len(password)
    while i < n:
        j = i
        while j + 1 < n and password[j + 1] == password[i]:
            j += 1
        run_length = j - i + 1
        if run_length >= MIN_RUN_LENGTH:
            findings.append(Finding(
                code="PW003",
                severity="warning",
                message=f"{run_length} repeated '{password[i]}' characters in a row reduce entropy",
                start=i,
                end=j + 1,
            ))
        i = j + 1
    return findings


def _is_sequential_pair(a: str, b: str) -> bool:
    diff = ord(b.lower()) - ord(a.lower())
    return diff == 1 or diff == -1


def _find_sequential_runs(password: str) -> list[Finding]:
    findings = []
    n = len(password)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and _is_sequential_pair(password[j], password[j + 1]):
            j += 1
        run_length = j - i + 1
        if run_length >= MIN_RUN_LENGTH:
            findings.append(Finding(
                code="PW004",
                severity="warning",
                message=f"'{password[i:j + 1]}' is a sequential run, easy to guess",
                start=i,
                end=j + 1,
            ))
            i = j + 1
        else:
            i += 1
    return findings


def _find_keyboard_runs(password: str) -> list[Finding]:
    findings = []
    lowered = password.lower()
    n = len(lowered)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and lowered[j + 1] in _KEYBOARD_ADJACENCY.get(lowered[j], ()):
            j += 1
        run_length = j - i + 1
        if run_length >= MIN_RUN_LENGTH:
            findings.append(Finding(
                code="PW005",
                severity="warning",
                message=f"'{password[i:j + 1]}' follows the keyboard layout, easy to guess",
                start=i,
                end=j + 1,
            ))
            i = j + 1
        else:
            i += 1
    return findings


def _character_classes(password: str) -> int:
    classes = 0
    if any(c in string.ascii_lowercase for c in password):
        classes += 1
    if any(c in string.ascii_uppercase for c in password):
        classes += 1
    if any(c in string.digits for c in password):
        classes += 1
    if any(c not in string.ascii_letters + string.digits for c in password):
        classes += 1
    return classes


def _score(password: str, findings: list[Finding]) -> int:
    if not password:
        return 0
    score = 1
    if len(password) >= MIN_LENGTH:
        score += 1
    if len(password) >= 12:
        score += 1
    if _character_classes(password) >= 3:
        score += 1
    score -= sum(2 for f in findings if f.severity == "error")
    score -= sum(1 for f in findings if f.severity == "warning")
    return max(0, min(4, score))


def analyze(password: str) -> Report:
    findings = []

    if len(password) < MIN_LENGTH:
        findings.append(Finding(
            code="PW001",
            severity="error",
            message=f"password is {len(password)} characters, minimum is {MIN_LENGTH}",
            start=0,
            end=max(len(password), 1),
        ))

    if password.lower() in COMMON_PASSWORDS:
        findings.append(Finding(
            code="PW002",
            severity="error",
            message="this is one of the most common passwords in use, it will be guessed instantly",
            start=0,
            end=len(password),
        ))

    findings.extend(_find_repeated_runs(password))
    findings.extend(_find_sequential_runs(password))
    findings.extend(_find_keyboard_runs(password))
    findings.sort(key=lambda f: f.start)

    return Report(
        password_length=len(password),
        findings=findings,
        score=_score(password, findings),
    )
