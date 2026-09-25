"""Diagnostic data structures and rendering.

Rendering is styled after compiler output on purpose: a header with
file:line:column, the source line itself, and a caret span underneath it.
Pointing at the exact characters is the whole point of this project --
"password too weak" is useless, "these six repeated digits are the
problem" is not.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str  # "error" | "warning"
    message: str
    start: int  # 0-indexed column into the password, inclusive
    end: int    # 0-indexed column into the password, exclusive

    def width(self) -> int:
        return max(self.end - self.start, 1)


@dataclass
class Report:
    password_length: int
    findings: list = field(default_factory=list)
    score: int = 0  # 0 (very weak) .. 4 (very strong)

    def errors(self):
        return [f for f in self.findings if f.severity == "error"]

    def is_acceptable(self) -> bool:
        return not self.errors()


def render_finding(finding: Finding, source: str, line_no: int = 1, filename: str = "<password>") -> str:
    col = finding.start + 1  # header columns are 1-indexed, like every other compiler
    header = f"{filename}:{line_no}:{col}: {finding.severity} [{finding.code}]: {finding.message}"
    gutter = str(line_no)
    pad = " " * len(gutter)
    caret_line = " " * finding.start + "^" * finding.width()
    return (
        f"{header}\n"
        f"{pad} |\n"
        f"{gutter} | {source}\n"
        f"{pad} | {caret_line}"
    )
