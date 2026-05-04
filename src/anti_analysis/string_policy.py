"""Release artifact string scanning policy.

The scanner is a defensive acceptance helper: it finds protected terms in build
artifacts and reports policy violations. It does not transform binaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re
from typing import Iterable, Mapping, Sequence


class ProtectedStringClass(str, Enum):
    BUSINESS = "business"
    API = "api"
    JNI = "jni"
    LICENSE = "license"
    URL = "url"
    SECRET = "secret"


@dataclass(frozen=True)
class ScanFinding:
    string_class: ProtectedStringClass
    pattern: str
    offset: int
    evidence: str


@dataclass(frozen=True)
class StringScanResult:
    artifact: Path
    findings: tuple[ScanFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings


@dataclass(frozen=True)
class StringScannerPolicy:
    """Policy for strings that must not appear in release artifacts."""

    protected_patterns: Mapping[ProtectedStringClass, tuple[str, ...]] = field(default_factory=dict)
    case_sensitive: bool = False
    max_evidence_bytes: int = 48

    @classmethod
    def default(cls) -> "StringScannerPolicy":
        return cls(
            protected_patterns={
                ProtectedStringClass.API: (
                    "GetProcAddress",
                    "LoadLibrary",
                    "dlopen",
                    "dlsym",
                ),
                ProtectedStringClass.JNI: (
                    "Java_",
                    "JNI_OnLoad",
                ),
                ProtectedStringClass.LICENSE: (
                    "license_key",
                    "activation_token",
                ),
                ProtectedStringClass.URL: (
                    "http://",
                    "https://",
                ),
                ProtectedStringClass.SECRET: (
                    "BEGIN PRIVATE KEY",
                    "api_secret",
                    "client_secret",
                ),
            }
        )

    def with_patterns(
        self,
        string_class: ProtectedStringClass,
        patterns: Iterable[str],
    ) -> "StringScannerPolicy":
        updated = {key: tuple(value) for key, value in self.protected_patterns.items()}
        updated[string_class] = tuple(patterns)
        return StringScannerPolicy(
            protected_patterns=updated,
            case_sensitive=self.case_sensitive,
            max_evidence_bytes=self.max_evidence_bytes,
        )

    def scan_bytes(self, artifact: Path | str, data: bytes) -> StringScanResult:
        haystack = data if self.case_sensitive else data.lower()
        findings: list[ScanFinding] = []

        for string_class, patterns in self.protected_patterns.items():
            for pattern in patterns:
                needle = pattern.encode("utf-8", errors="ignore")
                if not needle:
                    continue
                search_for = needle if self.case_sensitive else needle.lower()
                for offset in _find_all(haystack, search_for):
                    findings.append(
                        ScanFinding(
                            string_class=string_class,
                            pattern=pattern,
                            offset=offset,
                            evidence=_evidence(data, offset, len(needle), self.max_evidence_bytes),
                        )
                    )

        return StringScanResult(Path(artifact), tuple(sorted(findings, key=lambda item: item.offset)))

    def scan_file(self, artifact: Path | str) -> StringScanResult:
        path = Path(artifact)
        return self.scan_bytes(path, path.read_bytes())

    def scan_printable_strings(self, artifact: Path | str, strings: Sequence[str]) -> StringScanResult:
        joined = "\n".join(strings).encode("utf-8", errors="ignore")
        return self.scan_bytes(artifact, joined)


def _find_all(haystack: bytes, needle: bytes) -> Iterable[int]:
    start = 0
    while True:
        offset = haystack.find(needle, start)
        if offset < 0:
            return
        yield offset
        start = offset + max(1, len(needle))


def _evidence(data: bytes, offset: int, length: int, max_bytes: int) -> str:
    left = max(0, offset - max_bytes // 2)
    right = min(len(data), offset + length + max_bytes // 2)
    excerpt = data[left:right]
    return re.sub(r"[^\x20-\x7e]", ".", excerpt.decode("latin1", errors="replace"))
