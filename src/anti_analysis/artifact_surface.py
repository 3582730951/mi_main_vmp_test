"""Release artifact surface-minimization checks.

The scanner is a defensive QA helper. It reports avoidable product/VM/OLLVM
markers and protected plaintext in release artifacts while separately recording
mandatory container signatures such as ELF, PE, and APK/ZIP magic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re
from typing import Iterable, Mapping


class SurfaceCategory(str, Enum):
    PRODUCT_MARKER = "product_marker"
    VM_MARKER = "vm_marker"
    OLLVM_MARKER = "ollvm_marker"
    PROTECTED_PLAINTEXT = "protected_plaintext"
    IMPORT_RESOLVER_NAME = "import_resolver_name"


@dataclass(frozen=True)
class SurfaceFinding:
    category: SurfaceCategory
    pattern: str
    offset: int
    evidence: str


@dataclass(frozen=True)
class SurfaceScanResult:
    artifact: Path
    container: str
    mandatory_features: tuple[str, ...]
    findings: tuple[SurfaceFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings


@dataclass(frozen=True)
class ArtifactSurfacePolicy:
    forbidden_patterns: Mapping[SurfaceCategory, tuple[bytes, ...]] = field(default_factory=dict)
    max_evidence_bytes: int = 48

    @classmethod
    def default(cls) -> "ArtifactSurfacePolicy":
        return cls(
            forbidden_patterns={
                SurfaceCategory.PRODUCT_MARKER: (
                    b"VMProtect",
                    b"VMPPassPlugin",
                    b"vmp-hotspot-policy",
                    b"vmp.call.thunk",
                    b"vmp_runtime",
                    b"vmp4core",
                    b"vmp7runtime",
                    b"vmp_",
                    b".vmp",
                ),
                SurfaceCategory.VM_MARKER: (
                    b"VMPBC",
                    b"VMPSAM",
                    b"VMPIRL",
                    b"VMPBH",
                ),
                SurfaceCategory.OLLVM_MARKER: (
                    b"OLLVM",
                    b"ollvm",
                    b"obfuscator-llvm",
                ),
                SurfaceCategory.PROTECTED_PLAINTEXT: (
                    b"protected-sample-seed-v1",
                    b"alternate-sample-seed-v1",
                    b"llvm-plugin-sample-seed-v1",
                    b"authorized_sample_behavior",
                    b"CRITICAL_AUTHZ_TOKEN_SAMPLE",
                    b"https://license.sample.invalid",
                    b"Authorization:",
                    b"Bearer ",
                ),
                SurfaceCategory.IMPORT_RESOLVER_NAME: (
                    b"GetProcAddress",
                    b"LoadLibrary",
                    b"dlopen",
                    b"dlsym",
                    b"Java_",
                ),
            }
        )

    def with_patterns(self, category: SurfaceCategory, patterns: Iterable[bytes | str]) -> "ArtifactSurfacePolicy":
        updated = {key: tuple(value) for key, value in self.forbidden_patterns.items()}
        normalized = []
        for pattern in patterns:
            normalized.append(pattern.encode("utf-8") if isinstance(pattern, str) else pattern)
        updated[category] = tuple(normalized)
        return ArtifactSurfacePolicy(
            forbidden_patterns=updated,
            max_evidence_bytes=self.max_evidence_bytes,
        )

    def scan_bytes(self, artifact: Path | str, data: bytes) -> SurfaceScanResult:
        findings: list[SurfaceFinding] = []
        for category, patterns in self.forbidden_patterns.items():
            for pattern in patterns:
                if not pattern:
                    continue
                for offset in _find_all(data, pattern):
                    findings.append(
                        SurfaceFinding(
                            category=category,
                            pattern=pattern.decode("ascii", errors="backslashreplace"),
                            offset=offset,
                            evidence=_evidence(data, offset, len(pattern), self.max_evidence_bytes),
                        )
                    )
        container, mandatory = _container_features(data)
        return SurfaceScanResult(
            artifact=Path(artifact),
            container=container,
            mandatory_features=mandatory,
            findings=tuple(sorted(findings, key=lambda item: (item.offset, item.category.value, item.pattern))),
        )

    def scan_file(self, artifact: Path | str) -> SurfaceScanResult:
        path = Path(artifact)
        return self.scan_bytes(path, path.read_bytes())


def _find_all(haystack: bytes, needle: bytes) -> Iterable[int]:
    start = 0
    while True:
        offset = haystack.find(needle, start)
        if offset < 0:
            return
        yield offset
        start = offset + max(1, len(needle))


def _container_features(data: bytes) -> tuple[str, tuple[str, ...]]:
    if data.startswith(b"\x7fELF"):
        return "elf", ("elf_magic", "elf_program_headers", "elf_dynamic_sections")
    if data.startswith(b"MZ"):
        return "pe", ("mz_magic", "pe_headers", "data_directories")
    if data.startswith(b"PK\x03\x04"):
        return "zip_apk", ("zip_magic", "central_directory")
    return "opaque", ()


def _evidence(data: bytes, offset: int, length: int, max_bytes: int) -> str:
    left = max(0, offset - max_bytes // 2)
    right = min(len(data), offset + length + max_bytes // 2)
    excerpt = data[left:right]
    return re.sub(r"[^\x20-\x7e]", ".", excerpt.decode("latin1", errors="replace"))
