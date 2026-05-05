import struct
import tempfile
import unittest
from pathlib import Path

from scripts.audit import surface_minimization_audit


class SurfaceMinimizationElfMetadataTests(unittest.TestCase):
    def test_reports_elf_section_headers_and_standard_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample"
            artifact.write_bytes(self._sample_elf(section_headers=True, section_names=True))

            observations = surface_minimization_audit.elf_metadata_observations(artifact)
            findings = surface_minimization_audit.elf_metadata_findings(observations)

        self.assertEqual(observations["status"], "observed")
        self.assertTrue(observations["section_header_table_present"])
        self.assertEqual(
            {finding["category"] for finding in findings},
            {"elf_section_header_table", "elf_standard_section_string"},
        )

    def test_stripped_elf_metadata_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample"
            artifact.write_bytes(self._sample_elf(section_headers=False, section_names=False))

            observations = surface_minimization_audit.elf_metadata_observations(artifact)
            findings = surface_minimization_audit.elf_metadata_findings(observations)

        self.assertEqual(observations["status"], "observed")
        self.assertFalse(observations["section_header_table_present"])
        self.assertEqual(observations["standard_section_string_hits"], [])
        self.assertEqual(findings, [])

    @staticmethod
    def _sample_elf(*, section_headers: bool, section_names: bool) -> bytes:
        data = bytearray(0x240)
        data[:4] = b"\x7fELF"
        data[4] = 2
        data[5] = 1
        if section_headers:
            struct.pack_into("<Q", data, 40, 0x100)
            struct.pack_into("<H", data, 58, 64)
            struct.pack_into("<H", data, 60, 1)
            struct.pack_into("<H", data, 62, 0)
        if section_names:
            data[0x200:0x206] = b".text\0"
            data[0x208:0x211] = b".shstrtab"
        return bytes(data)
