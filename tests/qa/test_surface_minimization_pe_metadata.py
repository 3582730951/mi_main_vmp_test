import struct
import tempfile
import unittest
from pathlib import Path

from scripts.audit import surface_minimization_audit
from scripts.audit.scrub_pe_section_names import scrub


class SurfaceMinimizationPeMetadataTests(unittest.TestCase):
    def test_reports_printable_pe_and_coff_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample.exe"
            artifact.write_bytes(self._sample_pe_with_coff_metadata())

            observations = surface_minimization_audit.pe_metadata_observations(artifact)
            findings = surface_minimization_audit.pe_metadata_findings(observations)

        self.assertEqual(observations["status"], "observed")
        self.assertIn(".text", observations["printable_section_names"])
        self.assertTrue(observations["coff_symbol_table_present"])
        self.assertEqual(
            {finding["category"] for finding in findings},
            {
                "pe_printable_section_name",
                "pe_coff_symbol_table",
                "pe_standard_section_string",
            },
        )

    def test_scrubbed_pe_metadata_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample.exe"
            artifact.write_bytes(self._sample_pe_with_coff_metadata())

            scrub(artifact)
            data = artifact.read_bytes()
            observations = surface_minimization_audit.pe_metadata_observations(artifact)
            findings = surface_minimization_audit.pe_metadata_findings(observations)

        self.assertEqual(observations["status"], "observed")
        self.assertEqual(observations["printable_section_names"], [])
        self.assertEqual(observations["nonprintable_high_bit_section_names"], observations["section_count"])
        self.assertEqual(observations["section_name_distinct_count"], observations["section_count"])
        self.assertEqual(observations["zero_padded_section_names"], 0)
        self.assertFalse(observations["coff_symbol_table_present"])
        self.assertEqual(observations["standard_section_string_hits"], [])
        self.assertEqual(findings, [])
        self.assertNotIn(b"This program cannot be run in DOS mode", data)
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        self.assertEqual(struct.unpack_from("<I", data, pe_offset + 8)[0], 0)
        self.assertEqual(data[pe_offset + 24 + 2 : pe_offset + 24 + 4], b"\0\0")
        section_table = pe_offset + 24 + 0xF0
        self.assertTrue(all(byte >= 0x80 for byte in data[section_table : section_table + 8]))

    @staticmethod
    def _sample_pe_with_coff_metadata() -> bytes:
        data = bytearray(0x380)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x40:0x67] = b"This program cannot be run in DOS mode"
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x86, 1)
        struct.pack_into("<I", data, 0x88, 0x12345678)
        struct.pack_into("<I", data, 0x8C, 0x300)
        struct.pack_into("<I", data, 0x90, 2)
        struct.pack_into("<H", data, 0x94, 0xF0)
        optional = 0x80 + 24
        data[optional + 2 : optional + 4] = b"\x0e\x28"
        section_table = 0x80 + 24 + 0xF0
        data[section_table : section_table + 8] = b".text\0\0\0"
        struct.pack_into("<I", data, section_table + 16, 0x100)
        struct.pack_into("<I", data, section_table + 20, 0x200)
        data[0x300:0x308] = b".text\0\0\0"
        struct.pack_into("<I", data, 0x300 + 36, 4 + len(b".rdata$blob\0"))
        data[0x300 + 40 : 0x300 + 52] = b".rdata$blob\0"
        return bytes(data[: 0x300 + 52])
