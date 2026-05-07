import struct
import tempfile
import unittest
from pathlib import Path

from scripts.audit import macho_metadata_audit


class MachoMetadataAuditTests(unittest.TestCase):
    def test_reports_macho_load_commands_and_standard_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "sample.macho"
            artifact.write_bytes(self._sample_macho())

            report = macho_metadata_audit.build_report(root, [artifact.name])
            strict_report = macho_metadata_audit.build_report(root, [artifact.name], strict=True)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["gate"], "report_only_runtime_preserving")
        scan = report["scanned_artifacts"][0]
        self.assertEqual(scan["binary_count"], 1)
        binary = scan["binaries"][0]
        self.assertEqual(binary["status"], "observed")
        self.assertIn("LC_SEGMENT_64", binary["load_commands"])
        self.assertIn("LC_SYMTAB", binary["load_commands"])
        self.assertIn("LC_DYSYMTAB", binary["load_commands"])
        self.assertIn("LC_LOAD_DYLIB", binary["load_commands"])
        self.assertIn("LC_CODE_SIGNATURE", binary["load_commands"])
        self.assertEqual(binary["segment_names"], ["__TEXT"])
        self.assertEqual(binary["section_names"], ["__TEXT,__text"])
        self.assertEqual(binary["dylibs"], ["/usr/lib/libSystem.B.dylib"])
        self.assertEqual(
            {finding["category"] for finding in scan["metadata_observed_findings"]},
            {
                "macho_symbol_table_present",
                "macho_dynamic_symbol_table_present",
                "macho_dylib_load_command",
                "macho_code_signature_present",
                "macho_standard_name_string",
            },
        )
        self.assertEqual(strict_report["status"], "fail")
        self.assertGreater(strict_report["strict_surface_findings"], 0)

    def test_scans_macho_members_inside_static_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "libsample.a"
            artifact.write_bytes(self._ar_archive("ios_adapter.o", self._sample_macho()))

            report = macho_metadata_audit.build_report(root, [artifact.name])

        self.assertEqual(report["status"], "pass")
        scan = report["scanned_artifacts"][0]
        self.assertEqual(scan["container"], "ar_archive")
        self.assertEqual(scan["binary_count"], 1)
        self.assertIn("!ios_adapter.o", scan["binaries"][0]["path"])

    def test_empty_symbol_tables_are_not_reported_as_exposed_symbols(self) -> None:
        findings = macho_metadata_audit.observed_findings(
            {
                "status": "observed",
                "file_offset": 0,
                "symtab": {"symoff": 0, "nsyms": 0, "stroff": 0, "strsize": 0},
                "dysymtab": {
                    "ilocalsym": 0,
                    "nlocalsym": 0,
                    "iextdefsym": 0,
                    "nextdefsym": 0,
                    "iundefsym": 0,
                    "nundefsym": 0,
                },
                "dylibs": [],
                "standard_name_hits": [],
            }
        )

        self.assertEqual(findings, [])

    @staticmethod
    def _sample_macho() -> bytes:
        dylib_name = b"/usr/lib/libSystem.B.dylib\0"
        dylib_cmdsize = 24 + len(dylib_name)
        dylib_cmdsize += (8 - dylib_cmdsize % 8) % 8

        segment_cmdsize = 72 + 80
        segment = bytearray(segment_cmdsize)
        struct.pack_into(
            "<II16sQQQQIIII",
            segment,
            0,
            0x19,
            segment_cmdsize,
            b"__TEXT\0\0\0\0\0\0\0\0\0\0",
            0,
            0x1000,
            0,
            0x1000,
            7,
            5,
            1,
            0,
        )
        struct.pack_into(
            "<16s16sQQIIIIIIII",
            segment,
            72,
            b"__text\0\0\0\0\0\0\0\0\0\0",
            b"__TEXT\0\0\0\0\0\0\0\0\0\0",
            0,
            0x20,
            0,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        )

        symtab = struct.pack("<IIIIII", 0x2, 24, 0x300, 2, 0x340, 0x20)
        dysymtab = struct.pack("<II18I", 0xB, 80, 0, 1, 1, 1, 2, 0, *([0] * 12))
        dylib = bytearray(dylib_cmdsize)
        struct.pack_into("<IIIIII", dylib, 0, 0xC, dylib_cmdsize, 24, 0, 0, 0)
        dylib[24 : 24 + len(dylib_name)] = dylib_name
        code_signature = struct.pack("<IIII", 0x1D, 16, 0x400, 0x80)

        commands = bytes(segment) + symtab + dysymtab + bytes(dylib) + code_signature
        header = struct.pack(
            "<IiiIIIII",
            0xFEEDFACF,
            0x0100000C,
            0,
            0x2,
            5,
            len(commands),
            0,
            0,
        )
        return header + commands + b"\0" * 0x500

    @staticmethod
    def _ar_archive(member_name: str, payload: bytes) -> bytes:
        encoded_name = member_name.encode("utf-8")
        content = encoded_name + payload
        header = (
            f"#1/{len(encoded_name)}".encode("ascii").ljust(16)
            + b"0".ljust(12)
            + b"0".ljust(6)
            + b"0".ljust(6)
            + b"100644".ljust(8)
            + str(len(content)).encode("ascii").ljust(10)
            + b"`\n"
        )
        archive = b"!<arch>\n" + header + content
        if len(content) % 2:
            archive += b"\n"
        return archive


if __name__ == "__main__":
    unittest.main()
