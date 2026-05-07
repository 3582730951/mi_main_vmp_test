import tempfile
import struct
import unittest
import zipfile
from pathlib import Path

from scripts.audit import platform_string_residuals


class PlatformStringResidualTests(unittest.TestCase):
    def test_apk_classifier_records_categories_without_raw_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"ABCD", compress_type=zipfile.ZIP_STORED)

            report = platform_string_residuals.analyze_apk(root, apk)

        self.assertGreaterEqual(report["total_strings"], 1)
        self.assertIn("zip_entry_name", report["category_counts"])
        self.assertFalse(report["strict_zero_string"]["strict_zero_string_compatible"])
        self.assertGreaterEqual(report["strict_zero_string"]["platform_contract_residuals"], 1)
        self.assertFalse(report["raw_values_recorded"])

    def test_android_so_classifier_identifies_required_entry_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            so = root / "liba.so"
            so.write_bytes(b"\x7fELF" + b"\0" * 80 + b"JNI_OnLoad\0ANativeActivity_onCreate\0")

            report = platform_string_residuals.analyze_android_so(root, so)

        self.assertEqual(report["category_counts"], {"android_required_entry_export": 2})

    def test_macho_classifier_identifies_dylinker_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            macho = root / "ios_min_exec"
            macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 80 + b"/usr/lib/dyld\0")

            report = platform_string_residuals.analyze_macho(root, macho)

        self.assertEqual(report["category_counts"], {"macho_load_dylinker": 1})
        self.assertEqual(report["strict_zero_string"]["platform_contract_residuals"], 1)

    def test_unknown_residuals_are_not_treated_as_platform_contract(self) -> None:
        summary = platform_string_residuals.strict_constraint_summary({"custom_plaintext": 2})

        self.assertFalse(summary["strict_zero_string_compatible"])
        self.assertEqual(summary["platform_contract_residuals"], 0)
        self.assertEqual(summary["unknown_or_avoidable_residuals"], 2)
        self.assertEqual(summary["blockers"][0]["constraint"], "unknown_or_avoidable_residual")

    def test_instruction_byte_runs_do_not_count_as_plaintext(self) -> None:
        summary = platform_string_residuals.strict_constraint_summary({"native_executable_bytes": 2})

        self.assertTrue(summary["strict_zero_string_compatible"])
        self.assertEqual(summary["instruction_byte_residuals"], 2)
        self.assertEqual(summary["unknown_or_avoidable_residuals"], 0)

    def test_apk_classifier_maps_native_payload_executable_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            so = bytearray(b"\x7fELF" + b"\x02\x01\x01" + b"\0" * 57)
            struct.pack_into("<Q", so, 0x20, 0x40)
            struct.pack_into("<H", so, 0x36, 56)
            struct.pack_into("<H", so, 0x38, 1)
            phdr = struct.pack(
                "<IIQQQQQQ",
                1,
                1,
                0x100,
                0x1000,
                0x1000,
                0x20,
                0x20,
                0x1000,
            )
            so.extend(phdr)
            so.extend(b"\0" * (0x100 - len(so)))
            so.extend(b"ABCD\0")
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/x86_64/liba.so", bytes(so), compress_type=zipfile.ZIP_STORED)

            report = platform_string_residuals.analyze_apk(root, apk)

        self.assertIn("native_executable_bytes", report["category_counts"])
        self.assertEqual(report["strict_zero_string"]["unknown_or_avoidable_residuals"], 0)


if __name__ == "__main__":
    unittest.main()
