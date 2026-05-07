import unittest
from pathlib import Path

from scripts.audit import surface_minimization_audit


class SurfaceMinimizationDynamicSurfaceTests(unittest.TestCase):
    def test_printable_string_observations_do_not_record_raw_values(self) -> None:
        observations = surface_minimization_audit.printable_string_observations(b"\x00ABCD\x00xyz\x00WXYZ123")

        self.assertEqual(observations["count"], 2)
        self.assertEqual(observations["max_length"], 7)
        self.assertIsNotNone(observations["sha256"])
        self.assertFalse(observations["raw_values_recorded"])

    def test_pe_printable_string_observations_are_classified_by_section(self) -> None:
        observations = surface_minimization_audit.pe_printable_string_section_observations(fake_pe_with_printable_runs())

        self.assertEqual(observations["total"], 2)
        self.assertEqual(observations["executable_section_strings"], 1)
        self.assertEqual(observations["non_executable_section_strings"], 1)
        self.assertEqual(observations["unknown_section_strings"], 0)
        self.assertFalse(observations["raw_values_recorded"])

    def test_allows_only_fixed_windows_runtime_and_console_demo_imports(self) -> None:
        observations = {
            "status": "observed",
            "export_directory_present": False,
            "tls_directory_present": False,
            "imports": [
                {"dll": "KERNEL32.dll", "name": "ExitProcess"},
                {"dll": "KERNEL32.dll", "name": "GetStdHandle"},
                {"dll": "KERNEL32.dll", "name": "ReadFile"},
                {"dll": "KERNEL32.dll", "name": "WriteFile"},
            ],
        }

        findings = surface_minimization_audit.pe_dynamic_surface_findings(observations)

        self.assertEqual(findings, [])

    def test_reports_pe_export_tls_and_disallowed_imports(self) -> None:
        observations = {
            "status": "observed",
            "export_directory_present": True,
            "import_directory_present": True,
            "import_count": 1,
            "tls_directory_present": True,
            "imports": [
                {"dll": "KERNEL32.dll", "name": "ExitProcess"},
                {"dll": "USER32.dll", "name": "MessageBoxA"},
            ],
        }

        findings = surface_minimization_audit.pe_dynamic_surface_findings(observations)

        self.assertEqual(
            {finding["category"] for finding in findings},
            {"pe_export_directory", "pe_tls_directory", "pe_disallowed_import"},
        )

    def test_reports_empty_pe_import_directory(self) -> None:
        observations = {
            "status": "observed",
            "export_directory_present": False,
            "import_directory_present": True,
            "import_count": 0,
            "tls_directory_present": False,
            "imports": [],
        }

        findings = surface_minimization_audit.pe_dynamic_surface_findings(observations)

        self.assertEqual([finding["category"] for finding in findings], ["pe_empty_import_directory"])

    def test_reports_elf_dynamic_imports_and_exports(self) -> None:
        observations = {
            "status": "observed",
            "import_count": 1,
            "export_count": 1,
            "import_names": ["puts"],
            "export_names": ["protected_entry"],
        }

        findings = surface_minimization_audit.elf_dynamic_surface_findings(observations)

        self.assertEqual(
            {finding["category"] for finding in findings},
            {"elf_dynamic_import", "elf_dynamic_export"},
        )

    def test_surface_report_declares_windows_api_minimization_without_direct_syscalls(self) -> None:
        report = surface_minimization_audit.scan(Path(__file__).resolve().parents[2], [])

        policy = report["syscall_policy"]
        self.assertEqual(policy["windows_release_io_policy"], "minimal_fixed_kernel32_console_api_for_visible_demo")
        self.assertFalse(policy["windows_direct_syscalls_enabled"])
        self.assertFalse(policy["generic_syscall_resolver_allowed"])
        self.assertTrue(policy["api_call_minimization"]["stdout_stdin_handles_cached"])
        self.assertTrue(policy["api_call_minimization"]["writefile_calls_batched"])

def fake_pe_with_printable_runs() -> bytes:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    data[pe_offset + 4:pe_offset + 6] = (0x8664).to_bytes(2, "little")
    data[pe_offset + 6:pe_offset + 8] = (2).to_bytes(2, "little")
    data[pe_offset + 20:pe_offset + 22] = (0).to_bytes(2, "little")
    section_offset = pe_offset + 24
    write_section(data, section_offset, b"\x81\x93\xa5\xb7", 0x200, 0x200, 0x60000020)
    write_section(data, section_offset + 40, b"\x82\x94\xa6\xb8", 0x200, 0x400, 0xC0000040)
    data[0x210:0x215] = b"CODE!"
    data[0x410:0x415] = b"DATA!"
    return bytes(data)


def write_section(data: bytearray, offset: int, name: bytes, raw_size: int, raw_pointer: int, characteristics: int) -> None:
    data[offset:offset + 8] = name.ljust(8, b"\0")
    data[offset + 16:offset + 20] = raw_size.to_bytes(4, "little")
    data[offset + 20:offset + 24] = raw_pointer.to_bytes(4, "little")
    data[offset + 36:offset + 40] = characteristics.to_bytes(4, "little")


if __name__ == "__main__":
    unittest.main()
