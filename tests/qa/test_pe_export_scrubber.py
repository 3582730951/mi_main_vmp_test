import struct
import tempfile
import unittest
from pathlib import Path

from scripts.audit.scrub_pe_export_directory import scrub


class PeExportScrubberTests(unittest.TestCase):
    def test_removes_empty_export_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample.dll"
            artifact.write_bytes(self._sample_pe(functions=0, names=0))

            result = scrub(artifact)
            data = artifact.read_bytes()

        self.assertTrue(result["changed"])
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        data_directories = pe_offset + 24 + 112
        self.assertEqual(struct.unpack_from("<II", data, data_directories), (0, 0))
        self.assertEqual(data[0x200 : 0x200 + 40], b"\0" * 40)

    def test_refuses_non_empty_export_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample.dll"
            artifact.write_bytes(self._sample_pe(functions=1, names=1))

            with self.assertRaises(ValueError):
                scrub(artifact)

    @staticmethod
    def _sample_pe(*, functions: int, names: int) -> bytes:
        data = bytearray(0x500)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80 : 0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x84, 0x8664)
        struct.pack_into("<H", data, 0x86, 1)
        struct.pack_into("<H", data, 0x94, 0xF0)
        optional = 0x80 + 24
        struct.pack_into("<H", data, optional, 0x20B)
        data_directories = optional + 112
        struct.pack_into("<II", data, data_directories, 0x1000, 40)
        section = optional + 0xF0
        data[section : section + 8] = b".edata\0\0"
        struct.pack_into("<I", data, section + 8, 0x200)
        struct.pack_into("<I", data, section + 12, 0x1000)
        struct.pack_into("<I", data, section + 16, 0x200)
        struct.pack_into("<I", data, section + 20, 0x200)
        struct.pack_into("<II", data, 0x200 + 20, functions, names)
        return bytes(data)


if __name__ == "__main__":
    unittest.main()
