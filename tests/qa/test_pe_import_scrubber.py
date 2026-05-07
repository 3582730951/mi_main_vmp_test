import struct
import tempfile
import unittest
from pathlib import Path

from scripts.audit.scrub_pe_import_directory import scrub


class PeImportScrubberTests(unittest.TestCase):
    def test_removes_empty_import_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample.exe"
            artifact.write_bytes(self._sample_pe(non_empty=False))

            result = scrub(artifact)
            data = artifact.read_bytes()

        self.assertTrue(result["changed"])
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        data_directories = pe_offset + 24 + 112
        self.assertEqual(struct.unpack_from("<II", data, data_directories + 8), (0, 0))
        self.assertEqual(data[0x200 : 0x200 + 40], b"\0" * 40)

    def test_refuses_non_empty_import_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample.exe"
            artifact.write_bytes(self._sample_pe(non_empty=True))

            with self.assertRaises(ValueError):
                scrub(artifact)

    @staticmethod
    def _sample_pe(*, non_empty: bool) -> bytes:
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
        struct.pack_into("<II", data, data_directories + 8, 0x1000, 40)
        section = optional + 0xF0
        data[section : section + 8] = b".idata\0\0"
        struct.pack_into("<I", data, section + 8, 0x200)
        struct.pack_into("<I", data, section + 12, 0x1000)
        struct.pack_into("<I", data, section + 16, 0x200)
        struct.pack_into("<I", data, section + 20, 0x200)
        if non_empty:
            struct.pack_into("<I", data, 0x200, 0x1234)
        return bytes(data)


if __name__ == "__main__":
    unittest.main()
