import struct
import tempfile
import unittest
from pathlib import Path

from scripts.audit.scrub_pe_section_names import scrub


class PeSectionScrubberTests(unittest.TestCase):
    def test_scrubs_printable_section_names(self) -> None:
        data = bytearray(0x300)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x86, 2)
        struct.pack_into("<H", data, 0x94, 0xF0)
        section_table = 0x80 + 24 + 0xF0
        data[section_table : section_table + 8] = b".text\0\0\0"
        struct.pack_into("<I", data, section_table + 16, 0x40)
        struct.pack_into("<I", data, section_table + 20, 0x200)
        data[section_table + 40 : section_table + 48] = b".rdata\0\0"
        struct.pack_into("<I", data, section_table + 40 + 16, 0x40)
        struct.pack_into("<I", data, section_table + 40 + 20, 0x240)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.exe"
            path.write_bytes(data)

            count = scrub(path)
            scrubbed = path.read_bytes()

        self.assertEqual(count, 2)
        self.assertNotIn(b".text", scrubbed)
        self.assertNotIn(b".rdata", scrubbed)
        self.assertTrue(all(byte >= 0x80 for byte in scrubbed[section_table : section_table + 8]))
        self.assertTrue(all(byte >= 0x80 for byte in scrubbed[section_table + 40 : section_table + 48]))

    def test_removes_trailing_coff_symbol_table(self) -> None:
        data = bytearray(0x380)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x86, 1)
        struct.pack_into("<I", data, 0x8C, 0x300)
        struct.pack_into("<I", data, 0x90, 2)
        struct.pack_into("<H", data, 0x94, 0xF0)
        section_table = 0x80 + 24 + 0xF0
        data[section_table : section_table + 8] = b".text\0\0\0"
        struct.pack_into("<I", data, section_table + 16, 0x100)
        struct.pack_into("<I", data, section_table + 20, 0x200)
        data[0x300:0x308] = b".text\0\0\0"
        struct.pack_into("<I", data, 0x300 + 36, 4 + len(b".rdata$blob\0"))
        data[0x300 + 40 : 0x300 + 52] = b".rdata$blob\0"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.exe"
            path.write_bytes(data[: 0x300 + 52])

            scrub(path)
            scrubbed = path.read_bytes()

        self.assertEqual(struct.unpack_from("<I", scrubbed, 0x8C)[0], 0)
        self.assertEqual(struct.unpack_from("<I", scrubbed, 0x90)[0], 0)
        self.assertEqual(len(scrubbed), 0x300)
        self.assertNotIn(b".text", scrubbed)
        self.assertNotIn(b".rdata", scrubbed)

    def test_randomizes_section_names_between_runs(self) -> None:
        data = bytearray(0x300)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x86, 1)
        struct.pack_into("<H", data, 0x94, 0xF0)
        section_table = 0x80 + 24 + 0xF0
        data[section_table : section_table + 8] = b".text\0\0\0"
        struct.pack_into("<I", data, section_table + 16, 0x40)
        struct.pack_into("<I", data, section_table + 20, 0x200)
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first.exe"
            second = Path(tmp) / "second.exe"
            first.write_bytes(data)
            second.write_bytes(data)

            scrub(first)
            scrub(second)
            first_name = first.read_bytes()[section_table : section_table + 8]
            second_name = second.read_bytes()[section_table : section_table + 8]

        self.assertNotEqual(first_name, second_name)
        self.assertTrue(all(byte >= 0x80 for byte in first_name))
        self.assertTrue(all(byte >= 0x80 for byte in second_name))


if __name__ == "__main__":
    unittest.main()
