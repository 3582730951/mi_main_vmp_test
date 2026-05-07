import struct
import tempfile
import unittest
from pathlib import Path

from scripts.audit.add_pe_decoy_sections import add_decoy_sections


class PeDecoySectionsTests(unittest.TestCase):
    def test_adds_nonprintable_decoy_sections_without_moving_existing_section(self) -> None:
        data = bytearray(0x500)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x84, 0x8664)
        struct.pack_into("<H", data, 0x86, 1)
        struct.pack_into("<H", data, 0x94, 0xF0)
        optional = 0x80 + 24
        data[optional : optional + 2] = b"\x0b\x02"
        struct.pack_into("<I", data, optional + 32, 0x1000)
        struct.pack_into("<I", data, optional + 36, 0x200)
        struct.pack_into("<I", data, optional + 56, 0x2000)
        struct.pack_into("<I", data, optional + 60, 0x400)
        section_table = 0x80 + 24 + 0xF0
        data[section_table : section_table + 8] = b".text\0\0\0"
        struct.pack_into("<I", data, section_table + 8, 0x80)
        struct.pack_into("<I", data, section_table + 12, 0x1000)
        struct.pack_into("<I", data, section_table + 16, 0x200)
        struct.pack_into("<I", data, section_table + 20, 0x400)
        struct.pack_into("<I", data, section_table + 36, 0x60000020)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.exe"
            path.write_bytes(data)

            report = add_decoy_sections(path, minimum=3, maximum=3, seed="stable")
            updated = path.read_bytes()

        self.assertEqual(report["decoy_section_count"], 3)
        self.assertEqual(struct.unpack_from("<H", updated, 0x86)[0], 4)
        self.assertEqual(updated[section_table : section_table + 8], b".text\0\0\0")
        for index in range(1, 4):
            header = section_table + index * 40
            self.assertTrue(all(byte >= 0x80 for byte in updated[header : header + 8]))
            self.assertGreaterEqual(struct.unpack_from("<I", updated, header + 12)[0], 0x2000)
            self.assertGreaterEqual(struct.unpack_from("<I", updated, header + 20)[0], 0x600)


if __name__ == "__main__":
    unittest.main()
