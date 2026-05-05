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
        data[section_table + 40 : section_table + 48] = b".rdata\0\0"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.exe"
            path.write_bytes(data)

            count = scrub(path)
            scrubbed = path.read_bytes()

        self.assertEqual(count, 2)
        self.assertNotIn(b".text", scrubbed)
        self.assertNotIn(b".rdata", scrubbed)
        self.assertEqual(scrubbed[section_table + 4 : section_table + 8], b"\0\0\0\0")


if __name__ == "__main__":
    unittest.main()
