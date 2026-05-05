import struct
import tempfile
import unittest
from pathlib import Path

from scripts.audit.scrub_elf_section_metadata import scrub


class ElfSectionScrubberTests(unittest.TestCase):
    def test_removes_trailing_elf64_section_metadata(self) -> None:
        data = self._elf64(section_offset=0x100, loaded_size=0x100)
        data[0x180:0x186] = b".text\0"
        data[0x188:0x191] = b".shstrtab"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample"
            path.write_bytes(data)

            result = scrub(path)
            scrubbed = path.read_bytes()

        self.assertEqual(result["elf_class"], "ELF64")
        self.assertEqual(result["scrubbed_size"], 0x100)
        self.assertEqual(struct.unpack_from("<Q", scrubbed, 40)[0], 0)
        self.assertEqual(struct.unpack_from("<H", scrubbed, 58)[0], 0)
        self.assertEqual(struct.unpack_from("<H", scrubbed, 60)[0], 0)
        self.assertEqual(struct.unpack_from("<H", scrubbed, 62)[0], 0)
        self.assertNotIn(b".text", scrubbed)
        self.assertNotIn(b".shstrtab", scrubbed)

    def test_can_preserve_file_size_while_zeroing_metadata(self) -> None:
        data = self._elf64(section_offset=0x100, loaded_size=0x100)
        data[0x180:0x186] = b".text\0"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample"
            path.write_bytes(data)

            result = scrub(path, preserve_size=True)
            scrubbed = path.read_bytes()

        self.assertEqual(result["scrubbed_size"], len(data))
        self.assertEqual(struct.unpack_from("<Q", scrubbed, 40)[0], 0)
        self.assertNotIn(b".text", scrubbed)
        self.assertEqual(scrubbed[0x100:], b"\0" * (len(data) - 0x100))

    def test_rejects_section_table_inside_loaded_bytes(self) -> None:
        data = self._elf64(section_offset=0x80, loaded_size=0x100)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample"
            path.write_bytes(data)

            with self.assertRaises(ValueError):
                scrub(path)

    @staticmethod
    def _elf64(*, section_offset: int, loaded_size: int) -> bytearray:
        data = bytearray(0x240)
        data[:4] = b"\x7fELF"
        data[4] = 2
        data[5] = 1
        struct.pack_into("<Q", data, 32, 0x40)
        struct.pack_into("<Q", data, 40, section_offset)
        struct.pack_into("<H", data, 54, 56)
        struct.pack_into("<H", data, 56, 1)
        struct.pack_into("<H", data, 58, 64)
        struct.pack_into("<H", data, 60, 2)
        struct.pack_into("<H", data, 62, 1)
        struct.pack_into("<I", data, 0x40, 1)
        struct.pack_into("<Q", data, 0x40 + 8, 0)
        struct.pack_into("<Q", data, 0x40 + 32, loaded_size)
        return data
