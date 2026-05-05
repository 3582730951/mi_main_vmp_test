import tempfile
import unittest
from pathlib import Path

from scripts.audit import protected_callgraph_audit


ORIGINAL_IR = """\
define i32 @secret_hot(i32 %x) {
entry:
  ret i32 %x
}

define i32 @caller_a(i32 %x) {
entry:
  %a = call i32 @secret_hot(i32 %x)
  %b = call i32 @secret_hot(i32 %a)
  ret i32 %b
}

define i32 @caller_b(i32 %x) {
entry:
  %c = call i32 @secret_hot(i32 %x)
  ret i32 %c
}
"""

PROTECTED_IR = """\
define hidden i32 @secret_hot(i32 %x) !vmp.protect !0 !vmp.replaced !1 {
entry:
  %r = call i32 @vmp_runtime_entry_i32_i32(i8* null, i64 0, i32 %x)
  ret i32 %r
}

define i32 @caller_a(i32 %x) {
entry:
  %a = call i32 @vmp.call.thunk.1111111111111111(i32 %x)
  %b = call i32 @vmp.call.thunk.2222222222222222(i32 %a)
  ret i32 %b
}

define i32 @caller_b(i32 %x) {
entry:
  %c = call i32 @vmp.call.thunk.3333333333333333(i32 %x)
  ret i32 %c
}
"""

LOG = """\
VMPPassPlugin hotspot: function=secret_hot call_sites=3 vm_level=1
VMPPassPlugin callsite_obfuscation: rewritten_calls=3
VMPPassPlugin callsite_obfuscation: unique_thunks=3
"""

CONFIG = """\
hotspot_analysis:
  enabled: true
  call_site_threshold: 2
  hot_vm_level: 1
  defense_floor: 1
"""


class ProtectedCallgraphAuditTests(unittest.TestCase):
    def write_fixture(self, root: Path, protected_ir: str = PROTECTED_IR) -> tuple[Path, Path, Path, Path]:
        original = root / "original.ll"
        protected = root / "protected.ll"
        log = root / "plugin.log"
        config = root / "protect.yml"
        original.write_text(ORIGINAL_IR, encoding="utf-8")
        protected.write_text(protected_ir, encoding="utf-8")
        log.write_text(LOG, encoding="utf-8")
        config.write_text(CONFIG, encoding="utf-8")
        return original, protected, log, config

    def test_reports_xrefs_and_hotspot_speed_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, protected, log, config = self.write_fixture(root)

            report = protected_callgraph_audit.build_report(root, original, protected, log, config)

        self.assertEqual(report["status"], "pass")
        target = report["protected_functions"][0]
        self.assertEqual(target["original_direct_callsite_count"], 3)
        self.assertEqual(target["original_direct_callers"], {"caller_a": 2, "caller_b": 1})
        self.assertEqual(target["protected_direct_callsite_count"], 0)
        self.assertTrue(report["analysis"]["protected_xrefs_discovered"])
        self.assertTrue(report["analysis"]["high_frequency_policy_applied"])
        self.assertTrue(report["analysis"]["defense_floor_preserved"])

    def test_fails_when_direct_protected_xref_remains(self) -> None:
        leaking_ir = PROTECTED_IR.replace(
            "call i32 @vmp.call.thunk.1111111111111111",
            "call i32 @secret_hot",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, protected, log, config = self.write_fixture(root, leaking_ir)

            report = protected_callgraph_audit.build_report(root, original, protected, log, config)

        self.assertEqual(report["status"], "fail")
        self.assertFalse(report["analysis"]["direct_protected_xrefs_removed"])


if __name__ == "__main__":
    unittest.main()
