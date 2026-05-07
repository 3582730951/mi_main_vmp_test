import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from scripts.audit import reverse_tooling


class ReverseToolingTests(unittest.TestCase):
    def test_object_name_handles_binary_names(self) -> None:
        class BinaryNamed:
            name = b"\x81\x82"

        class BadString:
            def __str__(self) -> str:
                raise UnicodeDecodeError("utf-8", b"\x81", 0, 1, "invalid")

        self.assertEqual(reverse_tooling.object_name(BinaryNamed()), "\\x81\\x82")
        self.assertIn("BadString", reverse_tooling.object_name(BadString()))

    def test_lief_result_summarizes_binary_surface(self) -> None:
        class Named:
            def __init__(self, name: str) -> None:
                self.name = name

        fake_binary = types.SimpleNamespace(
            format="ELF",
            entrypoint=4096,
            sections=[Named(".text"), Named(".rodata")],
            symbols=[Named("main"), Named("helper")],
            imported_functions=[Named("puts")],
            exported_functions=[],
            libraries=["libc.so.6"],
        )
        fake_lief = types.SimpleNamespace(parse=lambda _path: fake_binary)

        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample"
            artifact.write_bytes(b"\x7fELF")
            with mock.patch.dict(sys.modules, {"lief": fake_lief}):
                with mock.patch.object(reverse_tooling, "python_module_available", return_value=True):
                    result = reverse_tooling.analyze_with_lief(artifact)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["sections"]["count"], 2)
        self.assertEqual(result["imports"]["sample"], ["puts"])
        self.assertEqual(result["exports"]["count"], 0)

    def test_capa_result_summarizes_matching_rules(self) -> None:
        completed = subprocess_result(
            0,
            json.dumps(
                {
                    "rules": {
                        "load PE": {"matches": [{"success": True}]},
                        "unused": {"matches": []},
                    },
                    "meta": {"analysis": {"format": "pe"}},
                }
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "sample.exe"
            artifact.write_bytes(b"MZ")
            with mock.patch.object(reverse_tooling, "capa_command", return_value=["capa"]):
                with mock.patch.object(reverse_tooling, "capa_rules_path", return_value="/tmp/capa-rules"):
                    with mock.patch("subprocess.run", return_value=completed):
                        result = reverse_tooling.analyze_with_capa(root, artifact)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["rules"], "/tmp/capa-rules")
        self.assertEqual(result["matched_rules"]["sample"], ["load PE"])

    def test_floss_result_summarizes_recovered_strings_without_raw_values(self) -> None:
        completed = subprocess_result(
            0,
            json.dumps(
                {
                    "strings": {
                        "static_strings": [{"string": "plain"}],
                        "stack_strings": [{"string": "VMPBC"}],
                        "tight_strings": [],
                        "decoded_strings": [{"value": "decoded"}],
                    }
                }
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "sample"
            artifact.write_bytes(b"\x7fELF")
            with mock.patch.object(reverse_tooling, "floss_command", return_value=["floss"]):
                with mock.patch("subprocess.run", return_value=completed):
                    result = reverse_tooling.analyze_with_floss(root, artifact)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["total_recovered_strings"], 3)
        self.assertEqual(result["recovered_string_counts"]["stack_strings"], 1)
        self.assertEqual(result["forbidden_recovered_hits"], ["VMPBC"])
        self.assertFalse(result["raw_values_recorded"])

    def test_radare2_result_summarizes_callgraph(self) -> None:
        functions_completed = subprocess_result(
            0,
            json.dumps(
                [
                    {"name": "entry", "offset": 0x1000, "callrefs": []},
                    {"name": "worker", "offset": 0x1010, "callrefs": []},
                ]
            ),
        )
        graph_completed = subprocess_result(
            0,
            json.dumps([{"name": "entry", "imports": ["worker"]}]),
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "sample"
            artifact.write_bytes(b"\x7fELF")
            with mock.patch.object(reverse_tooling, "radare2_command", return_value="/usr/bin/r2"):
                with mock.patch("subprocess.run", side_effect=[functions_completed, graph_completed]):
                    result = reverse_tooling.analyze_with_radare2(root, artifact)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["function_inventory"]["count"], 2)
        self.assertEqual(result["call_edges"]["sample"], [{"caller": "entry", "callee": "worker"}])
        self.assertEqual(result["callgraph_metrics"]["call_edge_count"], 1)

    def test_rizin_result_summarizes_callgraph(self) -> None:
        completed = subprocess_result(
            0,
            json.dumps(
                [
                    {
                        "name": "entry",
                        "offset": 0x1000,
                        "callrefs": [{"type": "CALL", "addr": 0x1010}],
                    },
                    {"name": "worker", "offset": 0x1010, "callrefs": []},
                ]
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "sample"
            artifact.write_bytes(b"\x7fELF")
            with mock.patch.object(reverse_tooling, "rizin_command", return_value="/usr/bin/rizin"):
                with mock.patch("subprocess.run", return_value=completed):
                    result = reverse_tooling.analyze_with_rizin(root, artifact)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["function_inventory"]["count"], 2)
        self.assertEqual(result["call_edges"]["sample"], [{"caller": "entry", "callee": "worker"}])
        self.assertEqual(result["callgraph_metrics"]["max_in_degree"], 1)

    def test_angr_result_summarizes_cfgfast_callgraph(self) -> None:
        class FakeFunction:
            def __init__(self, name: str) -> None:
                self.name = name

        class FakeCallgraph:
            def edges(self):
                return [(0x1000, 0x1010)]

        class FakeFunctions(dict):
            callgraph = FakeCallgraph()

        fake_functions = FakeFunctions(
            {
                0x1000: FakeFunction("entry"),
                0x1010: FakeFunction("worker"),
            }
        )
        fake_cfg = types.SimpleNamespace(kb=types.SimpleNamespace(functions=fake_functions))
        fake_project = types.SimpleNamespace(
            analyses=types.SimpleNamespace(CFGFast=lambda **_kwargs: fake_cfg)
        )
        fake_angr = types.SimpleNamespace(Project=lambda *_args, **_kwargs: fake_project)

        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample"
            artifact.write_bytes(b"\x7fELF")
            with mock.patch.dict(sys.modules, {"angr": fake_angr}):
                with mock.patch.object(reverse_tooling, "python_module_available", return_value=True):
                    result = reverse_tooling.analyze_with_angr(artifact)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["function_inventory"]["count"], 2)
        self.assertEqual(result["call_edges"]["sample"], [{"caller": "0x1000", "callee": "0x1010"}])
        self.assertEqual(result["callgraph_metrics"]["unique_callers"], 1)

    def test_ghidra_result_summarizes_headless_callgraph(self) -> None:
        def fake_run(args, _cwd, **_kwargs):
            output = Path(args[args.index("-postScript") + 2])
            output.write_text(
                json.dumps(
                    {
                        "functions": ["entry", "worker"],
                        "edges": [{"caller": "entry", "callee": "worker"}],
                    }
                ),
                encoding="utf-8",
            )
            return 0, "headless ok"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script_dir = root / "scripts/audit/ghidra"
            script_dir.mkdir(parents=True)
            (script_dir / "ExportCallGraph.java").write_text("// script", encoding="utf-8")
            artifact = root / "sample"
            artifact.write_bytes(b"\x7fELF")
            with mock.patch.object(reverse_tooling, "ghidra_headless_command", return_value="/opt/ghidra/support/analyzeHeadless"):
                with mock.patch.object(reverse_tooling, "run_command", side_effect=fake_run):
                    result = reverse_tooling.analyze_with_ghidra(root, artifact)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["function_inventory"]["count"], 2)
        self.assertEqual(result["call_edges"]["sample"], [{"caller": "entry", "callee": "worker"}])
        self.assertEqual(result["callgraph_metrics"]["unique_callees"], 1)

    def test_callgraph_metrics_reports_high_frequency_callees(self) -> None:
        edges = [
            {"caller": "a", "callee": "hot"},
            {"caller": "b", "callee": "hot"},
            {"caller": "c", "callee": "hot"},
            {"caller": "c", "callee": "cold"},
        ]

        metrics = reverse_tooling.callgraph_metrics(edges, hot_threshold=3)

        self.assertEqual(metrics["call_edge_count"], 4)
        self.assertEqual(metrics["max_in_degree"], 3)
        self.assertEqual(metrics["high_frequency_callees"]["sample"], [{"callee": "hot", "call_sites": 3}])

    def test_external_callgraph_consensus_aggregates_available_backends(self) -> None:
        results = [
            {
                "tool": "radare2-r2pipe",
                "status": "pass",
                "function_inventory": {"count": 2},
                "callgraph_metrics": {
                    "call_edge_count": 3,
                    "high_frequency_callees": {"sample": [{"callee": "hot", "call_sites": 3}]},
                },
            },
            {
                "tool": "angr",
                "status": "pass",
                "function_inventory": {"count": 3},
                "callgraph_metrics": {
                    "call_edge_count": 2,
                    "high_frequency_callees": {"sample": []},
                },
            },
            {"tool": "ghidra", "status": "unavailable"},
        ]

        consensus = reverse_tooling.external_callgraph_consensus(results)

        self.assertEqual(consensus["status"], "pass")
        self.assertEqual(consensus["backend_count"], 2)
        self.assertEqual(consensus["total_functions_observed"], 5)
        self.assertEqual(consensus["total_call_edges_observed"], 5)
        self.assertEqual(
            consensus["high_frequency_callee_observations"]["sample"],
            [{"tool": "radare2-r2pipe", "callee": "hot", "call_sites": 3}],
        )

    def test_collect_external_tooling_scores_callgraph_consensus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"\x7fELF")
            callgraph_result = {
                "tool": "rizin",
                "status": "pass",
                "function_inventory": {"count": 2},
                "callgraph_metrics": {
                    "call_edge_count": 1,
                    "high_frequency_callees": {"sample": []},
                },
            }
            with mock.patch.object(reverse_tooling, "analyze_with_lief", return_value={"tool": "lief", "status": "unavailable"}):
                with mock.patch.object(reverse_tooling, "analyze_with_capa", return_value={"tool": "capa", "status": "unavailable"}):
                    with mock.patch.object(reverse_tooling, "analyze_with_floss", return_value={"tool": "floss", "status": "unavailable"}):
                        with mock.patch.object(reverse_tooling, "analyze_with_radare2", return_value={"tool": "radare2-r2pipe", "status": "unavailable"}):
                            with mock.patch.object(reverse_tooling, "analyze_with_rizin", return_value=callgraph_result):
                                with mock.patch.object(reverse_tooling, "analyze_with_angr", return_value={"tool": "angr", "status": "unavailable"}):
                                    with mock.patch.object(reverse_tooling, "analyze_with_ghidra", return_value={"tool": "ghidra", "status": "unavailable"}):
                                        result = reverse_tooling.collect_external_reverse_tooling(root, artifact)

        self.assertEqual(result["callgraph_consensus"]["status"], "pass")
        self.assertEqual(result["score_breakdown"]["rizin_callgraph_inventory"], 25)
        self.assertEqual(result["score_breakdown"]["external_callgraph_consensus"], 25)

    def test_collect_external_tooling_keeps_missing_tools_non_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"not an executable")
            with mock.patch.object(reverse_tooling, "python_module_available", return_value=False):
                with mock.patch.object(reverse_tooling, "capa_command", return_value=None):
                    with mock.patch.object(reverse_tooling, "floss_command", return_value=None):
                        with mock.patch.object(reverse_tooling, "radare2_command", return_value=None):
                            with mock.patch.object(reverse_tooling, "rizin_command", return_value=None):
                                with mock.patch.object(reverse_tooling, "ghidra_headless_command", return_value=None):
                                    result = reverse_tooling.collect_external_reverse_tooling(root, artifact)

        self.assertEqual(result["available_tools"], [])
        self.assertEqual(result["score_breakdown"], {})
        self.assertEqual(result["callgraph_consensus"]["status"], "unavailable")
        self.assertTrue(all(item["status"] == "unavailable" for item in result["tool_results"]))


def subprocess_result(returncode: int, stdout: str):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout)


if __name__ == "__main__":
    unittest.main()
