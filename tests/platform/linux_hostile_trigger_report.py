#!/usr/bin/env python3
"""Collect local Linux hostile-environment trigger evidence.

This script uses benign self-contained probes. It does not bypass security
controls or inspect unrelated processes.
"""

from __future__ import annotations

import ctypes
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from anti_analysis import DetectionCategory, EnvironmentObservation, PassiveEnvironmentDetector  # noqa: E402


def compile_preload_probe(work_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    preload_c = work_dir / "mi_preload_probe.c"
    preload_so = work_dir / "libmi_preload_probe.so"
    probe_py = work_dir / "maps_probe.py"
    preload_c.write_text(
        textwrap.dedent(
            """
            __attribute__((visibility("default"))) int mi_preload_probe_marker(void) {
              return 0x564d50;
            }
            """
        ),
        encoding="utf-8",
    )
    probe_py.write_text(
        textwrap.dedent(
            """
            from pathlib import Path
            import os

            target = os.environ["MI_PRELOAD_PROBE"]
            maps = Path("/proc/self/maps").read_text(encoding="utf-8", errors="ignore")
            print("ld_preload_env=1" if os.environ.get("LD_PRELOAD") else "ld_preload_env=0")
            print("preload_mapped=1" if target in maps else "preload_mapped=0")
            """
        ),
        encoding="utf-8",
    )
    cc = os.environ.get("CC", "cc")
    subprocess.run([cc, "-shared", "-fPIC", str(preload_c), "-o", str(preload_so)], check=True)
    return preload_so, probe_py


def run_preload_probe(preload_so: pathlib.Path, probe_py: pathlib.Path) -> dict[str, object]:
    env = {
        **os.environ,
        "LD_PRELOAD": str(preload_so),
        "MI_PRELOAD_PROBE": str(preload_so),
    }
    proc = subprocess.run(
        [sys.executable, str(probe_py)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    lines = set(proc.stdout.splitlines())
    return {
        "signal": "ld_preload_module_mapped",
        "source": "linux_proc_maps",
        "exit_code": proc.returncode,
        "present": "ld_preload_env=1" in lines and "preload_mapped=1" in lines,
    }


def run_preload_baseline(preload_so: pathlib.Path, probe_py: pathlib.Path) -> dict[str, object]:
    env = {
        **os.environ,
        "VMP_PRELOAD_PROBE": str(preload_so),
    }
    env.pop("LD_PRELOAD", None)
    proc = subprocess.run(
        [sys.executable, str(probe_py)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    lines = set(proc.stdout.splitlines())
    return {
        "signal": "ld_preload_module_mapped",
        "source": "linux_proc_maps_baseline",
        "exit_code": proc.returncode,
        "present": "ld_preload_env=1" in lines or "preload_mapped=1" in lines,
    }


def run_tracer_probe() -> dict[str, object]:
    libc = ctypes.CDLL(None, use_errno=True)
    ptrace = libc.ptrace
    ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
    ptrace.restype = ctypes.c_long
    ptrace_traceme = 0

    code = textwrap.dedent(
        """
        import ctypes
        import pathlib

        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.ptrace(0, 0, None, None)
        tracer_pid = "0"
        for line in pathlib.Path("/proc/self/status").read_text().splitlines():
            if line.startswith("TracerPid:"):
                tracer_pid = line.split(":", 1)[1].strip()
                break
        print(f"ptrace_result={result}")
        print(f"tracer_pid={tracer_pid}")
        """
    )
    proc = subprocess.run([sys.executable, "-c", code], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tracer_pid = 0
    ptrace_result = -1
    for line in proc.stdout.splitlines():
        if line.startswith("tracer_pid="):
            tracer_pid = int(line.split("=", 1)[1])
        if line.startswith("ptrace_result="):
            ptrace_result = int(line.split("=", 1)[1])
    return {
        "signal": "tracer_pid_nonzero",
        "source": "linux_proc_status_ptrace_traceme",
        "exit_code": proc.returncode,
        "ptrace_result": ptrace_result,
        "tracer_pid": tracer_pid,
        "present": proc.returncode == 0 and ptrace_result == 0 and tracer_pid > 0,
        "scope_note": "Self-contained ptrace TRACEME probe demonstrates debugger/tracer detection plumbing; it is not non-self hardware-breakpoint evidence.",
    }


def run_tracer_baseline() -> dict[str, object]:
    code = textwrap.dedent(
        """
        import pathlib

        tracer_pid = "0"
        for line in pathlib.Path("/proc/self/status").read_text().splitlines():
            if line.startswith("TracerPid:"):
                tracer_pid = line.split(":", 1)[1].strip()
                break
        print(f"tracer_pid={tracer_pid}")
        """
    )
    proc = subprocess.run([sys.executable, "-c", code], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tracer_pid = 0
    for line in proc.stdout.splitlines():
        if line.startswith("tracer_pid="):
            tracer_pid = int(line.split("=", 1)[1])
    return {
        "signal": "tracer_pid_nonzero",
        "source": "linux_proc_status_baseline",
        "exit_code": proc.returncode,
        "tracer_pid": tracer_pid,
        "present": proc.returncode == 0 and tracer_pid > 0,
    }


def finding_json(finding) -> dict[str, object]:
    return {
        "category": finding.category.value,
        "severity": finding.severity.value,
        "signal": finding.signal,
        "source": finding.source,
        "action": finding.action,
        "confidence": finding.confidence,
        "details": dict(finding.details),
    }


def main() -> int:
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "docs/qa/reports/linux-hostile-triggers.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    detector = PassiveEnvironmentDetector()

    with tempfile.TemporaryDirectory(prefix="vmp-linux-hostile-") as tmp:
        preload_so, probe_py = compile_preload_probe(pathlib.Path(tmp))
        preload = run_preload_probe(preload_so, probe_py)
        preload_baseline = run_preload_baseline(preload_so, probe_py)
    tracer = run_tracer_probe()
    tracer_baseline = run_tracer_baseline()

    observations = []
    if preload["present"]:
        observations.append(
            EnvironmentObservation(
                DetectionCategory.INJECTION,
                str(preload["signal"]),
                True,
                str(preload["source"]),
                0.95,
                {"exit_code": str(preload["exit_code"]), "trigger_mode": "ld_preload"},
            )
        )
    if tracer["present"]:
        observations.append(
            EnvironmentObservation(
                DetectionCategory.DEBUGGER,
                str(tracer["signal"]),
                True,
                str(tracer["source"]),
                0.90,
                {
                    "exit_code": str(tracer["exit_code"]),
                    "ptrace_result": str(tracer["ptrace_result"]),
                    "tracer_pid": str(tracer["tracer_pid"]),
                    "trigger_mode": "ptrace_traceme",
                },
            )
        )
    findings = detector.evaluate(tuple(observations))
    baseline_observations = []
    if preload_baseline["present"]:
        baseline_observations.append(
            EnvironmentObservation(
                DetectionCategory.INJECTION,
                str(preload_baseline["signal"]),
                True,
                str(preload_baseline["source"]),
                0.95,
                {"exit_code": str(preload_baseline["exit_code"]), "trigger_mode": "baseline_no_ld_preload"},
            )
        )
    if tracer_baseline["present"]:
        baseline_observations.append(
            EnvironmentObservation(
                DetectionCategory.DEBUGGER,
                str(tracer_baseline["signal"]),
                True,
                str(tracer_baseline["source"]),
                0.90,
                {
                    "exit_code": str(tracer_baseline["exit_code"]),
                    "tracer_pid": str(tracer_baseline["tracer_pid"]),
                    "trigger_mode": "baseline_no_ptrace",
                },
            )
        )
    baseline_findings = detector.evaluate(tuple(baseline_observations))

    data = {
        "schema": "vmp.platform.linux_hostile_triggers.v1",
        "status": "partial" if findings else "blocked",
        "real_platform_triggers": bool(findings),
        "normal_environment_findings": len(baseline_findings),
        "triggers": {
            "ld_preload": preload,
            "tracer": tracer,
        },
        "baseline_controls": {
            "ld_preload": preload_baseline,
            "tracer": tracer_baseline,
        },
        "findings": [finding_json(finding) for finding in findings],
        "baseline_findings": [finding_json(finding) for finding in baseline_findings],
        "scope_note": "Linux-only real trigger evidence. Full hard acceptance still requires Windows hardware/memory breakpoint and DLL injection evidence plus Android root/Xposed/LSPosed/Frida/hook evidence.",
    }
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("linux hostile trigger report written")
    return 0 if findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
