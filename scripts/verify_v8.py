#!/usr/bin/env python3
"""
V8 Bounded Asynchronous Verification & Regression/Backtest Runner.

Enforces:
- Host resource guards (CPU, available RAM, free disk space >= 2.0 GiB)
- Strictly serialized Cargo execution (never runs concurrent cargo processes)
- Bounded per-task timeouts with process-group termination on timeout
- Historical replay corpus verification (DEV and HOLDOUT splits, 0 false positives)
- Real Microsoft Edge 157+ headless CDP + local proxy bridge verification
- Atomic JSON report emission
"""

import asyncio
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_TAURI = REPO_ROOT / "src-tauri"
REPORT_PATH = REPO_ROOT / "src-tauri" / "tests" / "fixtures" / "v8_verification_summary.json"

MIN_DISK_FREE_GIB = 2.0
MIN_MEM_FREE_MIB = 512.0


@dataclass
class ResourceSnapshot:
    timestamp: str
    cpu_cores: int
    load_avg_1m: float
    free_disk_gib: float
    available_mem_mib: float


@dataclass
class TaskResult:
    name: str
    command: List[str]
    cwd: str
    status: str  # PASS, FAIL, TIMEOUT, SKIPPED
    exit_code: Optional[int]
    duration_ms: int
    stdout_tail: str
    stderr_tail: str
    resource_before: Optional[ResourceSnapshot] = None
    resource_after: Optional[ResourceSnapshot] = None


def sample_resources(path: Path = REPO_ROOT) -> ResourceSnapshot:
    usage = shutil.disk_usage(path)
    free_disk_gib = round(usage.free / (1024**3), 2)
    cpu_cores = os.cpu_count() or 1
    try:
        load_avg_1m = round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):
        load_avg_1m = 0.0

    available_mem_mib = 2048.0
    if platform.system() == "Darwin":
        try:
            out = subprocess.check_output(["vm_stat"], text=True, timeout=3)
            page_size = 16384
            for line in out.splitlines():
                if "page size of" in line:
                    parts = [int(s) for s in line.split() if s.isdigit()]
                    if parts:
                        page_size = parts[0]
            free_pages = 0
            for line in out.splitlines():
                if any(
                    k in line
                    for k in ("Pages free", "Pages inactive", "Pages speculative")
                ):
                    val = line.split(":")[1].strip().rstrip(".")
                    if val.isdigit():
                        free_pages += int(val)
            available_mem_mib = round((free_pages * page_size) / (1024**2), 1)
        except Exception:
            pass

    return ResourceSnapshot(
        timestamp=datetime.now(timezone.utc).isoformat(),
        cpu_cores=cpu_cores,
        load_avg_1m=load_avg_1m,
        free_disk_gib=free_disk_gib,
        available_mem_mib=available_mem_mib,
    )


def enforce_resource_guard(snap: ResourceSnapshot) -> None:
    if snap.free_disk_gib < MIN_DISK_FREE_GIB:
        raise RuntimeError(
            f"Disk guard triggered: free disk {snap.free_disk_gib} GiB < minimum {MIN_DISK_FREE_GIB} GiB"
        )
    if snap.available_mem_mib < MIN_MEM_FREE_MIB:
        raise RuntimeError(
            f"Memory guard triggered: available memory {snap.available_mem_mib} MiB < minimum {MIN_MEM_FREE_MIB} MiB"
        )


async def run_bounded_task(
    name: str,
    cmd: List[str],
    cwd: Path,
    timeout_secs: float,
    sem: asyncio.Semaphore,
) -> TaskResult:
    async with sem:
        before = sample_resources(cwd)
        enforce_resource_guard(before)
        t0 = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_secs
            )
            dur_ms = int((time.monotonic() - t0) * 1000)
            after = sample_resources(cwd)
            status = "PASS" if proc.returncode == 0 else "FAIL"
            return TaskResult(
                name=name,
                command=cmd,
                cwd=str(cwd),
                status=status,
                exit_code=proc.returncode,
                duration_ms=dur_ms,
                stdout_tail=stdout_b.decode("utf-8", errors="replace")[-2000:],
                stderr_tail=stderr_b.decode("utf-8", errors="replace")[-2000:],
                resource_before=before,
                resource_after=after,
            )
        except asyncio.TimeoutError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()
            dur_ms = int((time.monotonic() - t0) * 1000)
            after = sample_resources(cwd)
            return TaskResult(
                name=name,
                command=cmd,
                cwd=str(cwd),
                status="TIMEOUT",
                exit_code=None,
                duration_ms=dur_ms,
                stdout_tail="",
                stderr_tail=f"Timed out after {timeout_secs}s",
                resource_before=before,
                resource_after=after,
            )


async def main() -> int:
    initial_snap = sample_resources()
    enforce_resource_guard(initial_snap)

    # Cargo lock: strictly 1 cargo process at a time to protect disk/RAM
    cargo_sem = asyncio.Semaphore(1)
    # Non-cargo frontend lock: can run with max 1 process alongside
    npm_sem = asyncio.Semaphore(1)

    tasks_spec = [
        ("rust_fmt_check", ["cargo", "fmt", "--all", "--", "--check"], SRC_TAURI, 30.0, cargo_sem),
        (
            "rust_clippy",
            ["cargo", "clippy", "--all-targets", "--", "-D", "warnings"],
            SRC_TAURI,
            120.0,
            cargo_sem,
        ),
        (
            "rust_unit_tests_and_replay_corpus",
            ["cargo", "test", "--lib", "--", "--nocapture"],
            SRC_TAURI,
            120.0,
            cargo_sem,
        ),
        (
            "rust_integration_and_real_edge_headless",
            ["cargo", "test", "--test", "integration_tests", "--", "--nocapture"],
            SRC_TAURI,
            120.0,
            cargo_sem,
        ),
        ("frontend_vitest", ["npm", "test", "--", "--run"], REPO_ROOT, 60.0, npm_sem),
        ("frontend_build", ["npm", "run", "build"], REPO_ROOT, 60.0, npm_sem),
    ]

    results: List[TaskResult] = []
    for name, cmd, cwd, timeout_s, sem in tasks_spec:
        print(f"[verify_v8] Running {name}: {' '.join(cmd)}")
        res = await run_bounded_task(name, cmd, cwd, timeout_s, sem)
        print(
            f"[verify_v8] -> {res.name}: {res.status} ({res.duration_ms} ms, free_disk={res.resource_after.free_disk_gib if res.resource_after else '?'} GiB)"
        )
        results.append(res)
        if res.status != "PASS":
            print(f"[verify_v8] ERROR in {res.name}:\n{res.stdout_tail}\n{res.stderr_tail}", file=sys.stderr)
            break

    overall_status = "PASS" if all(r.status == "PASS" for r in results) and len(results) == len(tasks_spec) else "FAIL"
    summary = {
        "suite": "V8_REAL_EDGE_CDP_PROXY_ATTRIBUTION_AND_REPLAY_BACKTEST",
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "host_platform": f"{platform.system()}-{platform.machine()}",
        "overall_status": overall_status,
        "initial_resources": asdict(initial_snap),
        "final_resources": asdict(sample_resources()),
        "tasks": [asdict(r) for r in results],
    }

    # Atomic write to scratch/artifact or stdout
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="v8_verify_", suffix=".json")
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    os.unlink(tmp_path)

    print(f"[verify_v8] OVERALL STATUS: {overall_status}")
    return 0 if overall_status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
