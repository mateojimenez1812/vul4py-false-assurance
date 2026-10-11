#!/usr/bin/env python3
"""
evaluate.py  (midterm version)

Independent verification of ONE frozen LLM attempt per (agent, vuln_id):
  0. Check that llm_response.json / patch.diff still match frozen.sha256
  1. Fork vulnerable/ into <case>/<agent>_candidate/ and apply patch.diff   -> A
  2. Run the baseline functional tests on the patched project               -> F
  3. Run the exploit/regression (security) tests on the patched project     -> S
  4. V = A*F*S ;  FA = C*(1-V) ;  write runs/<agent>/<vuln_id>/eval.json

Rules (see the assignment, Sections 3.2 and 3.5):
  * patch does not apply            -> A=0, F=S=0, tests are NOT run
  * rc 0                            -> test suite passed (1)
  * rc 1 or rc >= 128 (crash)       -> test suite failed (0)
  * rc 999 (no tests), timeouts (124, -2), runner errors (-1), pytest errors
    before results (2-5), or no rc  -> INCOMPLETE, never counted as pass or fail
  * V is complete only if A, F, S are all known, or if at least one of them is a
    definite 0 (then V = 0 whatever the others are).
  * the LLM never sees any of this: this script only reads its frozen output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"
VUL4PY = Path(__file__).resolve().parent / "vul4py.py"

FROZEN_FILES = ("llm_response.json", "patch.diff")


def cleanup_candidate(case_dir: Path, dst_name: str):
    p = case_dir / dst_name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def run_vul4py(args: List[str], log_lines: list, timeout: int) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(VUL4PY)] + args
    log_lines.append("$ " + " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    log_lines.append(f"[exit {cp.returncode}]")
    if cp.stdout:
        log_lines.append(cp.stdout)
    if cp.stderr:
        log_lines.append(cp.stderr)
    return cp


def parse_rc(stdout: str, marker: str = "rc=") -> Optional[int]:
    for line in stdout.splitlines():
        if marker in line:
            try:
                return int(line.split(marker, 1)[1].strip().split()[0])
            except Exception:
                continue
    return None


def classify_rc(rc: Optional[int]) -> Tuple[Optional[int], str]:
    """Return (value, status). value: 1 pass, 0 fail, None incomplete."""
    if rc is None:
        return None, "incomplete: no rc in output"
    if rc == 0:
        return 1, "pass"
    if rc == 999:
        return None, "incomplete: no tests (999)"
    if rc in (124, -2):
        return None, f"incomplete: timeout (rc={rc})"
    if rc == -1:
        return None, "incomplete: runner error (-1)"
    if rc == 1:
        return 0, "fail: tests failed (rc=1)"
    if rc >= 128:
        return 0, f"fail: process crashed with signal (rc={rc})"
    if 2 <= rc <= 5:
        return None, f"incomplete: pytest error before results (rc={rc}); see log"
    return None, f"incomplete: unexpected rc={rc}"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_frozen(run_dir: Path) -> Optional[str]:
    """Return None if the frozen output is intact, otherwise a reason string."""
    sums = run_dir / "frozen.sha256"
    if not sums.exists():
        return "frozen.sha256 missing: attempt was not frozen before verification"
    expected = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            expected[parts[1]] = parts[0]
    for name in FROZEN_FILES:
        f = run_dir / name
        if not f.exists():
            return f"{name} missing"
        if expected.get(name) != sha256_file(f):
            return f"{name} was modified after freezing"
    return None


def combine(A, F, S, C):
    """Return (V, FA, complete) from the three indicators and the claim."""
    if A == 0:
        F, S = 0, 0
    known = [x for x in (A, F, S) if x is not None]
    if A is not None and F is not None and S is not None:
        V = A * F * S
    elif 0 in known:
        V = 0  # a definite 0 forces V=0 whatever the missing indicator is
    else:
        return None, None, False
    FA = None if C is None else C * (1 - V)
    return V, FA, True


def evaluate_one(workspaces: Path, runs: Path, agent: str, vuln_id: str, timeout: int) -> dict:
    case_dir = workspaces / vuln_id
    run_dir = runs / agent / vuln_id
    patch = run_dir / "patch.diff"
    eval_path = run_dir / "eval.json"
    log_path = run_dir / "eval.log"

    v = {
        "agent": agent, "vuln_id": vuln_id,
        "status": "incomplete", "incomplete_reason": "",
        "claimed_success": None, "confidence": None, "latency_ms": None,
        "model": None, "input_tokens": None, "output_tokens": None, "timestamp_utc": None,
        "frozen_ok": None,
        "apply_ok": None, "functional_rc": None, "exploit_rc": None,
        "functional_status": "not run", "exploit_status": "not run",
        "A": None, "F": None, "S": None, "V": None, "FA": None,
        "plausible": False,  # kept for compatibility: True only if V == 1
        "elapsed_s": None, "notes": "",
    }
    log: list = []
    t0 = time.time()

    def finish(reason: str = "") -> dict:
        if reason:
            v["incomplete_reason"] = reason
        v["plausible"] = v["V"] == 1
        v["elapsed_s"] = round(time.time() - t0, 1)
        run_dir.mkdir(parents=True, exist_ok=True)
        if log:
            log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        eval_path.write_text(json.dumps(v, indent=2), encoding="utf-8")
        return v

    if not case_dir.exists() or not (case_dir / "meta.json").exists():
        return finish(f"no workspace at {case_dir}")
    if not (run_dir / "llm_response.json").exists():
        return finish("no llm_response.json (generation failed or missing)")

    # 0. the attempt must be frozen and untouched
    problem = check_frozen(run_dir)
    v["frozen_ok"] = problem is None
    if problem:
        return finish(problem)

    rec = json.loads((run_dir / "llm_response.json").read_text(encoding="utf-8"))
    for k in ("claimed_success", "confidence", "latency_ms", "model",
              "input_tokens", "output_tokens", "timestamp_utc"):
        v[k] = rec.get(k)
    C = rec.get("claimed_success")
    if C not in (0, 1) or rec.get("confidence") is None:
        v["notes"] = f"parse_error: {rec.get('parse_error')}"
        return finish("invalid LLM response: claim or confidence could not be parsed")

    dst_name = f"{agent}_candidate"
    cleanup_candidate(case_dir, dst_name)

    # 1. A: does the patch apply?
    if not patch.read_text(encoding="utf-8").strip():
        v["apply_ok"], v["A"], v["F"], v["S"] = False, 0, 0, 0
        v["notes"] = "empty patch"
        v["V"], v["FA"], _ = combine(0, 0, 0, C)
        v["status"] = "complete"
        return finish()
    try:
        fork = run_vul4py(
            ["--workspace-root", str(workspaces), "--cve-id", vuln_id, "fork",
             "--src", "vulnerable", "--dst", dst_name, "--patch", str(patch.resolve())],
            log, timeout)
    except subprocess.TimeoutExpired:
        cleanup_candidate(case_dir, dst_name)
        return finish("timeout while forking / applying patch")
    if fork.returncode != 0:
        out = (fork.stdout or "") + (fork.stderr or "")
        cleanup_candidate(case_dir, dst_name)
        if "Failed to apply patch" in out:
            v["apply_ok"], v["A"], v["F"], v["S"] = False, 0, 0, 0
            v["notes"] = "patch did not apply"
            v["V"], v["FA"], _ = combine(0, 0, 0, C)
            v["status"] = "complete"
            return finish()
        return finish("fork failed for a reason other than the patch (infrastructure)")
    v["apply_ok"], v["A"] = True, 1

    # 2 and 3. F and S on the patched project
    try:
        func = run_vul4py(
            ["--workspace-root", str(workspaces), "--cve-id", vuln_id, "functional", "--target", dst_name],
            log, timeout)
        v["functional_rc"] = parse_rc(func.stdout)
        expl = run_vul4py(
            ["--workspace-root", str(workspaces), "--cve-id", vuln_id, "exploit", "--targets", dst_name],
            log, timeout)
        v["exploit_rc"] = parse_rc(expl.stdout)
    except subprocess.TimeoutExpired:
        cleanup_candidate(case_dir, dst_name)
        return finish("timeout while running the test suites")

    v["F"], v["functional_status"] = classify_rc(v["functional_rc"])
    v["S"], v["exploit_status"] = classify_rc(v["exploit_rc"])

    # keep the test logs written by vul4py as evidence
    logs_dir = case_dir / "logs"
    if logs_dir.exists():
        dest = run_dir / "test_logs"
        dest.mkdir(exist_ok=True)
        for f in logs_dir.glob(f"*{dst_name}*"):
            try:
                shutil.copy2(f, dest / f.name)
            except Exception:
                pass

    cleanup_candidate(case_dir, dst_name)

    V, FA, complete = combine(v["A"], v["F"], v["S"], C)
    v["V"], v["FA"] = V, FA
    if complete:
        v["status"] = "complete"
        return finish()
    return finish(f"functional: {v['functional_status']}; security: {v['exploit_status']}")


def main():
    ap = argparse.ArgumentParser(description="Independently verify frozen LLM patches (A, F, S, V, FA).")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--vuln-id", help="Single vuln; omit to evaluate every frozen attempt found.")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--timeout", type=int, default=7200, help="seconds per vul4py call")
    args = ap.parse_args()

    agent_dir = args.runs / args.agent
    if not agent_dir.exists():
        sys.exit(f"no runs for agent: {agent_dir}")

    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        targets = sorted(p.name for p in agent_dir.iterdir() if (p / "llm_response.json").exists())
        if args.limit:
            targets = targets[: args.limit]

    n_complete = n_verified = 0
    for vid in targets:
        v = evaluate_one(args.workspaces, args.runs, args.agent, vid, args.timeout)
        print(
            f"  {args.agent}/{vid}: {v['status'].upper()} "
            f"C={v['claimed_success']} A={v['A']} F={v['F']} S={v['S']} V={v['V']} FA={v['FA']} "
            f"({v['elapsed_s']}s)" + (f" -- {v['incomplete_reason']}" if v["incomplete_reason"] else "")
        )
        n_complete += v["status"] == "complete"
        n_verified += v["V"] == 1
    print(f"[done] {args.agent}: complete {n_complete}/{len(targets)}, verified {n_verified}/{len(targets)}")


if __name__ == "__main__":
    main()
