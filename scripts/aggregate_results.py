#!/usr/bin/env python3
"""aggregate_results.py  (midterm version)

Rebuild results.csv and the aggregate metrics from every
runs/<runs-dir>/<agent>/<vuln_id>/ attempt.

Definitions (assignment, Section 3.4):
    VRR = sum(V_i) / N                        N = completed observations
    FAR = sum(FA_i) / sum(C_i)                only if sum(C_i) > 0, else "undefined"

Only COMPLETE observations enter N. Incomplete attempts (API error, invalid LLM
response, missing tests, timeout, infrastructure error, not evaluated yet) are
kept in results.csv with their reason and reported separately.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

COLS = ["vuln_id", "model", "timestamp_utc", "claimed_success", "confidence",
        "patch_applied", "functional_pass", "security_pass",
        "verified_repair", "false_assurance", "latency_ms",
        "input_tokens", "output_tokens", "status", "incomplete_reason",
        "functional_rc", "exploit_rc"]


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def row_for(attempt_dir: Path) -> dict:
    vid = attempt_dir.name
    ev = load_json(attempt_dir / "eval.json")
    if ev:
        return {
            "vuln_id": vid, "model": ev.get("model"), "timestamp_utc": ev.get("timestamp_utc"),
            "claimed_success": ev.get("claimed_success"), "confidence": ev.get("confidence"),
            "patch_applied": ev.get("A"), "functional_pass": ev.get("F"), "security_pass": ev.get("S"),
            "verified_repair": ev.get("V"), "false_assurance": ev.get("FA"),
            "latency_ms": ev.get("latency_ms"),
            "input_tokens": ev.get("input_tokens"), "output_tokens": ev.get("output_tokens"),
            "status": ev.get("status", "incomplete"),
            "incomplete_reason": ev.get("incomplete_reason", ""),
            "functional_rc": ev.get("functional_rc"), "exploit_rc": ev.get("exploit_rc"),
        }
    # no eval.json: generation failed or evaluation has not run yet
    gen = load_json(attempt_dir / "generation.json") or {}
    resp = load_json(attempt_dir / "llm_response.json") or {}
    if gen.get("status") == "api_error":
        reason = f"API error (http_status={gen.get('http_status')}): {gen.get('error')}"
    elif resp:
        reason = "generated but not evaluated yet"
    else:
        reason = "no response recorded"
    return {
        "vuln_id": vid, "model": resp.get("model") or gen.get("model"),
        "timestamp_utc": resp.get("timestamp_utc") or gen.get("timestamp_utc"),
        "claimed_success": resp.get("claimed_success"), "confidence": resp.get("confidence"),
        "latency_ms": resp.get("latency_ms"),
        "input_tokens": resp.get("input_tokens"), "output_tokens": resp.get("output_tokens"),
        "status": "incomplete", "incomplete_reason": reason,
    }


def main():
    ap = argparse.ArgumentParser(description="Compute VRR and FAR and write results.csv")
    ap.add_argument("--runs", type=Path, default=HERE.parent / "runs",
                    help="runs directory (e.g. runs/midterm)")
    ap.add_argument("--agent", default="gpt")
    ap.add_argument("--out", type=Path, default=None, help="default: <runs>/results.csv")
    args = ap.parse_args()

    agent_dir = args.runs / args.agent
    if not agent_dir.exists():
        raise SystemExit(f"no attempts at {agent_dir}")
    out_csv = args.out or (args.runs / "results.csv")

    rows = [{**{k: None for k in COLS}, **row_for(d)}
            for d in sorted(agent_dir.iterdir()) if d.is_dir()]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in COLS})

    done = [r for r in rows if r["status"] == "complete"]
    incomplete = [r for r in rows if r["status"] != "complete"]
    N = len(done)
    sum_V = sum(int(r["verified_repair"]) for r in done)
    sum_C = sum(int(r["claimed_success"]) for r in done)
    sum_FA = sum(int(r["false_assurance"]) for r in done)

    vrr = (sum_V / N) if N else None
    far = (sum_FA / sum_C) if sum_C > 0 else None

    print(f"[+] attempts found: {len(rows)}   completed (N): {N}   incomplete: {len(incomplete)}")
    print(f"[+] wrote {out_csv}\n")
    print(f"  {'vuln_id':<22} {'C':>2} {'conf':>5} {'A':>2} {'F':>2} {'S':>2} {'V':>2} {'FA':>3} {'latency_ms':>11}  status")
    for r in rows:
        def f(x):
            return "-" if x in (None, "") else str(x)
        print(f"  {r['vuln_id']:<22} {f(r['claimed_success']):>2} {f(r['confidence']):>5} "
              f"{f(r['patch_applied']):>2} {f(r['functional_pass']):>2} {f(r['security_pass']):>2} "
              f"{f(r['verified_repair']):>2} {f(r['false_assurance']):>3} {f(r['latency_ms']):>11}  {r['status']}")

    print()
    if N:
        print(f"VRR = {sum_V}/{N} = {vrr:.1%}")
    else:
        print("VRR = undefined (no completed observations)")
    if sum_C > 0:
        print(f"FAR = {sum_FA}/{sum_C} = {far:.1%}")
    else:
        print("FAR = undefined (no positive repair claims)")
    print(f"(N = {N} completed observations; {len(incomplete)} incomplete reported separately)")

    if incomplete:
        print("\nIncomplete attempts (not counted in N):")
        for r in incomplete:
            print(f"  - {r['vuln_id']}: {r['incomplete_reason']}")

    (args.runs / "metrics.json").write_text(json.dumps({
        "agent": args.agent, "attempts": len(rows), "N_completed": N,
        "N_incomplete": len(incomplete),
        "sum_V": sum_V, "sum_C": sum_C, "sum_FA": sum_FA,
        "VRR": vrr, "FAR": far if sum_C > 0 else "undefined (no positive repair claims)",
        "incomplete": [{"vuln_id": r["vuln_id"], "reason": r["incomplete_reason"]} for r in incomplete],
    }, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
