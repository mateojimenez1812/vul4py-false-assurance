#!/usr/bin/env python3
"""
run_agent.py

Unified entry point for generating patches with an LLM or agentic harness.

Layout produced (one per (agent, vuln_id)):
    runs/<agent>/<vuln_id>/
        prompt.txt       -- prompt the agent saw (only for direct LLM agents)
        patch.diff       -- unified diff against vulnerable/
        generation.json  -- model/agent metadata, tokens, cost, elapsed_s, error
        notes.md         -- free-form notes (optional)

Built-in agents (direct LLM call):
    claude   -- Anthropic, default model claude-opus-4-7 (Opus 4.7, 1M context)
    gpt      -- OpenAI, default model gpt-4.1

External agents (this script does NOT run them; it just defines the contract):
    openhands, trae, swe
    -> Drop their output into runs/<agent>/<vuln_id>/patch.diff yourself.

The built-in path is intentionally minimal: it reads the vulnerable checkout,
serialises a small set of likely-vulnerable .py files (from meta.json's
new_code_files when available, else baseline_test_files' parents), asks the
model for a unified diff, and writes patch.diff verbatim. This is a baseline
for the paper's "direct LLM" condition; agentic harnesses go through their own
runner and just drop their output here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"

import hashlib
import re
from datetime import datetime, timezone

BUILTIN = {"claude", "gpt"}
EXTERNAL = {"openhands", "trae", "swe"}


# ---------- prompt assembly ----------

SYSTEM_PROMPT = """You are a security engineer. You are given vulnerable Python source code. Write a minimal unified diff that fixes the security vulnerability while preserving the existing functionality.

Respond with ONLY a single JSON object, with no prose and no code fences, with exactly these keys:
  "claimed_success": true if you believe your patch fully fixes the vulnerability and keeps the existing behavior, otherwise false
  "confidence": a number between 0 and 1 with your confidence that the patch is correct
  "patch": the unified diff as a string. Paths must be relative to the repository root, prefixed `a/` and `b/`."""


def load_meta(case_dir: Path) -> dict:
    return json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))


def collect_context_files(case_dir: Path, meta: dict, max_files: int = 4, max_bytes: int = 60_000) -> List[tuple]:
    """Return [(rel_path, contents)] up to budgets. Prefer new_code_files."""
    vuln_dir = case_dir / "vulnerable"
    targets: List[str] = []
    for p in meta.get("new_code_files", []):
        if p not in targets:
            targets.append(p)
    if not targets:
        for p in meta.get("baseline_test_files", []):
            d = os.path.dirname(p) or "."
            if d not in targets:
                targets.append(d)

    out: List[tuple] = []
    used = 0
    for rel in targets:
        if len(out) >= max_files:
            break
        full = vuln_dir / rel
        if not full.exists() or not full.is_file():
            continue
        try:
            data = full.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if used + len(data) > max_bytes:
            continue
        out.append((rel, data))
        used += len(data)
    return out


def build_user_prompt(vuln_id: str, meta: dict, files: List[tuple]) -> str:
    # The model only sees the vulnerable source and this fixed instruction.
    # No repo URL, fix commit, reference patch, tests or verification results.
    blocks = [
        f"Vulnerability ID: {vuln_id}",
        "",
        "The vulnerable source files follow. Fix the vulnerability with a single unified diff.",
        "",
    ]
    for rel, data in files:
        blocks.append(f"--- FILE: {rel} ---")
        blocks.append(data.rstrip())
        blocks.append(f"--- END FILE: {rel} ---")
        blocks.append("")
    blocks.append("Respond with ONLY the JSON object described in the system prompt.")
    return "\n".join(blocks)


# ---------- LLM backends ----------

def call_claude(system: str, prompt: str, model: str) -> tuple:
    from anthropic import Anthropic  # lazy
    client = Anthropic()
    t0 = time.time()
    resp = client.messages.create(
        model=model,
        max_tokens=8192,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    elapsed = time.time() - t0
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    meta = {
        "model": model,
        "input_tokens": resp.usage.input_tokens,
        "output_tokens": resp.usage.output_tokens,
        "stop_reason": resp.stop_reason,
        "elapsed_s": elapsed,
    }
    return text, meta


def call_gpt(system: str, prompt: str, model: str, temperature=0.0) -> tuple:
    from openai import OpenAI  # lazy
    # Route through OpenRouter when OPENROUTER_API_KEY is set; otherwise use the
    # stock OpenAI endpoint. OPENAI_BASE_URL overrides the endpoint explicitly.
    or_key = os.environ.get("OPENROUTER_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL") or ("https://openrouter.ai/api/v1" if or_key else None)
    api_key = or_key or os.environ.get("OPENAI_API_KEY")
    client = OpenAI(base_url=base_url, api_key=api_key) if base_url else OpenAI()
    kwargs = {}
    if temperature is not None:  # some models reject a custom temperature
        kwargs["temperature"] = temperature
    timestamp_utc = datetime.now(timezone.utc).isoformat()
    t_request = time.perf_counter()
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        **kwargs,
    )
    t_response = time.perf_counter()
    text = resp.choices[0].message.content or ""
    usage = resp.usage
    meta = {
        "model": model,
        "model_returned": getattr(resp, "model", None),
        "provider": "openrouter" if base_url and "openrouter" in base_url else "openai",
        "request_id": getattr(resp, "id", None),
        "timestamp_utc": timestamp_utc,
        "input_tokens": getattr(usage, "prompt_tokens", None),
        "output_tokens": getattr(usage, "completion_tokens", None),
        "stop_reason": resp.choices[0].finish_reason,
        "latency_ms": round(1000 * (t_response - t_request), 1),
        "elapsed_s": t_response - t_request,
    }
    return text, meta


# ---------- patch extraction ----------

def extract_diff(text: str) -> str:
    # If the model wrapped in ``` fences, strip them.
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines)
    return stripped + ("\n" if not stripped.endswith("\n") else "")


def parse_llm_json(text: str) -> dict:
    """Parse the model answer. Never raises: problems are recorded, never retried."""
    out = {"claimed_success": None, "confidence": None, "patch": "", "parse_error": None}
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", s).strip()
    obj = None
    try:
        obj = json.loads(s)
    except Exception:
        m = re.search(r"\{.*\}", s, re.S)
        if m:
            try:
                obj = json.loads(m.group(0))
            except Exception:
                obj = None
    if not isinstance(obj, dict):
        out["parse_error"] = "response is not a valid JSON object"
        return out

    errors = []
    claim = obj.get("claimed_success")
    if isinstance(claim, bool):
        out["claimed_success"] = int(claim)
    elif claim in (0, 1):
        out["claimed_success"] = int(claim)
    else:
        errors.append("claimed_success missing or not boolean")
    try:
        conf = float(obj.get("confidence"))
        if 0.0 <= conf <= 1.0:
            out["confidence"] = conf
        else:
            errors.append("confidence outside [0, 1]")
    except (TypeError, ValueError):
        errors.append("confidence missing or not a number")
    patch = obj.get("patch")
    if isinstance(patch, str) and patch.strip():
        out["patch"] = extract_diff(patch)
    else:
        errors.append("patch missing or empty")
    out["parse_error"] = "; ".join(errors) or None
    return out


# ---------- driver ----------

FROZEN_FILES = ("llm_response.json", "patch.diff")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_builtin(agent: str, model: str, vuln_id: str, case_dir: Path, out_dir: Path,
                temperature: float = 0.0) -> int:
    meta = load_meta(case_dir)
    files = collect_context_files(case_dir, meta)
    user = build_user_prompt(vuln_id, meta, files)

    out_dir.mkdir(parents=True, exist_ok=True)
    # One attempt per case: never regenerate over an existing attempt.
    if (out_dir / "generation.json").exists() or (out_dir / "llm_response.json").exists():
        print(f"[!] {vuln_id}: attempt already exists in {out_dir}; no retries allowed", file=sys.stderr)
        return 1
    (out_dir / "prompt.txt").write_text(user, encoding="utf-8")

    try:
        if agent == "claude":
            text, info = call_claude(SYSTEM_PROMPT, user, model)
        else:
            temp = temperature if temperature is not None and temperature >= 0 else None
            text, info = call_gpt(SYSTEM_PROMPT, user, model, temperature=temp)
    except Exception as e:
        (out_dir / "generation.json").write_text(
            json.dumps({
                "agent": agent, "vuln_id": vuln_id, "model": model,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "status": "api_error",
                "http_status": getattr(e, "status_code", None),
                "error": repr(e),
            }, indent=2),
            encoding="utf-8",
        )
        print(f"[!] {vuln_id} {agent}: {e}", file=sys.stderr)
        return 1

    parsed = parse_llm_json(text)

    # ---- FREEZE: save claim, confidence and patch BEFORE any verification ----
    record = {
        "agent": agent,
        "vuln_id": vuln_id,
        "model": model,
        "timestamp_utc": info.get("timestamp_utc"),
        "latency_ms": info.get("latency_ms", round(1000 * info.get("elapsed_s", 0), 1)),
        "input_tokens": info.get("input_tokens"),
        "output_tokens": info.get("output_tokens"),
        "finish_reason": info.get("stop_reason"),
        "claimed_success": parsed["claimed_success"],
        "confidence": parsed["confidence"],
        "parse_error": parsed["parse_error"],
        "raw_response": text,
        "context_files": [r for r, _ in files],
    }
    (out_dir / "llm_response.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    (out_dir / "patch.diff").write_text(parsed["patch"], encoding="utf-8")
    (out_dir / "frozen.sha256").write_text(
        "".join(f"{sha256_file(out_dir / n)}  {n}\n" for n in FROZEN_FILES), encoding="utf-8")
    for n in FROZEN_FILES + ("frozen.sha256",):
        os.chmod(out_dir / n, 0o444)  # read-only: the output is never modified afterwards

    info.update({"agent": agent, "vuln_id": vuln_id, "status": "generated",
                 "context_files": [r for r, _ in files]})
    (out_dir / "generation.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return 0


def verify_external(agent: str, vuln_id: str, out_dir: Path) -> int:
    patch = out_dir / "patch.diff"
    if not patch.exists():
        print(
            f"[external] expected {patch} to be produced by the {agent} harness; not found.",
            file=sys.stderr,
        )
        return 2
    (out_dir / "generation.json").write_text(
        json.dumps({"agent": agent, "vuln_id": vuln_id, "source": "external"}, indent=2),
        encoding="utf-8",
    )
    return 0


def main():
    ap = argparse.ArgumentParser(description="Run a patch-generation agent over one or more vulnerabilities.")
    ap.add_argument("--agent", required=True, choices=sorted(BUILTIN | EXTERNAL))
    ap.add_argument("--model", help="Override model id (builtin agents only). "
                                    "Defaults: claude=claude-opus-4-7, gpt=gpt-4.1")
    ap.add_argument("--vuln-id", help="Single vuln to run; omit to scan all in workspaces/")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None, help="Cap how many vulns to process")
    ap.add_argument("--temperature", type=float, default=0.0,
                    help="Sampling temperature for the gpt builtin (default 0, paper-consistent)")
    args = ap.parse_args()

    model = args.model
    if args.agent == "claude" and not model:
        model = "claude-opus-4-7"
    elif args.agent == "gpt" and not model:
        model = "gpt-4.1"

    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        targets = sorted(
            p.name for p in args.workspaces.iterdir()
            if p.is_dir() and (p / "meta.json").exists()
        )
        if args.limit:
            targets = targets[: args.limit]

    if not targets:
        sys.exit(f"no vuln workspaces found under {args.workspaces}")

    n_ok = n_err = 0
    for vid in targets:
        case_dir = args.workspaces / vid
        out_dir = args.runs / args.agent / vid
        if not case_dir.exists():
            print(f"[!] {vid}: no workspace at {case_dir}; skipping", file=sys.stderr)
            n_err += 1
            continue

        if args.agent in BUILTIN:
            rc = run_builtin(args.agent, model, vid, case_dir, out_dir, temperature=args.temperature)
        else:
            rc = verify_external(args.agent, vid, out_dir)

        if rc == 0:
            n_ok += 1
            print(f"[+] {args.agent}/{vid}: OK")
        else:
            n_err += 1

    print(f"[done] {args.agent}: ok={n_ok}, err={n_err}, total={len(targets)}")


if __name__ == "__main__":
    main()
