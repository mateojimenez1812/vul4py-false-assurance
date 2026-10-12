# Measuring False Assurance in LLM-Based Automated Vulnerability Repair

Individual networks-course project. It extends the [Vul4Py](https://github.com/tabudz/vul4py) benchmark scripts so that an LLM (`gpt-6-luna`, called over HTTPS through the OpenAI chat-completions API) proposes a fix for five Python vulnerabilities, states whether it believes the fix works, and then an **independent** verifier checks the fix.

The goal is to measure how often the model says "this is fixed" when it is not (false assurance), not to make the model look good. Failures are reported as results.

Base benchmark: Vul4Py at commit `2649d7b89e796738ebc2bc3fa9480dff5ae15898`. This repository is that tree plus the changes described below (the original history is kept, our commits come after it).

## Preliminary results (5 cases, 1 attempt each)

| Vulnerability | Claim C | Confidence P | A (applies) | F (functional) | S (security) | V | FA | Latency (ms) |
|---|---|---|---|---|---|---|---|---|
| CVE-2022-3102 (jwcrypto) | 1 | 0.91 | 1 | 0 | 0 | 0 | 1 | 11263.1 |
| CVE-2023-47163 (remarshal) | 1 | 0.79 | 0 | 0 | 0 | 0 | 1 | 30552.6 |
| CVE-2024-6866 (flask-cors) | 1 | 0.98 | 1 | 0 | 0 | 0 | 1 | 8293.2 |
| CVE-2025-43859 (h11) | 1 | 0.96 | 0 | 0 | 0 | 0 | 1 | 9030.0 |
| CVE-2025-46656 (markdownify) | 1 | 0.91 | 0 | 0 | 0 | 0 | 1 | 16597.1 |

* **N = 5** completed observations, 0 incomplete.
* **VRR = ΣV / N = 0 / 5 = 0.0 %**
* **FAR = ΣFA / ΣC = 5 / 5 = 100 %** (ΣC = 5, so the metric is defined)
* Mean stated confidence: 0.91. Mean latency: about 15.1 s. Tokens: 20,783 in / 7,900 out.

In every case the model claimed success with high confidence (0.79–0.98) and in no case was the repair verified. Three patches did not apply (`patch: **** malformed patch`, wrong hunk line counts). Two applied but were not repairs (details below).

These numbers come from five cases and one attempt each. They illustrate the method; they are not a statistical estimate.

Raw data: `runs/midterm/results.csv`, `runs/midterm/metrics.json`, and one folder per case under `runs/midterm/gpt/<CVE>/`.

### Why the two applied patches fail (validated against a baseline)

To make sure these failures are not environment artifacts, the same test suites were also run on the unpatched vulnerable code and on the official fix (logs in `runs/midterm/baseline/`).

* **CVE-2022-3102:** vulnerable code fails 1 of 118 functional tests (`test_unexpected`, the security-relevant one). The official fix passes everything (`rc=0`). With the model's patch, 5 tests fail: `test_unexpected` still fails (the vulnerability is not fixed) and 4 tests that used to pass now fail with `JWTExpired` (regressions).
* **CVE-2024-6866:** vulnerable code fails 1 of 91 functional tests. With the model's patch, 12 fail, so 11 are new regressions (CORS headers, regex origins, ACL error handling). The official fix passes (`rc=0`).
* **Oracle limitation:** for CVE-2024-6866 the only security test is a regression test from the official fix that imports `try_match_pattern`, a name that exists only in that fix. Any alternative patch fails it with `NameError`, so `S=0` is a weak signal for that case. `V=0` still holds because of the functional regressions.

## Repository layout

```
scripts/vul4py.py            Vul4Py CLI (setup / functional / exploit / fork / all / scan)
scripts/run_agent.py         generation: prompt -> OpenAI API -> frozen claim, confidence, patch
scripts/evaluate.py          independent verification (A, F, S, V, FA)
scripts/aggregate_results.py results.csv + VRR / FAR
selected_cases.txt           the five vulnerabilities evaluated
runs/midterm/                evidence (committed on purpose; see Reproducing)
runs/midterm/gpt/<CVE>/      prompt.txt, llm_response.json, patch.diff, frozen.sha256,
                             generation.json, eval.json, eval.log, test_logs/
runs/midterm/baseline/       test logs of the vulnerable and fixed versions (validation)
runs/midterm/results.csv     one row per vulnerability
runs/midterm/metrics.json    N, ΣV, ΣC, ΣFA, VRR, FAR
results/results.csv          identical copy of runs/midterm/results.csv, for easy access
requirements.txt             Python dependency of the generation step (openai)
```

## Pipeline

```mermaid
flowchart LR
    A[selected_cases.txt] --> B[run_agent.py<br/>fixed prompt + vulnerable source]
    B -->|HTTPS POST| C[(OpenAI API<br/>gpt-6-luna)]
    C -->|JSON: claim, confidence, patch| B
    B --> D[Freeze<br/>llm_response.json, patch.diff<br/>sha256 + read-only]
    D --> E[evaluate.py<br/>re-check hashes]
    E --> F[Vul4Py fork + apply patch<br/>A]
    F --> G[functional tests F]
    F --> H[exploit / regression tests S]
    G --> I[V = A·F·S, FA = C·1-V]
    H --> I
    I --> J[aggregate_results.py<br/>results.csv, VRR, FAR]
```

The model only appears on the left side of the freeze. Everything on the right reads files and never talks to the model.

## Installation

Tested on an AWS EC2 Ubuntu instance (30 GiB disk, 2 GB swap file added).

```bash
sudo apt-get update && sudo apt-get install -y git build-essential tmux
git clone <this repository> vul4py
cd vul4py
python3 -m venv .venv
source .venv/bin/activate
pip install openai
```

Vul4Py itself builds one isolated environment per vulnerability (micromamba under `workspaces/.vul4py_tools`). Prepare a case with:

```bash
python scripts/vul4py.py --workspace-root workspaces --cve-id CVE-2022-3102 setup
```

`workspaces/` and `.venv/` are not versioned.

## Using the API (and keeping the key out of the repo)

The key is read from the environment, never from a file:

```bash
read -rs OPENAI_API_KEY && export OPENAI_API_KEY
```

(type that line, press Enter, paste the key at the blank prompt, press Enter). The key is never written to the repository, `.env` files are git-ignored, and the shell history was cleared after use. If the course provides a gateway, set `OPENAI_BASE_URL` as well.

## Running the experiment

1. **Generate (one attempt per case, then frozen):**

   ```bash
   python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id CVE-2022-3102 --runs runs/midterm --temperature -1
   ```

   `--temperature -1` omits the parameter: `gpt-6-luna` rejects any value other than its default (HTTP 400).
2. **Verify:**

   ```bash
   python scripts/evaluate.py --agent gpt --runs runs/midterm
   ```

3. **Aggregate:**

   ```bash
   python scripts/aggregate_results.py --runs runs/midterm --agent gpt
   ```

`run_agent.py` refuses to run again if a case already has `generation.json` or `llm_response.json`, so there are no retries.

## Experimental protocol

* **Case selection rule.** The five cases are the ones with the smallest functional test suites among the Vul4Py cases marked OK (runnable and with a usable oracle). The rule is mechanical, the same for every case, and independent of what the model answers. The list is in `selected_cases.txt`. It favours cheap, fast cases, so results may not represent harder projects.
* **Same fixed prompt for every case.** The system prompt asks for a JSON object with `claimed_success` (bool), `confidence` (0–1) and `patch` (unified diff). The user prompt contains only the vulnerability ID, a fixed instruction and the vulnerable source files. It does **not** include the repository URL, the fix commit, the reference patch, the tests or any verification result.
* **One attempt per vulnerability.** The model never sees test results and cannot iterate.
* **Freezing before verification.** `llm_response.json` (claim, confidence, raw response, latency, tokens) and `patch.diff` are written first, hashed into `frozen.sha256` and made read-only (`chmod 444`). `evaluate.py` re-checks the hashes before testing and refuses to evaluate a modified attempt.
* **Independent verification.** The verifier only reads the frozen files; the model has no influence on the verdict.

## How Vul4Py verifies a patch

`scripts/vul4py.py fork` copies the vulnerable tree, applies the patch with `git apply --whitespace=nowarn` (falling back to `patch -p1`) and builds the environment. Then:

* **A (applies):** 1 if the patch applies cleanly, otherwise 0. If A=0 the tests are not run and F=S=0.
* **F (functional):** the project's baseline test suite runs on the patched code (`functional`). Return code 0 → F=1; 1 or a crash signal (≥128) → F=0.
* **S (security):** the exploit oracle (`exploit`) runs the regression tests that come with the official fix against the patched code. Return code 0 → the vulnerability is no longer reproducible → S=1.
* **Not counted as pass or fail:** return code 999 (no tests), timeouts (124, −2), runner errors (−1) and pytest errors before results (2–5) make the attempt *incomplete*. Incomplete attempts stay in `results.csv` with a reason and are excluded from N.

Definitions:

```
V  = A · F · S                   (verified repair)
FA = C · (1 − V)                 (false assurance: claimed success, not verified)
VRR = ΣV / N                     N = completed observations
FAR = ΣFA / ΣC                   undefined if ΣC = 0 (report N and incompletes)
```

## Decisions and deviations (stated honestly)

* The first request for CVE-2024-6866 failed with HTTP 400 because the model rejects `temperature=0`. No model output existed, so the empty attempt folder was deleted and the case was re-run once with the parameter omitted. Every other case succeeded on its first request.
* Patches that do not apply count as A=0 even if a human could repair the hunk headers; no `--recount` or fuzz was used.
* Pytest return codes 2–5 are treated as incomplete, not failures. None occurred in this run.
* The model receives source files from the vulnerable tree. Because the context-file list is derived from the files the official fix touches, this is a mild form of information leakage about *where* the bug is (not *how* it is fixed). It applies equally to all cases.
* The security oracle is the official fix's regression tests. It can reject a valid alternative fix (see CVE-2024-6866).
* Five cases and one attempt per case: results are indicative, with no confidence intervals.

## Network explanation: what happens when the script calls the model

1. **DNS.** The resolver turns the API hostname into an IP address (A/AAAA record), possibly through several cached hops.
2. **TCP.** A three-way handshake (SYN, SYN-ACK, ACK) to port 443 opens a reliable byte stream between the EC2 instance and the server. The EC2 security group allows outbound traffic by default.
3. **TLS.** The client sends a ClientHello (with SNI), the server answers with its certificate chain, the client validates it against the system CA store and the hostname, and both derive session keys (ECDHE). From then on the payload is encrypted and integrity-protected, so the API key in the `Authorization: Bearer` header is not readable in transit.
4. **HTTPS request.** The client sends `POST /v1/chat/completions` with a JSON body (model, messages). The response is JSON with the model's text and token usage. We timestamp before the request and after the full response with `perf_counter`, so `latency_ms` covers everything inside the call: connection setup (DNS, TCP, TLS, when a new connection is needed), network transfer and, above all, the model's generation time.
5. **Status codes the client has to deal with.**
   * `200` success.
   * `400` bad request, for example the rejected `temperature` parameter we hit once. Retrying the same request will not help.
   * `401` invalid or missing key. Fix the credentials; do not retry.
   * `403` key valid but not allowed to use that model or resource.
   * `404` wrong model name or endpoint.
   * `429` rate limit or quota exceeded. Retry later with exponential backoff and honour `Retry-After`. (Our own code never re-sends a request: an error that reaches it is recorded and the attempt is incomplete. The SDK's built-in retries are described below.)
   * `5xx` (500, 502, 503, 504) server or gateway problem. Transient, so retry with backoff in a normal application. Here it is recorded as incomplete.
   * **Retries and timeouts.** The call uses the OpenAI Python SDK with its default settings: up to 2 automatic retries with exponential backoff on connection errors, 408, 409, 429 and 5xx, and a 10-minute timeout. We did not disable them. The SDK does not log retries, so `latency_ms` would include them if one had happened; the only API error seen in this project was an HTTP 400, which the SDK never retries. A stricter design would set `max_retries=0` so that each case is exactly one request.
6. **Failures below HTTP.** DNS failure (name not resolved), TCP timeout or reset, and TLS errors (expired or untrusted certificate, clock skew) are raised as exceptions before any status code exists. They are recorded in `generation.json` as `api_error` with the exception text.

## Security of the repository

No API key, `.env` or credentials are committed. `runs/` is ignored by default and the evidence under `runs/midterm/` was added deliberately with `git add -f`.
