# TWiN: NAS-Aware and Stateful 5G Control-Plane Fuzzing

This repository contains the implementation for the final TWiN term-project
prototype: a trace-driven, NAS-aware, and partially state-aware fuzzing
workflow for the `Open5GS + UERANSIM` software-only 5G testbed.

The implementation centers on:

- structured NAS mutation modeling
- history-aware campaign planning
- live proxy-based mutation injection
- log-driven result classification
- campaign summaries and submission-ready report export

Final implementation branch used for the report:

- `post-midterm-generalization`

---

## 1. What You Can Reproduce From This Repository

This repository supports **two levels of reproduction**.

### A. Code-level / artifact-level verification from this repository alone

You can do the following directly from this checkout:

- inspect the NAS mutation catalog and scheduler logic
- build the SCTP NGAP proxy
- run the unit tests
- inspect included example traces and mutation previews
- inspect the frozen Markdown submission reports
- inspect the included remote trace artifacts and mutation cases

This path is the fastest way to verify:

- the code structure,
- the implemented mutation families,
- the CLI workflow,
- the final frozen campaign summaries.

### B. Full live system-level reproduction

You can also reproduce the live workflow end-to-end on an Ubuntu machine with:

- Open5GS
- MongoDB
- UERANSIM
- SCTP support
- the repository synced to that machine

This path is required to reproduce the live proxy-backed runs reported in the
final submission.

---

## 2. Final Freeze-State Snapshot

These are the official frozen numbers used in the final report:

- Modeled NAS messages: `5`
- Summarized mutation families: `24`
- Recorded campaign observations: `97`

Modeled live campaign messages:

- `Registration Request`
- `Identity Response`
- `Authentication Response`
- `Security Mode Complete`
- `PDU Session Establishment Request`

The strongest overall finding was:

- `Registration Request :: mobile-identity value corruption`

The cleanest end-to-end demo case was:

- `Identity Response :: identity payload corruption :: invalid BCD`

Frozen Markdown campaign reports are already included under:

- [`submission_reports/`](submission_reports)

The overview table is here:

- [`submission_reports/overview.md`](submission_reports/overview.md)

---

## 3. Repository Layout

```text
src/ngap_nas_fuzz/    Python package for NAS mutation, planning, execution, and reporting
proxy/                C SCTP NGAP proxy used for live mutation injection
tests/                Unit tests for schema, scheduler, execution bridge, and automation logic
scripts/              Helper scripts for syncing, capture, and report export
docs/                 Setup notes, runbooks, implementation explanations, and project notes
examples/             Small example trace/history inputs for quick inspection
remote_traces/        Included trace artifacts, mutation previews, and early campaign material
submission_reports/   Frozen Markdown reports used in the final submission snapshot
requirements.txt      Minimal Python dependency list
README.md             General reproduction and usage guide
```

---

## 4. Software Requirements

### Repository-only verification

For code-level verification from this repository alone, the software
requirements are:

- `python3` (3.10+ recommended)
- `pip`
- `gcc` or `clang`
- SCTP development library for the proxy build
  - Ubuntu/Debian: `libsctp-dev`
  - other Linux distributions: equivalent SCTP development package

Python dependency:

- `scapy>=2.5.0`

Install locally:

```bash
cd /path/to/TWIN
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Full live reproduction

For full live execution, the software stack is:

- Ubuntu 22.04
- MongoDB
- Open5GS
- UERANSIM
- `python3`
- `git`
- `make`
- `gcc`
- `tshark`
- `tcpdump`
- SCTP build/runtime libraries
- `rsync` and `ssh` if you are using a separate controller machine

The detailed Ubuntu setup notes are:

- [`docs/remote-ubuntu22-setup.md`](docs/remote-ubuntu22-setup.md)

---

## 5. Hardware Requirements

This project does **not** require SDR hardware or a physical radio setup. It is
designed for a software-only `Open5GS + UERANSIM` environment.

### Repository-only verification

A modest development machine is enough:

- 2 CPU cores minimum
- 4 GB RAM minimum
- 2--5 GB free disk space

### Full live reproduction

For a comfortable single-machine Open5GS + UERANSIM setup, the practical
recommendation is:

- 64-bit Linux machine
- 4 CPU cores or more
- 8 GB RAM minimum
- 16 GB RAM recommended
- 15--25 GB free disk space
- sudo access for package installation, service control, and packet capture
- internet access for downloading packages and cloning dependencies

These are practical operating recommendations rather than hard-coded checks in
the repository.

---

## 6. Quick Local Verification

### 6.1 Build the proxy

```bash
cd proxy
make
```

This builds:

- `proxy/sctp_ngap_proxy`

### 6.2 Run the unit tests

From the repository root:

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py'
```

These tests cover:

- NAS schema and field location logic
- campaign planning
- execution bridge promotion from modeled operator to live proxy mutation
- result classification
- runner automation

### 6.3 Inspect the catalog and frontiers

```bash
python3 -m src.ngap_nas_fuzz.cli show-nas-catalog

python3 -m src.ngap_nas_fuzz.cli show-nas-candidates \
  --message "Registration Request" \
  --executable-only

python3 -m src.ngap_nas_fuzz.cli show-nas-frontiers \
  --limit 12
```

### 6.4 Inspect included example inputs

Examples:

- [`examples/initial_registration_trace.json`](examples/initial_registration_trace.json)
- [`examples/nas_campaign_history_example.json`](examples/nas_campaign_history_example.json)
- [`examples/ngap_tshark_excerpt.txt`](examples/ngap_tshark_excerpt.txt)

Included trace artifacts:

- [`remote_traces/ngap-registration-structured.json`](remote_traces/ngap-registration-structured.json)
- [`remote_traces/ngap-registration.txt`](remote_traces/ngap-registration.txt)
- [`remote_traces/first_nas_type_campaign/`](remote_traces/first_nas_type_campaign)

---

## 7. Read the Frozen Final Results

If you want to inspect the **final project outcomes** without rebuilding the
full Open5GS/UERANSIM environment first, start here:

- [`submission_reports/overview.md`](submission_reports/overview.md)
- [`submission_reports/registration-request.md`](submission_reports/registration-request.md)
- [`submission_reports/identity-response.md`](submission_reports/identity-response.md)
- [`submission_reports/authentication-response.md`](submission_reports/authentication-response.md)
- [`submission_reports/security-mode-complete.md`](submission_reports/security-mode-complete.md)
- [`submission_reports/pdu-session-establishment-request.md`](submission_reports/pdu-session-establishment-request.md)

These correspond to the frozen `97`-observation campaign snapshot used in the
report.

---

## 8. Deployment Options

The live workflow can be run in either of these ways:

### A. Single-machine setup

Install Open5GS, MongoDB, UERANSIM, and this repository on the same Ubuntu
machine and run everything locally on that host.

### B. Split-machine setup

Keep the repository on one machine and execute the full Open5GS/UERANSIM setup
on a separate Ubuntu host. In that case:

- use `git clone` directly on the Ubuntu host, or
- use `scripts/sync_remote_twin.sh` to copy the repository there

The project does **not** assume that you are using a remote desktop. A normal
terminal session on a Linux machine is enough. If you are using two machines,
SSH access is sufficient.

---

## 9. Runtime Assumptions for Full Live Reproduction

The current live runner assumes the following on the Ubuntu execution host:

- the repository is available at a path such as:
  - `$HOME/TWIN`
- UERANSIM is built under:
  - `$HOME/UERANSIM`
- UERANSIM config files are present:
  - `$HOME/UERANSIM/config/twin-gnb-proxy.yaml`
  - `$HOME/UERANSIM/config/twin-ue.yaml`
- Open5GS AMF is running as a systemd service:
  - `open5gs-amfd`
- a writable trace/history root exists:
  - `$HOME/twin-traces/nas-campaign`

These config files are **assumed by the live runner** but are **not bundled in
this repository**. If you are setting up a fresh machine, create them according
to the Open5GS + UERANSIM integration you use.

---

## 10. Put the Repository on the Ubuntu Execution Host

### Option A. Clone directly on the Ubuntu host

```bash
cd "$HOME"
git clone https://github.com/omya3/TWIN-5G-fuzzing.git TWIN
cd "$HOME/TWIN"
git checkout post-midterm-generalization
```

### Option B. Sync an existing local checkout to a separate Ubuntu host

```bash
scripts/sync_remote_twin.sh <user@host> [remote-path]
```

Example:

```bash
scripts/sync_remote_twin.sh user@example-host "$HOME/TWIN"
```

The sync script copies:

- `README.md`
- `requirements.txt`
- `docs/`
- `proxy/`
- `scripts/`
- `src/`
- `tests/`

After sync, the script prints suggested follow-up commands to:

- rebuild the proxy
- run the tests
- inspect the current frontiers

---

## 11. Build and Sanity Check on the Ubuntu Execution Host

```bash
export TWIN_ROOT="$HOME/TWIN"

cd "$TWIN_ROOT"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make -C proxy clean
make -C proxy
PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py'
```

Optional environment snapshot:

```bash
scripts/collect_env.sh
```

---

## 12. Generate or Inspect Campaign Recommendations

Set reusable paths first:

```bash
export TWIN_ROOT="$HOME/TWIN"
export TRACE_ROOT="$HOME/twin-traces/nas-campaign"
cd "$TWIN_ROOT"
```

### 12.1 Show modeled catalog and domains

```bash
python3 -m src.ngap_nas_fuzz.cli show-nas-catalog
python3 -m src.ngap_nas_fuzz.cli show-nas-domains --message "Registration Request"
```

### 12.2 Show highest-value frontiers from a history file

```bash
python3 -m src.ngap_nas_fuzz.cli show-nas-frontiers \
  --history "$TRACE_ROOT/history.json" \
  --limit 12
```

### 12.3 Build a multi-run proxy campaign plan

```bash
python3 -m src.ngap_nas_fuzz.cli plan-proxy-nas-campaign \
  --message "Registration Request" \
  --history "$TRACE_ROOT/history.json" \
  --output "$TRACE_ROOT/rr-plan.json" \
  --limit 20 \
  --base-log-root "$TRACE_ROOT"
```

### 12.4 Ask for the single best next live case

```bash
python3 -m src.ngap_nas_fuzz.cli next-proxy-nas-case \
  --message "Identity Response" \
  --history "$TRACE_ROOT/history.json" \
  --allow-repeats \
  --output "$TRACE_ROOT/identity-response-next.json" \
  --base-log-root "$TRACE_ROOT"
```

---

## 13. Reproduce a Representative Live Demo Case

The cleanest end-to-end demo case from the final submission is:

- `Identity Response :: identity payload corruption :: invalid BCD`

### 13.1 Generate the one-run plan

```bash
export TWIN_ROOT="$HOME/TWIN"
export TRACE_ROOT="$HOME/twin-traces/nas-campaign"

cd "$TWIN_ROOT"
python3 -m src.ngap_nas_fuzz.cli next-proxy-nas-case \
  --message "Identity Response" \
  --history "$TRACE_ROOT/history.json" \
  --allow-repeats \
  --output "$TRACE_ROOT/identity-response-next.json" \
  --base-log-root "$TRACE_ROOT"
```

Expected family/operator:

- Family: `identity payload corruption`
- Operator: `invalid BCD`

### 13.2 Execute the run

```bash
python3 -m src.ngap_nas_fuzz.cli run-proxy-nas-case \
  --plan "$TRACE_ROOT/identity-response-next.json" \
  --run-id identity-response-identity-payload-corruption-identity-response-invalid-bcd \
  --history-path "$TRACE_ROOT/history.json"
```

Expected outcome:

- `unexpected-accept`

Key logs typically include:

- proxy: `Identity Response payload mutation enabled: patch tail octet -> 0x2a`
- gNB: `Initial Context Setup Request received`
- UE: `Initial Registration is successful`

---

## 14. Reproduce the Strongest Overall Family Example

The strongest overall family in the final report is:

- `Registration Request :: mobile-identity value corruption`

One representative live case is:

- `toggle identity type bits inconsistently`

### 14.1 Build a plan for Registration Request

```bash
export TWIN_ROOT="$HOME/TWIN"
export TRACE_ROOT="$HOME/twin-traces/nas-campaign"

cd "$TWIN_ROOT"
python3 -m src.ngap_nas_fuzz.cli plan-proxy-nas-campaign \
  --message "Registration Request" \
  --history "$TRACE_ROOT/history.json" \
  --output "$TRACE_ROOT/rr-mobile-id-plan.json" \
  --limit 20 \
  --base-log-root "$TRACE_ROOT"
```

### 14.2 Execute the representative run

```bash
python3 -m src.ngap_nas_fuzz.cli run-proxy-nas-case \
  --plan "$TRACE_ROOT/rr-mobile-id-plan.json" \
  --run-id registration-request-mobile-identity-value-corruption-mobile-identity-toggle-type-bits \
  --history-path "$TRACE_ROOT/history.json"
```

Typical evidence:

- AMF logs `Unknown Mobile Identity type [6]`
- AMF logs `Unknown SUCI type [6]`
- UE still reaches `Initial Registration is successful`
- result class: `unexpected-accept`

---

## 15. Export Paper-Friendly Reports From a Campaign History

Once you have a populated history file, regenerate the Markdown reports with:

```bash
export TWIN_ROOT="$HOME/TWIN"
export TRACE_ROOT="$HOME/twin-traces/nas-campaign"

cd "$TWIN_ROOT"
scripts/export_submission_reports.sh \
  "$TRACE_ROOT/history.json" \
  submission_reports
```

This writes:

- one report per modeled NAS message
- one overview file summarizing the whole campaign

The export script currently covers:

- `Registration Request`
- `Identity Response`
- `Authentication Response`
- `Security Mode Complete`
- `PDU Session Establishment Request`

---

## 16. Included Documentation

Recommended reading order:

1. [`README.md`](README.md)
2. [`submission_reports/overview.md`](submission_reports/overview.md)
3. [`docs/remote-ubuntu22-setup.md`](docs/remote-ubuntu22-setup.md)
4. [`docs/code-explanations/00_code_flow_overview.md`](docs/code-explanations/00_code_flow_overview.md)
5. [`docs/code-explanations/04_nas_campaign_explanation.md`](docs/code-explanations/04_nas_campaign_explanation.md)

Useful deeper references:

- [`docs/nas-message-state-catalog.md`](docs/nas-message-state-catalog.md)
- [`docs/proxy-live-results-report.md`](docs/proxy-live-results-report.md)
- [`docs/experiment-results-table.md`](docs/experiment-results-table.md)
- [`docs/multi-message-type-campaign-runbook.md`](docs/multi-message-type-campaign-runbook.md)

---

## 17. What Is Included vs. What Is Not Included

### Included

- implementation code
- tests
- helper scripts
- included example traces and mutation previews
- frozen Markdown campaign reports
- setup notes and code explanations

### Not included

- a fully provisioned Open5GS/UERANSIM VM image
- the exact final execution-host `history.json` file used during all live runs
- bundled UERANSIM config files such as `twin-gnb-proxy.yaml` / `twin-ue.yaml`
- a turnkey one-command installer for the entire 5G stack

This means:

- **artifact-level verification** is immediate from this repo
- **full live reproduction** requires provisioning the Ubuntu runtime and
  preparing matching Open5GS/UERANSIM configs

---

## 18. Minimal Command Summary

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make -C proxy
PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m src.ngap_nas_fuzz.cli show-nas-catalog
python3 -m src.ngap_nas_fuzz.cli show-nas-frontiers --limit 12
```

For full live work on an Ubuntu execution host:

```bash
git clone https://github.com/omya3/TWIN-5G-fuzzing.git TWIN
cd TWIN
git checkout post-midterm-generalization
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make -C proxy
```

For frozen report inspection:

```bash
sed -n '1,200p' submission_reports/overview.md
```

---

## 19. Short Reproduction Statement

If you want the shortest possible summary:

1. Build the proxy and run the tests locally.
2. Read `submission_reports/overview.md` to inspect the frozen final results.
3. Use `docs/remote-ubuntu22-setup.md` to provision Ubuntu 22.04 with
   Open5GS + UERANSIM.
4. Put this repository on that Ubuntu host, either with `git clone` or
   `scripts/sync_remote_twin.sh`.
5. Run `next-proxy-nas-case` and `run-proxy-nas-case` to reproduce live cases.
6. Export reports from the resulting history with
   `scripts/export_submission_reports.sh`.
