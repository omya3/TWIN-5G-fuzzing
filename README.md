# TWiN NAS Fuzzing Prototype

This repository contains the implementation code for a 5G control-plane fuzzing
prototype focused on:

- NAS-aware structured mutation
- campaign planning and result tracking
- live proxy-based mutation for supported plain `Registration Request` cases
- nested/protected NAS mutation support through simulation

The current strongest implemented path is the 5GS NAS `Registration Request`
campaign against an `Open5GS + UERANSIM` testbed.

## Repository Scope

This GitHub-ready snapshot intentionally includes only the project code and
automation scripts:

- `src/ngap_nas_fuzz/` - Python campaign, scheduler, mutation, and CLI logic
- `proxy/` - C SCTP NGAP proxy used for live mutation injection
- `scripts/` - helper scripts for capture and campaign support

Local experiment traces, presentation assets, and draft notes are kept outside
the published repository.

## Key Implemented Components

- structured NAS mutation catalog for `Registration Request`
- field-aware locator logic for plain and nested NAS structures
- generic patch templates for reusable mutation logic
- execution bridge for live vs simulation-supported operators
- campaign planning, classification, recording, summary, and report export
- SCTP NGAP proxy mutations for supported live plain-message cases

## Project Layout

```text
src/ngap_nas_fuzz/   Python package for mutation and campaign tooling
proxy/               SCTP NGAP proxy implementation
scripts/             helper scripts for setup/capture/export
requirements.txt     minimal Python dependency list
```

## Current Status

- live `Registration Request` mutation coverage is strong for the currently
  supported operator set
- nested optional-IE mutation coverage is supported in simulation
- protected/nested live execution remains future work

## Minimal Usage

From the repository root:

```bash
python3 -m src.ngap_nas_fuzz.cli show-nas-catalog

python3 -m src.ngap_nas_fuzz.cli show-nas-candidates \
  --message "Registration Request" \
  --executable-only
```

For the live proxy component:

```bash
cd proxy
make
```

## Notes

This repository is a code-focused publication snapshot for the mid-term project
milestone. Experiment-specific traces and presentation materials are maintained
locally outside the published code snapshot.
