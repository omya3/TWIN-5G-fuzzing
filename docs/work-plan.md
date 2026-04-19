# Work Plan

## Project Direction

Primary implementation priority:

- `Novelty 2`: NAS-aware structured mutation inside valid NGAP wrappers

Secondary implementation priority:

- `Novelty 1`: procedure-level stateful mutation for selected NGAP/NAS flows

Future extensions:

- `Novelty 3`: hybrid valid-and-invalid fuzzing
- `Novelty 4`: LLM-assisted procedure/constraint extraction

## Phase 1: Local Prototype Scaffold

Goal:
create a runnable, testable mutation engine independent of the telecom stack.

Tasks:

- define a structured trace format for NGAP/NAS procedures
- implement baseline mutation operators
- implement NAS-aware field mutations
- keep mutation metadata so every generated case is reproducible

Outputs:

- example trace corpus
- mutation CLI
- JSON outputs that can later be fed into a replay layer

## Phase 2: Remote Machine Integration

Goal:
connect the prototype to the actual `Open5GS + UERANSIM` environment.

Tasks:

- validate the OS, package manager, and available privileges
- confirm whether Open5GS/UERANSIM are already installed
- capture valid traffic for:
  - NG Setup
  - Initial UE Registration
  - UE Context Release
- identify where NGAP/NAS decoding can be reused

Outputs:

- baseline trace corpus
- setup notes and environment checklist
- concrete target NAS message types for mutation

## Phase 3: Baseline Replay and Monitoring

Goal:
get a minimal end-to-end experiment loop.

Tasks:

- replay or proxy valid traces toward the AMF
- log accepts, rejects, timeouts, and crashes
- define baseline mutation behavior

Baseline comparisons:

- packet-level mutation
- opaque-byte NAS mutation
- structured NAS field mutation

## Phase 4: Stateful Extension

Goal:
extend the baseline to selected procedure-level mutations.

Candidate mutations:

- duplicate a message
- drop a prerequisite message
- replay stale messages
- reuse stale `RAN_UE_NGAP_ID` or `AMF_UE_NGAP_ID`
- send release-related messages for a nonexistent UE context

## What To Finish First

The first milestone should be:

1. confirm remote environment,
2. capture one valid registration trace,
3. map that trace into the JSON format,
4. run structured offline mutations,
5. prepare replay/injection integration.

## Machine Details That Will Help Next

When you are ready, the most useful details are:

- OS and version on the remote machine
- whether Docker is available
- whether Open5GS and UERANSIM are already installed
- whether you have `sudo`
- whether traffic capture tools like `tcpdump` or `tshark` are installed
