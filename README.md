# 5G Control-Plane Fuzzing Prototype

This workspace contains the first implementation scaffold for a term project
inspired by `RANsacked`, focused on extending LTE/5G RAN-core fuzzing toward:

- NAS-aware structured mutation
- procedure-level stateful mutation
- later hybrid valid/invalid fuzzing and LLM-assisted rule extraction

## Immediate Goal

Build a software-only prototype around `Open5GS + UERANSIM` that can:

1. capture valid NGAP/NAS traces,
2. replay or model them as structured procedure traces,
3. apply controlled mutations,
4. compare the behavior against simpler baselines.

## What Is Implemented Here

This initial scaffold includes:

- a concrete work plan in [docs/work-plan.md](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/docs/work-plan.md)
- a small Python package for structured trace mutation under
  [src/ngap_nas_fuzz](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/src/ngap_nas_fuzz)
- an example procedure trace in
  [examples/initial_registration_trace.json](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/examples/initial_registration_trace.json)

The current code is intentionally offline and protocol-agnostic at the wire
level. It gives us a clean place to implement mutation logic before coupling it
to real `pcap` or `tshark` output from the remote machine.

The current scaffold also includes a small proxy-preparation layer:

- a byte-level initial NAS mutation policy for the proxy MVP
- a local proxy-runtime simulation scaffold that applies those policies to a
  structured trace as if a live proxy had intercepted `InitialUEMessage`
- a CLI preview command to show how the first `Registration Request` NAS bytes
  would change before we wire the live relay
- a proxy MVP runbook in
  [docs/proxy-mvp-plan.md](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/docs/proxy-mvp-plan.md)
- a practical stage-by-stage roadmap in
  [docs/proxy-roadmap.md](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/docs/proxy-roadmap.md)
- a NAS message/state mutation catalog in
  [docs/nas-message-state-catalog.md](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/docs/nas-message-state-catalog.md)

## Project Structure

```text
docs/                   work plan and project notes
examples/               sample structured traces
src/ngap_nas_fuzz/      mutation logic and CLI
```

## Quick Start

From this directory:

```bash
python3 -m src.ngap_nas_fuzz.cli show \
  --input examples/initial_registration_trace.json

python3 -m src.ngap_nas_fuzz.cli mutate \
  --input examples/initial_registration_trace.json \
  --output /tmp/mutated_trace.json \
  --mutation duplicate-message \
  --index 5
```

You can also try NAS-aware mutation:

```bash
python3 -m src.ngap_nas_fuzz.cli mutate \
  --input examples/initial_registration_trace.json \
  --output /tmp/mutated_trace.json \
  --mutation nas-security-header \
  --index 1 \
  --value "Integrity protected"
```

You can extract a structured trace from `tshark -V` output:

```bash
python3 -m src.ngap_nas_fuzz.cli extract-text \
  --input examples/ngap_tshark_excerpt.txt \
  --output /tmp/extracted_trace.json \
  --procedure "Captured Registration Flow"

python3 -m src.ngap_nas_fuzz.cli show --input /tmp/extracted_trace.json
```

You can also preview the exact byte-level mutation that the proxy MVP should
apply to the first `Registration Request`:

```bash
python3 -m src.ngap_nas_fuzz.cli preview-initial-nas-mutation \
  --input remote_traces/ngap-registration-core-augmented.json \
  --mutation mobile-identity-length-zero
```

You can also simulate how the future proxy would mutate the first live
`InitialUEMessage` while forwarding all other messages unchanged:

```bash
python3 -m src.ngap_nas_fuzz.cli simulate-proxy-initial-nas \
  --input remote_traces/ngap-registration-core-augmented.json \
  --output /tmp/proxy-simulated-trace.json \
  --mutation message-type \
  --value 0x5c
```

You can also inspect the current NAS message/state mutation catalog:

```bash
python3 -m src.ngap_nas_fuzz.cli show-nas-catalog
```

You can list concrete mutation candidates for one NAS message:

```bash
python3 -m src.ngap_nas_fuzz.cli show-nas-candidates \
  --message "Registration Request" \
  --executable-only
```

You can also ask the scheduler what to fuzz next based on earlier outcomes:

```bash
python3 -m src.ngap_nas_fuzz.cli recommend-nas-next \
  --message "Registration Request" \
  --history examples/nas_campaign_history_example.json \
  --limit 6
```

You can turn those scheduler recommendations into concrete proxy runs:

```bash
python3 -m src.ngap_nas_fuzz.cli plan-proxy-nas-campaign \
  --message "Registration Request" \
  --history examples/nas_campaign_history_example.json \
  --output /tmp/nas-plan.json \
  --limit 6
```

After you execute one run on the remote machine, you can append the result
back into structured scheduler history:

```bash
python3 -m src.ngap_nas_fuzz.cli record-proxy-nas-observation \
  --plan /tmp/nas-plan.json \
  --run-id registration-request-mobile-identity-length-corruption-mobile-identity-length-zero \
  --result-class deep-decoder-failure \
  --history /tmp/nas-history.json \
  --notes "AMF log shows ogs_nas_5gmm_decode() failed"
```

## Next Integration Step

Once the remote machine details are available, the next layer will be:

1. Open5GS/UERANSIM setup validation
2. trace capture using `tshark`/`tcpdump`
3. conversion of captured traces into the structured JSON form used here
4. replay or proxy-based mutation against the AMF
