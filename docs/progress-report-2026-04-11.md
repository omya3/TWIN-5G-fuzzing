# TWIN Project Progress Report

## Project title

Extending RANsacked for NAS-aware and stateful fuzzing of 5G control-plane interfaces

## Date

2026-04-11

## 1. What this project is trying to do

This project is about testing how strong and reliable a 5G core network is when it receives unusual or malformed control-plane messages.

In simple words:

- A normal 5G UE sends a sequence of messages to register with the network.
- We first capture one clean, successful registration.
- Then we create modified versions of that sequence.
- Finally, we try to send those modified messages and observe what breaks.

The main software stack used in this work is:

- `Open5GS` as the 5G core
- `UERANSIM` as the simulated `UE + gNB`

The main research idea is:

- learn the normal NGAP/NAS message flow
- mutate it in controlled ways
- observe how the system behaves

## 2. Big picture of what we have completed

By the end of this stage, we have done five major things:

1. Set up a working 5G lab on the remote Ubuntu machine.
2. Captured a real successful registration trace.
3. Built a local trace-processing and mutation prototype.
4. Generated several mutation cases from the real trace.
5. Performed the first live mutation test by modifying the running UE code.

This means the project is no longer only a proposal or setup exercise. We now have a real implementation pipeline.

## 3. Remote machine setup that was completed

The remote test machine was identified as:

- `Ubuntu 22.04.5 LTS`

Installed and configured components:

- `MongoDB`
- `Open5GS 2.7.6`
- `UERANSIM v3.2.7`

Important configuration decisions:

- We kept the `Open5GS` loopback IP addresses because `Open5GS` and `UERANSIM` are running on the same machine.
- We changed the default PLMN values in `Open5GS` from `999/70` to `001/01` so they match `UERANSIM`.
- We created matching `gNB` and `UE` configs for same-host operation.
- We inserted a subscriber directly into MongoDB because the WebUI installation path ran into DNS issues.

Remote configuration summary:

- `MCC = 001`
- `MNC = 01`
- `TAC = 1`
- AMF NGAP address = `127.0.0.5:38412`

Subscriber used for testing:

- IMSI: `001010000000001`
- K: `465B5CE8B199B49FAA5F0A2EE238A6BC`
- OPC: `E8ED289DEBA952E4283B54E88E6183CA`
- AMF: `8000`
- DNN/APN: `internet`
- Slice SST: `1`

## 4. First successful clean 5G run

After the setup was fixed, we achieved a clean successful registration.

In simple words, the system did this:

- `gNB` connected to `AMF`
- `NG Setup` completed successfully
- `UE` sent the first registration message
- `AMF` authenticated the UE
- security mode setup happened
- registration completed
- a PDU session was established

This is important because it gave us a known-good baseline.

### Baseline AMF summary

From the parsed `AMF` log:

- total parsed events: `38`
- `gNB connected`: yes
- `InitialUEMessage`: yes
- `Registration request`: yes
- `Registration complete`: yes
- `PDU session`: yes

### Baseline gNB summary

From the parsed `gNB` log:

- SCTP connection established: yes
- `NG Setup` successful: yes
- initial NAS from UE observed: yes
- `Initial Context Setup Request` observed: yes
- PDU session resources set up: yes

### Baseline UE summary

From the parsed `UE` log:

- `Sending Initial Registration`: yes
- `Authentication Request received`: yes
- `Security Mode Command received`: yes
- `Registration accept received`: yes
- `Initial Registration is successful`: yes
- `PDU Session establishment is successful`: yes

Important note:

The `UE` log later showed `Signal lost` and `Radio link failure detected`, but this happened after the successful run ended. That is cleanup noise, not the main experimental result.

## 5. Local tooling and code that we built

We created a small local prototype under:

- `src/ngap_nas_fuzz/`

This prototype does not run the 5G network itself. Instead, it helps us:

- represent a protocol run as structured JSON
- extract that structure from `tshark` output
- generate mutations
- summarize logs
- compare clean and mutated traces

### Files created or extended

- `README.md`
- `docs/work-plan.md`
- `docs/remote-ubuntu22-setup.md`
- `scripts/collect_env.sh`
- `scripts/capture_ngap_trace.sh`
- `scripts/export_ngap_decode.sh`
- `scripts/generate_first_cases.sh`
- `src/ngap_nas_fuzz/models.py`
- `src/ngap_nas_fuzz/extractors.py`
- `src/ngap_nas_fuzz/mutators.py`
- `src/ngap_nas_fuzz/logs.py`
- `src/ngap_nas_fuzz/cli.py`

### What this local prototype can do

It can:

- load and save structured traces
- extract a trace from `tshark -V` text output
- augment the trace with raw NAS bytes from `tshark -T json`
- generate stateful mutations
- generate NAS-aware mutations
- summarize `AMF` logs
- summarize `UERANSIM` logs
- show a diff between a clean trace and a mutated trace

## 6. Real trace capture and extraction

Once the clean setup worked, we captured real NGAP traffic from the remote machine.

That gave us the following artifacts:

- `remote_traces/ngap-registration.txt`
- `remote_traces/ngap-registration.json`
- `remote_traces/ngap-registration-structured.json`
- `remote_traces/ngap-registration-core.json`
- `remote_traces/ngap-registration-core-augmented.json`

### What these files mean

`ngap-registration.txt`

- verbose `tshark -V` decode of the capture

`ngap-registration.json`

- `tshark -T json` output of the same capture

`ngap-registration-structured.json`

- the full structured NGAP/NAS message list extracted from the capture

`ngap-registration-core.json`

- the clean 8-message core registration procedure, sliced out of the larger trace

`ngap-registration-core-augmented.json`

- the same core procedure, but enriched with:
  - `frame_number`
  - raw NAS hex
  - NAS message type code
  - security header type code

### Core clean registration sequence

The 8-message core registration sequence is:

1. `InitialUEMessage` carrying `Registration request`
2. `DownlinkNASTransport` carrying `Authentication request`
3. `UplinkNASTransport` carrying `Authentication response`
4. `DownlinkNASTransport` carrying `Security mode command`
5. `UplinkNASTransport`
6. `InitialContextSetupRequest`
7. `InitialContextSetupResponse`
8. `UplinkNASTransport`

## 7. Mutation cases generated from the real trace

We created multiple mutation cases from the clean captured trace.

### Mutation case files

- `remote_traces/case1-duplicate-ics-response.json`
- `remote_traces/case2-reorder-ics.json`
- `remote_traces/case3-amf-id-mismatch.json`
- `remote_traces/case4-initial-nas-type.json`
- `remote_traces/case5-raw-nas-msgtype-patched.json`

### What each one means

`case1-duplicate-ics-response`

- duplicates `InitialContextSetupResponse`
- this is a stateful duplication test

`case2-reorder-ics`

- swaps `InitialContextSetupRequest` and `InitialContextSetupResponse`
- this is a wrong-order test

`case3-amf-id-mismatch`

- changes `AMF_UE_NGAP_ID` to `999` in `InitialContextSetupResponse`
- this is a context mismatch test

`case4-initial-nas-type`

- changes the structured meaning of the first NAS message
- from `Registration request`
- to `Identity response`
- this is a semantic mutation at the trace level

`case5-raw-nas-msgtype-patched`

- changes the actual raw NAS message-type byte in message 1
- from `0x41`
- to `0x5c`
- this is the first mutation that affects the actual raw payload bytes

## 8. Why case5 is important

`case5` is the most important mutation we produced so far.

Why?

Because it is no longer just a label change.

It changed the actual raw NAS bytes:

- base: `7e:00:41:79:...`
- mutated: `7e:00:5c:79:...`

In simple words:

- `7e` says this is a 5GS NAS message
- `00` says it is plain and not security protected
- `41` means `Registration request`
- `5c` means `Identity response`

So `case5` is our first realistic live mutation candidate.

### Exact diff observed for case5

The clean-to-mutated trace diff showed:

- message type changed from `Registration request` to `Identity response`
- message type code changed from `0x41` to `0x5c`
- raw NAS bytes changed only at that one message-type byte

This was a very controlled mutation:

- only 1 message position changed
- only 1 logical field changed
- only 1 raw NAS byte changed

## 9. Log summarization tooling

We added log summarizers so we can explain results more clearly.

### AMF log summarizer

This tells us whether the core network reached key stages like:

- gNB connection
- `InitialUEMessage`
- `Registration request`
- `Registration complete`
- `PDU session`

### UERANSIM log summarizer

This tells us whether the UE/gNB side reached key stages like:

- SCTP connected
- NG setup successful
- initial registration sent
- authentication request received
- security mode command received
- registration success
- PDU session success

### Why this matters

Instead of reading a long raw log every time, we can now quickly answer:

- did the run reach the AMF?
- did authentication happen?
- did registration finish?
- where did the procedure stop?

## 10. First live mutation test

After confirming that `case5` was meaningful offline, we performed a live experiment by patching the running UE code in `UERANSIM`.

### Remote code change

We patched:

- `/home/omkar/UERANSIM/src/ue/nas/mm/messaging.cpp`

The added logic:

- checks whether environment variable `TWIN_MUTATE_INITIAL_REG=1` is set
- checks whether the outgoing plain NAS message is a `REGISTRATION_REQUEST`
- checks whether the encoded bytes begin with `7e 00 41`
- if yes, changes the third byte from `0x41` to a target value
- by default, the target value is `0x5c`
- if `TWIN_MUTATE_INITIAL_REG_MSGTYPE` is set, that environment variable provides the target message type byte

In simple words:

- we left normal UERANSIM behavior intact
- but when the experiment flag is enabled, we mutate the first registration NAS message in the live running UE
- and now we can test multiple target message types without rebuilding every time

### Rebuild result

`UERANSIM` rebuilt successfully after this change.

That means the patched `nr-ue` binary was generated and was runnable.

## 11. Output of the first live mutation runs

The mutated UE was started with:

- `TWIN_MUTATE_INITIAL_REG=1`

### First live attempt: UE mutation reached gNB but gNB crashed

The UE log clearly showed:

- `Sending Initial Registration`
- `TWIN experiment: patching Registration Request message type 0x41 -> 0x5c`

This is very important because it proves the live mutation actually happened.

### What the first gNB log showed

The `gNB` log showed:

- SCTP connected
- NG Setup successful
- UE signal detected
- RRC setup

Then it crashed with:

- `std::runtime_error`
- `BCD string contains invalid characters`

### What the first AMF log showed

The `AMF` log only showed:

- gNB connected
- gNB later disconnected

It did not show:

- `InitialUEMessage`
- `Registration request`

This means the mutated message did not reach the core network successfully on the first live attempt.

### Second live attempt: gNB survived but AMF selection failed

We then patched the `gNB` NAS handling code to fail open:

- if NAS decode or modification failed, the gNB would forward the original NAS unchanged instead of crashing

This fixed the gNB crash.

However, the next blocker was AMF selection:

- `gNB` logged `Initial NAS message received from UE`
- but then it failed with:
  - `AMF selection for UE failed. Could not find a suitable AMF.`
  - `AMF context not found with id: 0`

This happened because the malformed NAS no longer carried usable slice information, and the gNB AMF-selection logic depended on that information.

### Third live attempt: malformed NAS finally reached Open5GS

We then patched the gNB AMF-selection logic so that:

- if slice extraction failed
- the gNB would fall back to the first connected AMF

After that change, the experiment reached the intended milestone.

### What the third gNB log showed

- `Initial NAS message received from UE[1]`
- `requested slice could not be extracted, falling back to connected AMF[2]`

This means:

- the gNB accepted the malformed NAS
- it did not crash
- it forwarded the message to a valid connected AMF

### What the third AMF log showed

The AMF log now clearly showed:

- `InitialUEMessage`
- `RAN_UE_NGAP_ID[...] AMF_UE_NGAP_ID[...] TAC[1] CellID[0x10]`
- `ERROR: Invalid 5GMM message type [92]`
- removal of the temporary `gNB-UE` context

This is the most important result so far.

In simple words:

- the malformed NAS finally reached `Open5GS`
- `Open5GS` did not crash
- `Open5GS` detected that the first NAS message type was invalid
- `Open5GS` rejected the message and cleaned up the UE context

### What the UE log showed in the third run

The UE kept retrying because:

- it sent the malformed first NAS message
- it got no valid registration response
- timer `T3510` expired
- then it retried after `T3511`

This is expected behavior for a failed registration attempt.

### Fourth live attempt: configurable message-type run with `0x56`

After proving the `0x5c` path end to end, we improved the UE patch so the target NAS message type can be selected at runtime.

The mutated UE was started with:

- `TWIN_MUTATE_INITIAL_REG=1`
- `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x56`

This changed the first NAS message from:

- `Registration request`

to:

- `Authentication request`

### What the fourth UE log showed

The UE log clearly showed:

- `TWIN experiment: patching Registration Request message type 0x41 -> 0x56`

The UE then retried after `T3510` and `T3511`, which again means no valid registration response came back.

### What the fourth gNB log showed

The gNB log showed:

- `Initial NAS message received from UE`
- fallback to the connected AMF
- fail-open warning:
  - `[TWIN gNB] NAS decode/modify failed, forwarding original NAS unchanged: Bad constructed NAS message`

This means:

- the malformed message was bad enough that the gNB could not decode it as a valid NAS structure
- but the gNB still stayed alive
- and it still forwarded the original malformed NAS toward the AMF

### What the fourth AMF log showed

The AMF log showed:

- `InitialUEMessage`
- temporary UE context allocation
- `ERROR: Invalid 5GMM message type [86]`
- UE context cleanup

This is another strong end-to-end result.

In simple words:

- we changed the first NAS message to a different wrong type
- the malformed NAS again reached `Open5GS`
- `Open5GS` again rejected it cleanly
- the core still did not crash

### Fifth live attempt: configurable message-type run with `0x57`

We then repeated the same live experiment pattern with:

- `TWIN_MUTATE_INITIAL_REG=1`
- `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x57`

This changed the first NAS message from:

- `Registration request`

to:

- `Authentication response`

### What the fifth UE log showed

The UE log clearly showed:

- `TWIN experiment: patching Registration Request message type 0x41 -> 0x57`

Just like the previous malformed runs, the UE later retried after `T3510` and `T3511`, which means no valid registration response was accepted from the network.

### What the fifth gNB log showed

The gNB log again showed:

- `Initial NAS message received from UE`
- fallback to the connected AMF
- fail-open warning:
  - `[TWIN gNB] NAS decode/modify failed, forwarding original NAS unchanged: Bad constructed NAS message`

This means the gNB behavior remained stable:

- malformed NAS did not crash the gNB
- the gNB still forwarded the malformed first NAS toward the AMF

### What the fifth AMF log showed

The AMF log showed:

- `InitialUEMessage`
- temporary UE context allocation
- `ERROR: Invalid 5GMM message type [87]`
- UE context cleanup

In simple words:

- the third malformed first-message-type test also reached `Open5GS`
- `Open5GS` again rejected it cleanly
- the core still did not crash

### Sixth live attempt: configurable message-type run with `0x5d`

We then repeated the same live experiment pattern with:

- `TWIN_MUTATE_INITIAL_REG=1`
- `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x5d`

This changed the first NAS message from:

- `Registration request`

to:

- `Security mode command`

### What the sixth UE log showed

The UE log clearly showed:

- `TWIN experiment: patching Registration Request message type 0x41 -> 0x5d`

The UE later retried after `T3510` and `T3511`, which again means no valid registration response was accepted from the network.

### What the sixth gNB log showed

The gNB log again showed:

- `Initial NAS message received from UE`
- fallback to the connected AMF

An interesting detail is that this run did not print the gNB fail-open exception warning that appeared in the `0x56` and `0x57` runs.

In simple words, that suggests:

- the malformed first NAS still did not crash the gNB
- but it may have taken a slightly different internal path through the gNB NAS handling logic
- even so, the gNB still forwarded the malformed message toward the AMF

### What the sixth AMF log showed

The AMF log showed:

- `InitialUEMessage`
- temporary UE context allocation
- `ERROR: Invalid 5GMM message type [93]`
- UE context cleanup

In simple words:

- the fourth malformed first-message-type test also reached `Open5GS`
- `Open5GS` again rejected it cleanly
- the core still did not crash

### Seventh live attempt: configurable message-type run with `0x00`

We then repeated the same live experiment pattern with:

- `TWIN_MUTATE_INITIAL_REG=1`
- `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x00`

This changed the first NAS message from:

- `Registration request`

to:

- an arbitrary message-type value `0x00`

### What the seventh UE log showed

The UE log clearly showed:

- `TWIN experiment: patching Registration Request message type 0x41 -> 0x00`

The UE later retried after `T3510` and `T3511`, which again means no valid registration response was accepted from the network.

### What the seventh gNB log showed

The gNB log showed:

- `Initial NAS message received from UE`
- fallback to the connected AMF

Just like the `0x5d` run, this case did not print the gNB fail-open exception warning line.

In simple words, that suggests:

- the malformed first NAS still did not crash the gNB
- the gNB still forwarded the malformed message toward the AMF
- but the exact internal parsing path in the gNB was a little different from the `0x56` and `0x57` cases

### What the seventh AMF log showed

The AMF log showed:

- `InitialUEMessage`
- temporary UE context allocation
- `ERROR: Invalid 5GMM message type [0]`
- UE context cleanup

In simple words:

- the malformed first NAS again reached `Open5GS`
- `Open5GS` again rejected it cleanly
- the core still did not crash

### Eighth live attempt: corrupting a mandatory mobile-identity length field

After collecting several message-type results, we moved to a second mutation family:

- keep the first message as `Registration request`
- but corrupt a mandatory NAS IE inside it

The concrete change was:

- change the mobile-identity length field from `0x000d`
- to `0x0000`

In simple words:

- the first NAS message still claimed to be a `Registration Request`
- but one of its mandatory fields was broken

### What the eighth UE log showed

The UE log clearly showed:

- `TWIN experiment: corrupting Registration Request mobile identity length 0x000d -> 0x0000`

The UE then retried after `T3510` and `T3511`, which means it again received no valid registration response.

### What the eighth gNB log showed

The gNB log showed:

- `Initial NAS message received from UE`
- fallback to the connected AMF
- fail-open warning:
  - `[TWIN gNB] NAS decode/modify failed, forwarding original NAS unchanged: basic_string::_M_create`

In simple words:

- the malformed mandatory-IE corruption confused the gNB-side NAS parser
- but the gNB still survived
- and the malformed NAS was still forwarded to the AMF

### What the eighth AMF log showed

The AMF log showed:

- `InitialUEMessage`
- temporary UE context allocation
- multiple NAS decoder errors such as:
  - `Unknown type(...) or not implemented`
  - `ogs_pkbuf_pull() failed`
  - `ogs_nas_5gs_decode_registration_request() failed`
  - `ogs_nas_5gmm_decode() failed`

This is a very important result.

In simple words:

- this is no longer only a top-level "wrong message type" rejection
- the core got far enough to try to decode the inner `Registration Request`
- then the decoder failed because the mandatory field structure was broken

This gives us a stronger and more interesting non-message-type result than the earlier message-type-only cases.

## 12. What the live mutation result means

This is the most important explanation of the current result.

### What we tried

We changed the very first NAS message from:

- `Registration request`

to:

- `Identity response`

### What we expected

The best-case research path would have been:

- UE sends mutated NAS
- gNB forwards it
- AMF receives it
- Open5GS reacts or rejects it

### What actually happened

Instead:

- UE sent the mutated message
- gNB tried to parse or inspect that malformed NAS
- gNB crashed before the message reached the AMF

### What that means in simple words

Our setup initially had a gNB-side weak point:

- the gNB is not acting like a transparent forwarder for this malformed NAS input
- it is trying to parse it
- that parser crashed first

That first result was useful, because it showed a real weakness in the gNB path.

But after the gNB fail-open patch and the AMF fallback patch, we successfully pushed the malformed NAS all the way to the core.

So the final interpretation is now:

- the live mutation mechanism works
- the malformed first NAS message reaches `Open5GS`
- `Open5GS` rejects it with:
  - `Invalid 5GMM message type [92]`
  - `Invalid 5GMM message type [86]`
  - `Invalid 5GMM message type [87]`
  - `Invalid 5GMM message type [93]`
  - `Invalid 5GMM message type [0]`
- and for mandatory-IE corruption, `Open5GS` fails deeper inside `Registration Request` decoding
- `Open5GS` cleans up the temporary UE context instead of crashing

This is exactly the type of observable robustness result the project is meant to produce.

## 13. Main artifacts produced so far

### Documentation

- `README.md`
- `docs/work-plan.md`
- `docs/remote-ubuntu22-setup.md`

### Scripts

- `scripts/collect_env.sh`
- `scripts/capture_ngap_trace.sh`
- `scripts/export_ngap_decode.sh`
- `scripts/generate_first_cases.sh`

### Local prototype source

- `src/ngap_nas_fuzz/models.py`
- `src/ngap_nas_fuzz/extractors.py`
- `src/ngap_nas_fuzz/mutators.py`
- `src/ngap_nas_fuzz/logs.py`
- `src/ngap_nas_fuzz/cli.py`

### Captured traces and logs

- `remote_traces/ngap-registration.txt`
- `remote_traces/ngap-registration.json`
- `remote_traces/ngap-registration-structured.json`
- `remote_traces/ngap-registration-core.json`
- `remote_traces/ngap-registration-core-augmented.json`
- `remote_traces/amf-baseline.log`
- `remote_traces/amf.log`
- `remote_traces/gnb.log`
- `remote_traces/ue.log`

### Generated mutation cases

- `remote_traces/case1-duplicate-ics-response.json`
- `remote_traces/case2-reorder-ics.json`
- `remote_traces/case3-amf-id-mismatch.json`
- `remote_traces/case4-initial-nas-type.json`
- `remote_traces/case5-raw-nas-msgtype-patched.json`

### Older intermediate mutation outputs

- `remote_traces/mutated-auth-req-msgtype.json`
- `remote_traces/mutated-duplicate-ics-response.json`

## 14. What changed in the codebase

### Local codebase changes

We extended the local prototype to support:

- structured trace extraction from `tshark` output
- augmentation with raw NAS payloads
- stateful message mutations
- NAS-aware message-type mutation
- raw plain-NAS message-type byte patching
- AMF log summarization
- UERANSIM log summarization
- trace diffing

### Remote codebase changes

We modified the remote `UERANSIM` UE send path in:

- `/home/omkar/UERANSIM/src/ue/nas/mm/messaging.cpp`

This was done to test live first-message-type mutation:

- patch `Registration Request` message-type byte from `0x41` to a configurable target
- default target: `0x5c`
- runtime override: `TWIN_MUTATE_INITIAL_REG_MSGTYPE`

We also modified the remote `UERANSIM` gNB NAS handling path in:

- `/home/omkar/UERANSIM/src/gnb/ngap/nas.cpp`

This change made the gNB fail open:

- if malformed NAS could not be decoded safely
- it would forward the original NAS unchanged instead of crashing

We also modified the remote `UERANSIM` AMF-selection logic in:

- `/home/omkar/UERANSIM/src/gnb/ngap/nnsf.cpp`

This change added a fallback rule:

- if slice extraction failed for malformed NAS
- the gNB would use the first connected AMF instead of failing AMF selection

## 15. What is working right now

These parts are working:

- `Open5GS + UERANSIM` clean setup
- clean successful registration and PDU session
- trace capture and extraction
- structured mutation generation
- raw NAS byte mutation generation
- live UE-side mutation hook
- configurable live UE-side first-message-type mutation hook
- gNB fail-open forwarding for malformed initial NAS
- gNB fallback AMF selection when slice extraction fails
- comparison between clean and mutated traces
- log summarization
- end-to-end delivery of malformed initial NAS to `Open5GS`
- observation of `Open5GS` rejecting invalid NAS message type `92`
- observation of `Open5GS` rejecting invalid NAS message type `86`
- observation of `Open5GS` rejecting invalid NAS message type `87`
- observation of `Open5GS` rejecting invalid NAS message type `93`
- observation of `Open5GS` rejecting invalid NAS message type `0`
- observation of `Open5GS` failing deeper in NAS decode when a mandatory mobile-identity length is corrupted

## 16. What is not finished yet

These parts are still incomplete:

- live replay/injection through a transparent proxy
- broader evaluation over multiple mutation classes
- automation of repeated experiment runs

## 17. Main lesson learned so far

The biggest lesson so far is:

- there is a big difference between:
  - generating a mutation offline
  - and executing it live in a running stack

In our case:

- offline mutation worked exactly as intended
- live mutation also triggered correctly
- the first live attempt failed at the gNB side
- after fixing the gNB path, the malformed NAS reached `Open5GS`
- `Open5GS` then rejected the invalid NAS message type cleanly

This is exactly why real experimental validation is important: each layer can fail differently.

## 18. Best interpretation of current status

At this point, the project has successfully demonstrated:

- a working experimental 5G lab
- a real captured registration trace
- a structured mutation pipeline
- a first live mutated run
- a concrete observed failure caused by malformed NAS input
- successful end-to-end delivery of malformed initial NAS to `Open5GS`
- a concrete `Open5GS` error response: `Invalid 5GMM message type [92]`
- a second concrete `Open5GS` error response: `Invalid 5GMM message type [86]`
- a third concrete `Open5GS` error response: `Invalid 5GMM message type [87]`
- a fourth concrete `Open5GS` error response: `Invalid 5GMM message type [93]`
- a fifth concrete `Open5GS` error response: `Invalid 5GMM message type [0]`
- a configurable live mutation hook that can test multiple first NAS message types
- a first strong non-message-type live mutation result using mandatory-IE corruption

So the project has already crossed the stage of being only conceptual.

## 19. Recommended next steps

The most logical next step is:

- keep extending the first-message-type response matrix
- compare message-type mutations against mandatory-IE corruption behavior
- decide whether one more local mutation family is worth the time before moving to proxy

After that, the next experiment would be:

- start the minimal proxy MVP for `InitialUEMessage` / `NAS-PDU`
- then move stateful later-message mutations such as `NGAP ID mismatch` into the proxy path
- extend from message-type mutation to other NAS and NGAP field mutations

## 20. Final summary in one paragraph

We successfully built a working `Open5GS + UERANSIM` lab, captured a real 5G registration trace, converted it into a structured mutation-friendly format, created multiple stateful and NAS-aware mutation cases, and implemented a live mutation hook that changes the initial registration NAS message in the running UE. The first live attempt failed at the gNB side, which led us to patch the gNB NAS and AMF-selection paths so malformed NAS could still be forwarded. After those fixes, malformed initial NAS messages reached `Open5GS`, and `Open5GS` rejected them with `Invalid 5GMM message type [92]` for `0x5c`, `Invalid 5GMM message type [86]` for `0x56`, `Invalid 5GMM message type [87]` for `0x57`, `Invalid 5GMM message type [93]` for `0x5d`, and `Invalid 5GMM message type [0]` for `0x00`, while cleaning up the UE context. We then moved to a second mutation family by corrupting the mandatory mobile-identity length inside the first `Registration Request`, and `Open5GS` failed deeper inside NAS decoding rather than only rejecting the top-level message type. This is a stronger end-to-end prototype result, because it shows the project can now inject malformed control-plane input into a live 5G stack, vary both message type and field structure, and observe how the core network reacts.
