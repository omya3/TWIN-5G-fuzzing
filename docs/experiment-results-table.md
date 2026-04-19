# Experiment Results Table

## Why this file exists

This file is the short, practical version of the longer progress report.

In simple words:

- the progress report explains the whole story
- this table helps us quickly answer:
  - what did we test?
  - what changed?
  - what happened?
  - what did we learn?

## Experiment ledger

| Experiment ID | Goal | What we changed | Result | What it means |
| --- | --- | --- | --- | --- |
| `baseline-clean-registration` | Confirm the lab works normally | No mutation | UE registration succeeded, authentication succeeded, security mode succeeded, PDU session succeeded | This is our known-good reference run |
| `case5-offline-structured` | Build a realistic malformed first NAS case offline | Changed first NAS message type in the structured trace from `Registration request` to `Identity response` | Structured trace changed correctly | Good for describing the mutation, but not yet a live packet |
| `case5-offline-raw` | Make the mutation affect real payload bytes | Changed raw NAS byte from `0x41` to `0x5c` in message 1 | Clean-to-mutated diff showed only the first message type byte changed | This became our first real live-mutation candidate |
| `live-case5-attempt-1` | Send the malformed first NAS from the running UE | Patched UE send path to mutate first NAS message type byte in live traffic | UE mutation triggered, but gNB crashed with `BCD string contains invalid characters` | The malformed NAS was killed in the gNB path before reaching Open5GS |
| `live-case5-attempt-2` | Make gNB tolerate malformed NAS instead of crashing | Patched gNB NAS decode/modify path to fail open | gNB survived, but AMF selection failed because requested slice could not be extracted | Malformed NAS now passed decode stage, but gNB still could not route it to an AMF |
| `live-case5-attempt-3` | Push malformed NAS all the way into Open5GS | Added gNB fallback to first connected AMF when slice extraction fails | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [92]` | This is the first successful end-to-end malformed NAS delivery and core-network observation |
| `live-msgtype-56` | Check whether another wrong first NAS message type follows the same pattern | Reused live UE mutation hook with `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x56` | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [86]` | The end-to-end harness works for more than one malformed first NAS type |
| `live-msgtype-57` | Check whether a third wrong first NAS message type follows the same pattern | Reused live UE mutation hook with `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x57` | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [87]` | The end-to-end harness now works consistently across three malformed first NAS types |
| `live-msgtype-5d` | Check whether a fourth wrong first NAS message type follows the same pattern | Reused live UE mutation hook with `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x5d` | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [93]` | The end-to-end harness now works consistently across four malformed first NAS types |
| `live-msgtype-00` | Check whether a more arbitrary first NAS message type still follows the same pattern | Reused live UE mutation hook with `TWIN_MUTATE_INITIAL_REG_MSGTYPE=0x00` | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [0]` | The end-to-end harness also works for an arbitrary message-type value, not only wrong-but-real NAS types |
| `live-mobile-id-length-zero` | Corrupt a mandatory NAS IE instead of only changing the message type | Reused live UE mutation hook with `TWIN_CORRUPT_INITIAL_REG_MOBILE_ID_LEN_ZERO=1` | AMF received `InitialUEMessage`, then failed inside `RegistrationRequest` decoding with NAS decoder errors and `ogs_nas_5gmm_decode() failed` | This is the first strong non-message-type live mutation result and shows deeper decode failure in the core |
| `proxy-clean-relay` | Validate that a proxy can sit between `gNB` and `AMF` without breaking normal behavior | Replaced direct `gNB -> AMF` path with `gNB -> proxy -> AMF`, no mutation enabled | `NG Setup` succeeded and clean registration completed through the proxy | This proves the proxy path is stable enough for live mutation work |
| `proxy-msgtype-5c` | Reproduce the first malformed NAS message-type case through the proxy | Proxy changed the first uplink NAS byte `0x41 -> 0x5c` inside `InitialUEMessage` | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [92]` | Proxy-side live NAS mutation matches the earlier UE-side result |
| `proxy-msgtype-56` | Reproduce the `0x56` malformed first-message case through the proxy | Proxy changed the first uplink NAS byte `0x41 -> 0x56` | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [86]` | Proxy-side mutation works consistently for another malformed first NAS type |
| `proxy-msgtype-57` | Reproduce the `0x57` malformed first-message case through the proxy | Proxy changed the first uplink NAS byte `0x41 -> 0x57` | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [87]` | Proxy-side mutation works consistently for a third malformed first NAS type |
| `proxy-msgtype-5d` | Reproduce the `0x5d` malformed first-message case through the proxy | Proxy changed the first uplink NAS byte `0x41 -> 0x5d` | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [93]` | Proxy-side mutation works consistently for a fourth malformed first NAS type |
| `proxy-msgtype-00` | Reproduce an arbitrary malformed first-message case through the proxy | Proxy changed the first uplink NAS byte `0x41 -> 0x00` | AMF received `InitialUEMessage` and rejected NAS with `Invalid 5GMM message type [0]` | Proxy-side mutation also works for an arbitrary message-type value |
| `proxy-mobile-id-length-zero` | Reproduce the mandatory-field corruption case through the proxy | Proxy changed mobile identity length `0x000d -> 0x0000` inside the first uplink `Registration Request` | AMF received `InitialUEMessage`, then failed inside NAS decoding with `ogs_nas_5gs_decode_registration_request() failed` and `ogs_nas_5gmm_decode() failed` | Proxy-side mutation now covers a deeper decoder-failure path, not just early message-type rejection |

## Important evidence from the runs

### Baseline clean run

Main observed path:

- `gNB connected`
- `InitialUEMessage`
- `Registration request`
- `Registration complete`
- `PDU session`

Main evidence files:

- [amf-baseline.log](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/remote_traces/amf-baseline.log)
- [gnb.log](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/remote_traces/gnb.log)
- [ue.log](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/remote_traces/ue.log)

### Offline raw mutation case

Main evidence:

- base NAS message type code: `0x41`
- mutated NAS message type code: `0x5c`
- raw byte change:
  - base: `7e:00:41:...`
  - mutated: `7e:00:5c:...`

Main evidence files:

- [ngap-registration-core-augmented.json](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/remote_traces/ngap-registration-core-augmented.json)
- [case5-raw-nas-msgtype-patched.json](/Users/sailor_omkar/Documents/Mtech_RA_Courses/sem_4/TWIN/remote_traces/case5-raw-nas-msgtype-patched.json)

### Live attempt 1

Main evidence:

- UE log showed:
  - `TWIN experiment: patching Registration Request message type 0x41 -> 0x5c`
- gNB crashed with:
  - `BCD string contains invalid characters`
- AMF did not receive `InitialUEMessage`

What we learned:

- the malformed message was real
- but the gNB path was too fragile for malformed NAS

### Live attempt 2

Main evidence:

- gNB no longer crashed
- gNB reported:
  - `Initial NAS message received from UE`
- but then failed with:
  - `AMF selection for UE failed`
  - `AMF context not found with id: 0`

What we learned:

- decode tolerance improved
- but routing still depended on successfully extracted slice information

### Live attempt 3

Main evidence:

- UE log showed the mutation fired
- gNB log showed:
  - `Initial NAS message received from UE`
  - fallback to connected AMF
- AMF log showed:
  - `InitialUEMessage`
  - `Invalid 5GMM message type [92]`

What we learned:

- malformed NAS successfully reached Open5GS
- Open5GS rejected it cleanly instead of crashing

## Current best result

The strongest result so far is:

`A live-mutated first NAS message with type 0x5c reaches Open5GS, and Open5GS rejects it with Invalid 5GMM message type [92].`

We now also have a second matching result:

`A live-mutated first NAS message with type 0x56 reaches Open5GS, and Open5GS rejects it with Invalid 5GMM message type [86].`

And now a third matching result:

`A live-mutated first NAS message with type 0x57 reaches Open5GS, and Open5GS rejects it with Invalid 5GMM message type [87].`

And now a fourth matching result:

`A live-mutated first NAS message with type 0x5d reaches Open5GS, and Open5GS rejects it with Invalid 5GMM message type [93].`

And now a fifth matching result:

`A live-mutated first NAS message with type 0x00 reaches Open5GS, and Open5GS rejects it with Invalid 5GMM message type [0].`

We now also have a different kind of result:

`A live-mutated Registration Request with a corrupted mandatory mobile-identity length reaches Open5GS, and Open5GS fails during NAS Registration Request decoding instead of only rejecting the top-level message type.`

We now also have matching proxy-side results:

`A transparent SCTP/NGAP proxy can forward clean registration traffic without breaking the baseline flow, and the same proxy can reproduce all earlier first-message NAS message-type mutations directly on the live gNB -> AMF path.`

And now a stronger proxy-side result:

`A proxy-mutated Registration Request with mobile identity length 0x000d -> 0x0000 reaches Open5GS, and Open5GS fails deeper inside NAS Registration Request decoding instead of only rejecting the top-level message type.`

In noob language:

- we changed the first registration message into something invalid for that stage
- the network core noticed it
- the core rejected it safely
- and it did this consistently for at least five different malformed first NAS message types
- we also confirmed a second mutation family: corrupting a mandatory NAS IE can push Open5GS into a deeper decode-failure path
- and now we can do both kinds of experiments from a live proxy, not only from UE-side code patches

## Why this matters

This is the exact kind of outcome we want in this project:

- build a malformed control-plane message
- inject it into the live system
- observe the response of the 5G core

So this table is our first clean set of experimental results.
