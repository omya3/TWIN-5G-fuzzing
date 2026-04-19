# First NAS Message Type Results

## Why this file exists

This file tracks one very specific experiment family:

- take the first NAS message in the registration flow
- replace its message type byte
- send it into the live system
- record what the system does

In simple words:

- we are asking:
  - "What happens if the very first NAS message is the wrong kind of message?"

## What “success” means here

For this experiment family, success does **not** mean registration succeeds.

Success means:

- the malformed first NAS message really gets sent
- the gNB does not crash
- the malformed message reaches `Open5GS`
- we record how `Open5GS` reacts

## Result matrix

| Message type code | Intended label | UE mutation fired | gNB forwarded | AMF received `InitialUEMessage` | AMF result | Interpretation |
| --- | --- | --- | --- | --- | --- | --- |
| `0x5c` | `Identity response` | yes | yes | yes | `Invalid 5GMM message type [92]` | `Open5GS` rejected the malformed first NAS cleanly |
| `0x56` | `Authentication request` | yes | yes | yes | `Invalid 5GMM message type [86]` | `Open5GS` again rejected the malformed first NAS cleanly |
| `0x57` | `Authentication response` | yes | yes | yes | `Invalid 5GMM message type [87]` | `Open5GS` again rejected the malformed first NAS cleanly |
| `0x5d` | `Security mode command` | yes | yes | yes | `Invalid 5GMM message type [93]` | `Open5GS` again rejected the malformed first NAS cleanly |
| `0x00` | `Arbitrary / unknown value` | yes | yes | yes | `Invalid 5GMM message type [0]` | `Open5GS` again rejected the malformed first NAS cleanly |

## Noob-friendly interpretation

### `0x5c` test

We changed the first NAS message into `Identity response`.

What happened:

- UE definitely sent the mutated message
- gNB forwarded it
- AMF received it
- AMF rejected it with invalid 5GMM message type `92`

That means:

- the core network noticed the message was wrong for that stage
- the core cleaned up the context instead of crashing

### `0x56` test

We changed the first NAS message into `Authentication request`.

What happened:

- UE definitely sent the mutated message
- gNB forwarded it
- AMF received it
- AMF rejected it with invalid 5GMM message type `86`

That means:

- the end-to-end injection path works for more than one malformed first NAS type
- Open5GS is consistently rejecting these bad first-message types

### `0x57` test

We changed the first NAS message into `Authentication response`.

What happened:

- UE definitely sent the mutated message
- gNB forwarded it
- AMF received it
- AMF rejected it with invalid 5GMM message type `87`

That means:

- the same end-to-end malformed-message path still works for a third wrong first NAS type
- Open5GS is behaving consistently across multiple malformed first-message cases

### `0x5d` test

We changed the first NAS message into `Security mode command`.

What happened:

- UE definitely sent the mutated message
- gNB forwarded it
- AMF received it
- AMF rejected it with invalid 5GMM message type `93`

That means:

- the end-to-end malformed first-message harness now works for four tested message types
- Open5GS is still rejecting the malformed first NAS cleanly instead of crashing
- this case looked slightly different on the gNB side because the fail-open exception line was not printed

### `0x00` test

We changed the first NAS message into `0x00`, which is an arbitrary low-value code rather than one of the real first-message NAS types we observed in the clean run.

What happened:

- UE definitely sent the mutated message
- gNB forwarded it
- AMF received it
- AMF rejected it with invalid 5GMM message type `0`

That means:

- the same end-to-end malformed-message harness also works for a more arbitrary message-type value
- Open5GS is still rejecting the malformed first NAS cleanly
- in this run, just like `0x5d`, the gNB forwarded the message without printing the fail-open exception line

## Important evidence pattern

For all successful end-to-end malformed-message tests so far, the logs showed the same broad pattern:

### UE side

- mutation warning printed
- no valid registration response arrived
- `T3510` expired
- UE retried using `T3511`

### gNB side

- `Initial NAS message received from UE`
- fallback AMF selection used when slice extraction failed
- malformed NAS was forwarded without crashing the gNB
- in some cases, the fail-open exception warning was printed
- in other cases, such as `0x5d` and `0x00`, the gNB still forwarded the message without printing that exception line

### AMF side

- `InitialUEMessage`
- temporary UE context creation
- `Invalid 5GMM message type [...]`
- UE context cleanup

## What we are learning from this matrix

The most important lesson so far is:

- malformed first NAS messages are reaching the core
- Open5GS is rejecting them early and explicitly
- the current malformed types tested so far do not crash the core

That is a valuable result because it means:

- the harness is working
- we can now classify how different malformed first NAS types are handled

## Important boundary of this matrix

This file is only about the "wrong first NAS message type" family.

We now also have a separate result outside this matrix:

- corrupting the mandatory mobile-identity length in the first `Registration Request`
- that malformed message still reached `Open5GS`
- but this time `Open5GS` failed deeper inside `Registration Request` decoding instead of only reporting an invalid top-level message type

In simple words:

- message-type mutations gave us one family of clean rejections
- mandatory-IE corruption gave us a different, deeper decoder failure path

## Next best test

The next natural case to try is:

- another clearly arbitrary first NAS message type such as `0x7f`

Why this is a good next step:

- it pushes beyond “wrong but still real NAS message types”
- it helps us see whether Open5GS keeps behaving consistently for more arbitrary malformed values
- it helps separate “unexpected valid enum” behavior from “completely arbitrary value” behavior

## Simple summary

So far, our mini response matrix says:

- `0x5c` as first message -> rejected by Open5GS
- `0x56` as first message -> rejected by Open5GS
- `0x57` as first message -> rejected by Open5GS
- `0x5d` as first message -> rejected by Open5GS
- `0x00` as first message -> rejected by Open5GS

That is now a small but real experimental dataset.
