# NAS Message-State Mutation Catalog

## Why this file exists

This file defines the NAS-side mutation space in a more rigorous way.

In simple words:

- instead of saying "we fuzz NAS randomly"
- we say "for each NAS message, in each state, these mutation families are meaningful"

This helps the project become:

- more systematic
- easier to explain in a report or presentation
- easier to grow toward broader coverage over time

## Coverage idea

We do not claim that the whole NAS specification is covered yet.

Instead, we define coverage in layers:

1. `message coverage`
2. `state/context coverage`
3. `information-element coverage`
4. `mutation-family coverage`
5. `result-class coverage`

This document focuses on the first four layers.

## Manual schema in this project

When we say `manual NAS schema`, we do not mean guessing random fields by hand.

We mean:

1. start from a real working NAS packet captured in the current setup
2. use `TS 24.501` to understand what the visible fields mean
3. write those fields down explicitly with:
   - field name
   - field kind
   - mandatory vs optional
   - baseline value
   - location hint
   - state/precondition

In simple words:

```text
real packet layout + protocol meaning = manual NAS schema
```

That schema then becomes the input to:

```text
manual NAS schema -> automatic mutation generation -> scheduler -> proxy run
```

## Current message set

The current catalog covers five NAS message families at useful depth:

1. `Registration Request`
2. `Identity Response`
3. `Authentication Response`
4. `Security Mode Complete`
5. `PDU Session Establishment Request`

This gives the project a respectable message spread across:

- initial registration entry
- identity procedure
- authentication procedure
- security completion
- post-registration session setup

## Message catalog

### 1. Registration Request

**Message type**

```text
0x41
```

**Normal role**

This is the normal first uplink NAS message in 5G registration.

**Why it matters**

This is the best first fuzzing target because it is:

- early in the protocol
- unauthenticated
- always present in normal registration
- already proven reachable in our live experiments

**Mutation families**

| Family | Target | Example operators | Why it matters |
| --- | --- | --- | --- |
| message-type substitution | 5GMM message type octet | `0x41 -> 0x5c`, `0x56`, `0x57`, `0x5d`, `0x00` | tests early semantic rejection |
| security-header mutation | plain NAS security header | `0x00 -> protected or inconsistent values` | tests security-context assumptions |
| mobile-identity length corruption | mobile identity length field | `0x000d -> 0x0000`, `0x0001`, `0x000c`, `0x00ff` | tests deeper mandatory-IE decoding with nearby boundary variants |
| mobile-identity value corruption | SUCI/mobile identity contents | invalid BCD, truncation, bad type bits | tests identity parser robustness |
| requested NSSAI corruption | optional Requested NSSAI IE | invalid length, bad SST/SD, duplicates | tests optional IE parsing and policy handling |
| 5GMM capability corruption | 5GMM capability IE | truncation, oversized length, reserved bits | tests deeper Registration Request parsing |

### 2. Identity Response

**Message type**

```text
0x5c
```

**Normal role**

This should only be sent after the `AMF` sends an `Identity Request`.

**Why it matters**

It is a strong state-aware target because it is clearly invalid as the first NAS message.

**Mutation families**

| Family | Target | Example operators | Why it matters |
| --- | --- | --- | --- |
| wrong-state delivery | procedure timing | send as first NAS message | tests state tracking |
| identity payload corruption | mobile identity value | invalid BCD, unsupported identity type, truncation | tests identity-specific decode logic |
| length inconsistency | identity length field | zero length, too short, too long | tests internal length validation |

### 3. Authentication Response

**Message type**

```text
0x57
```

**Normal role**

This should only be sent after `Authentication Request`.

**Why it matters**

It is another strong state-aware target, and it opens the door to mutating authentication-specific payloads.

**Mutation families**

| Family | Target | Example operators | Why it matters |
| --- | --- | --- | --- |
| wrong-state delivery | procedure timing | send as first NAS message, send before challenge | tests state enforcement |
| authentication parameter corruption | RES* / response parameter | truncate, oversize, all-zero value | tests deeper authentication parsing |
| extra trailing payload | message body layout | append extra bytes, inconsistent length | tests parser strictness on body format |

### 4. Security Mode Complete

**Message type**

```text
0x5e
```

**Normal role**

This should appear only after `Security Mode Command` and usually under a protected NAS header.

**Why it matters**

This gives us a good later-stage message where state and security-header expectations matter together.

**Mutation families**

| Family | Target | Example operators | Why it matters |
| --- | --- | --- | --- |
| wrong-state delivery | procedure timing | send too early, send without Security Mode Command | tests state tracking |
| security-header inconsistency | protection context | plain header when protected header is expected | tests header/semantics consistency |
| optional IE corruption | optional payload IEs | bad length, duplicate IE, unknown IE tag | tests later-message optional parsing |

### 5. PDU Session Establishment Request

**Message type**

```text
5GSM payload family
```

**Normal role**

This appears after successful registration when the UE asks for a data session.

**Why it matters**

This extends the project beyond the first registration message and shows that the NAS campaign is not limited to one early 5GMM packet.

**Mutation families**

| Family | Target | Example operators | Why it matters |
| --- | --- | --- | --- |
| wrong-state delivery | procedure timing | send before registration completes | tests session-state enforcement |
| session IE corruption | DNN / S-NSSAI / session type | truncate DNN, invalid session type, malformed S-NSSAI | tests later NAS session parsing |

## Result classes

Every executed mutation should be classified into one of these result classes:

| Result class | Meaning |
| --- | --- |
| `early semantic reject` | message rejected quickly because the message meaning is wrong for the current state |
| `deep decoder failure` | message entered deeper parsing and failed on a field or IE |
| `timeout/retry` | UE timed out and retried because no useful response came back |
| `unexpected accept` | malformed message was accepted |
| `AMF crash` | AMF process terminated unexpectedly |
| `proxy crash` | proxy process terminated unexpectedly |

## Scheduler idea

The scheduler should not choose mutations randomly.

Instead, it should use three inputs:

1. current NAS message
2. current procedure state
3. previous result history

The current scheduler prototype follows these simple rules:

- prefer `high` priority mutation families
- prefer operators that are `untried`
- prefer operators that are `supported by the current proxy`
- if a family has already produced only `early semantic reject`, start exploring a different family
- if a family has produced `deep decoder failure`, explore nearby operators in the same family
- if a family ever produces `unexpected accept` or `AMF crash`, prioritize that family strongly

In simple words:

```text
If a mutation is too shallow, try a different family.
If a mutation reaches deeper parsing, explore more variants around it.
```

## Why this is good for the presentation

This catalog helps present the work as a structured fuzzing framework, not just a few ad hoc test cases.

In simple words, you can now say:

```text
I am not mutating NAS randomly.
I have started building a message-by-message, state-aware NAS mutation catalog.
Right now the catalog covers five important NAS message families with multiple mutation families each.
```

## Practical next implementation step

The next engineering step should be:

1. pick one message as the current execution focus
2. list all its mutation families
3. let the scheduler pick mutations based on:
   - current message
   - current procedure state
   - previous result class

For the immediate next phase, `Registration Request` should remain the main focus because it already has:

- live proxy support
- the richest current evidence
- multiple known mutation families

After that, `Identity Response` and `Authentication Response` are the best next messages to operationalize because they are easy to explain and strongly state-dependent.
