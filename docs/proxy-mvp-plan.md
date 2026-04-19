# Proxy MVP Plan

## Why we are building a proxy now

We already proved two important things with the live UE-side patch:

- wrong first NAS message types can reach `Open5GS`
- a corrupted mandatory NAS IE can also reach `Open5GS` and trigger deeper decoder failures

In simple words:

- the experiment loop works
- now we want to stop editing the UE for every new case
- the proxy is the next cleaner architecture

## What this proxy is and is not

This proxy MVP is:

- a thin relay between `gNB` and `AMF`
- focused only on `NGAP`
- interested only in `InitialUEMessage`
- interested only in the embedded `NAS-PDU`

This proxy MVP is not:

- a full fuzzing framework
- a full `RANsacked` reimplementation
- a complete ASN.1 generation system

## Why we are not using ASNFuzzGen first

`ASNFuzzGen` is useful for structure-aware ASN.1 generation and is a good fit for `NGAP`.

But for this MVP, the hard problem is not ASN.1 fuzz generation. The hard problem is:

- accept SCTP from `gNB`
- connect SCTP to the real `AMF`
- decode `InitialUEMessage`
- mutate `NAS-PDU`
- re-encode and forward it

Also, our first mutations are still NAS-focused, and NAS itself is not defined using ASN.1.

So the right first move is:

- build a small custom relay
- keep the mutation logic simple
- bring in `ASNFuzzGen` later if we expand into richer `NGAP` IE fuzzing

## Minimal architecture

The smallest useful setup is:

```text
UERANSIM gNB  --->  Proxy  --->  Open5GS AMF
```

Where:

- `gNB` no longer points directly to the AMF IP
- `gNB` points to the proxy IP and port instead
- the proxy opens its own outgoing association to the real AMF

### Suggested same-host addressing

If everything stays on the same remote Ubuntu machine:

- real `AMF`: `127.0.0.5:38412`
- proxy listen address: `127.0.0.6:38412`
- `gNB` should connect to `127.0.0.6:38412`

In simple words:

- `gNB` talks to proxy
- proxy talks to `AMF`

## First feature set

The proxy should do only this:

1. receive SCTP/NGAP from `gNB`
2. decode `NGAP PDU`
3. check whether it is `InitialUEMessage`
4. extract `NAS-PDU`
5. apply one selected mutation
6. re-encode `InitialUEMessage`
7. forward it to `AMF`
8. forward everything else unchanged

## First mutation policies to support

The proxy MVP only needs to support the mutations we already understand well:

- `message-type`
- `security-header`
- `mobile-identity-length-zero`

These already exist conceptually in our local mutation logic and in the remote live UE experiments.

## Recommended implementation order

### Stage 1: local policy logic

Done in this repository:

- a reusable mutation-policy module for initial NAS mutation
- a CLI preview command to test byte-level changes on captured traces

This lets us verify:

- which bytes change
- whether the expected Registration Request prefix is present
- what the mutated `NAS-PDU` should look like

### Stage 2: remote relay skeleton

Create a process on the remote machine that:

- listens for SCTP from `gNB`
- opens SCTP to the real `AMF`
- forwards packets bidirectionally

At first, it can log traffic without mutation.

Goal:

- prove the relay path works before adding mutation

### Stage 3: decode only `InitialUEMessage`

After raw forwarding works:

- decode only uplink `InitialUEMessage`
- leave all other `NGAP` messages untouched

Goal:

- minimize complexity
- mutate only the message we already understand best

### Stage 4: inject the first NAS mutation

Add only one policy at first:

- mutate the embedded `NAS-PDU`

Recommended first proxy mutation:

- `message-type 0x41 -> 0x5c`

Why:

- we already know exactly how the core reacts
- this is a good correctness check for the proxy path

### Stage 5: move to deeper mutations

After the proxy can reproduce the known `0x5c` result:

- try `mobile-identity-length-zero`
- then try stateful later-message mutations such as `NGAP ID mismatch`

## What we should reuse

The best reuse candidates are:

- this repository's local byte-level mutation policy
- the existing `UERANSIM` NGAP ASN.1 decode/encode code on the remote box

In simple words:

- do not reinvent the byte mutation rules
- do not write a whole ASN.1 stack from scratch

## Immediate next remote tasks

Before writing the full relay, confirm these on the remote machine:

1. whether we want the proxy as:
   - a standalone new program
   - or a small fork of the existing `UERANSIM` `gNB` NGAP path
2. whether we can bind `127.0.0.6:38412`
3. where we will keep proxy logs
4. how we want to switch the `gNB` config between:
   - direct-to-AMF mode
   - proxy mode

## Recommended first milestone

The first proxy milestone should be:

- `gNB` connects to proxy
- proxy connects to `AMF`
- `NG Setup` succeeds through the proxy
- no mutation yet

Only after that should we add:

- `InitialUEMessage` decode
- `NAS-PDU` mutation

## Why this order matters

In simple words:

- if we try to build transport, ASN.1 decode, and mutation all at once, debugging becomes messy
- if we get plain forwarding working first, we know the plumbing is right
- then any later failure is much easier to explain
