# Proxy Implementation Roadmap

## Goal

Build a small proxy between `UERANSIM gNB` and `Open5GS AMF`.

In simple words:

- `gNB` sends NGAP traffic to the proxy
- the proxy forwards it to the real `AMF`
- later, the proxy mutates selected messages before forwarding

The first milestone is intentionally transport-only. No mutation is performed yet.

## Why transport-only first

If the proxy cannot forward clean traffic correctly, mutation results will be confusing.

So the first milestone is:

- `gNB -> proxy -> AMF`
- `NG Setup` succeeds
- clean UE registration still works
- proxy logs message size, stream, and PPID

Only after this should we add NGAP decode and NAS mutation.

## Stage 1: Transparent SCTP/NGAP Relay

Implemented prototype:

- `proxy/sctp_ngap_proxy.c`
- `proxy/Makefile`

This relay:

- listens for SCTP from the gNB
- connects to the real AMF using SCTP
- forwards messages in both directions
- preserves SCTP stream id and PPID
- logs a short hex preview of each SCTP user message
- can optionally patch the first uplink plain NAS signature `7e 00 41`
  by changing the message-type byte to a selected value such as `0x5c`

Suggested same-host addressing:

```text
real AMF:     127.0.0.5:38412
proxy listen: 127.0.0.6:38412
gNB target:   127.0.0.6:38412
```

## Stage 2: Minimal Inspect/Mutate Mode

Before a full NGAP decoder is added, the proxy can already:

- log the first few bytes of every SCTP user message
- search uplink traffic for the plain NAS registration signature
  `7e 00 41`
- patch that first NAS message-type byte to a chosen value

This is intentionally smaller than full ASN.1 decoding, but it is enough
to reproduce the known live mutation result through the proxy path.

## Stage 3: First NAS Mutation Through Proxy

Reproduce the known UE-side result:

```text
0x41 Registration Request -> 0x5c Identity Response
```

Success condition:

```text
AMF receives InitialUEMessage
AMF logs Invalid 5GMM message type [92]
```

This confirms that proxy-side NAS mutation behaves like the earlier UE-side hook.
The current C proxy supports this as:

```text
./sctp_ngap_proxy --mutate-initial-nas-msgtype 0x5c
```

## Stage 4: Add Existing NAS Policies

After `0x41 -> 0x5c` works, add:

- `0x41 -> 0x56`
- `0x41 -> 0x57`
- `0x41 -> 0x5d`
- `0x41 -> 0x00`
- mobile identity length `0x000d -> 0x0000`

These policies already exist locally in `src/ngap_nas_fuzz/proxy_policy.py`.

## Stage 5: Add Stateful NGAP Mutations

Once the proxy can safely decode/re-encode NGAP, use the offline mutation traces as scripts:

- duplicate `InitialContextSetupResponse`
- reorder `InitialContextSetupRequest` and `InitialContextSetupResponse`
- change `AMF_UE_NGAP_ID`

In simple words:

- the mutated trace tells the proxy what to do
- the live message comes from the current gNB-AMF traffic
- the proxy applies the mutation to live traffic

## Stage 6: Campaign Runner

Later, add a small runner that executes a list of mutations and saves:

- mutation used
- UE log
- gNB/proxy log
- AMF log
- classification result

Example classifications:

- clean reject
- invalid message type
- NAS decoder failure
- context cleanup
- timeout
- gNB crash
- AMF crash

## Stage 7: Wider Spec-Driven Mutation Catalog

For NAS:

- use TS 24.501 to build a custom NAS mutation catalog
- NAS is not ASN.1-defined, so this must be custom/spec-informed

For NGAP:

- use ASN.1/PER structure
- later consider ASNFuzzGen or ASN.1-derived mutation operators

This is future work after the proxy MVP works.
