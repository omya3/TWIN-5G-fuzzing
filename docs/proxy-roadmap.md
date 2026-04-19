# Proxy Roadmap

## Why this roadmap exists

We already proved the live mutation path with a direct UE-side patch.

That gave us:

- multiple malformed first NAS message-type results
- one deeper mandatory-IE corruption result

The next step is to move the mutation point out of the UE and into a proxy
between the `gNB` and `AMF`.

## Big picture

The proxy will sit here:

```text
UERANSIM gNB  --->  Proxy  --->  Open5GS AMF
```

The proxy will see `NGAP` traffic.

Inside some `NGAP` messages, especially `InitialUEMessage`, the proxy will
extract the embedded `NAS-PDU`, apply a selected mutation rule, and then
forward the modified `NGAP` message to the real `AMF`.

In simple words:

- `NGAP` is the envelope
- `NAS` is the letter inside the envelope
- the proxy opens the envelope, edits the letter, closes the envelope, and forwards it

## Roadmap stages

### Stage 1: transparent relay

Build a relay that:

- accepts traffic from `gNB`
- opens a connection to the real `AMF`
- forwards everything unchanged

Success condition:

- `NG Setup` succeeds through the proxy
- clean registration succeeds through the proxy

### Stage 2: logging relay

Add only visibility:

- direction of traffic
- message length
- packet counts

Success condition:

- we can confirm the traffic path without changing message behavior

### Stage 3: selective decode

Decode only enough `NGAP` to recognize:

- `InitialUEMessage`
- `DownlinkNASTransport`
- `UplinkNASTransport`
- `InitialContextSetupRequest`
- `InitialContextSetupResponse`

Success condition:

- the proxy can identify `InitialUEMessage`
- all other traffic still forwards unchanged

### Stage 4: first known-good proxy mutation

Apply the first known mutation:

- first NAS message type `0x41 -> 0x5c`

Success condition:

- `Open5GS` reports `Invalid 5GMM message type [92]`

This reproduces the already-known live UE result, but now through the proxy.

### Stage 5: expand NAS mutation policies

Add the NAS mutations we already understand:

- `0x41 -> 0x56`
- `0x41 -> 0x57`
- `0x41 -> 0x5d`
- `0x41 -> 0x00`
- mobile-identity length `0x000d -> 0x0000`

Success condition:

- proxy reproduces the same AMF behaviors we already observed in the UE-hook runs

### Stage 6: campaign runner

Add a small driver that:

- selects one mutation
- runs a test
- collects logs
- records the AMF outcome

Success condition:

- results are reproducible and easy to compare

### Stage 7: stateful NGAP mutations

Move beyond the first NAS message and use the proxy for later-message mutations:

- duplicate `InitialContextSetupResponse`
- reorder `InitialContextSetupRequest` and `InitialContextSetupResponse`
- rewrite `AMF_UE_NGAP_ID`

Success condition:

- the proxy applies these live mutation scripts to real traffic

## NAS plan

For NAS, we will use custom spec-informed mutation rules.

Why:

- `NAS` is defined in `TS 24.501`
- but `NAS` is not specified as `ASN.1`
- so we cannot rely on generic ASN.1 tooling to generate NAS mutations automatically

So our NAS strategy is:

1. start from a clean valid NAS message
2. mutate a meaningful field
3. forward it live
4. classify the AMF behavior

## NGAP plan

For NGAP, we can be more systematic later because:

- `NGAP` is `ASN.1` / `PER` based
- later, this makes ASN.1-aware mutation tooling more useful

But the first proxy milestone should still stay simple:

- do not fuzz all NGAP fields yet
- only forward traffic
- then mutate only the embedded NAS

## Immediate implementation target

The first implementation target in this repository is:

- local proxy-style mutation simulation
- then remote transport-only relay
- then real proxy-side mutation
