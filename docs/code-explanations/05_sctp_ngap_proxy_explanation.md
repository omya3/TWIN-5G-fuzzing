# `sctp_ngap_proxy.c`

## Big Picture

What this file does:

> It sits between the gNB and the AMF, forwards SCTP NGAP traffic in both directions, and mutates one selected NAS message on the way from gNB to AMF.

In simple words:

```text
UE -> gNB -> Proxy -> AMF
AMF -> Proxy -> gNB -> UE
```

Normally the proxy just forwards packets.

But if you start it with a mutation flag like:

```bash
--mutate-mobile-identity-type-bits
```

or

```bash
--mutate-nested-optional-ie field:requested_nssai,action:omit
```

then the proxy:

1. receives the SCTP packet
2. scans the bytes
3. finds the target NAS message/field
4. changes the bytes
5. forwards the modified packet to AMF

So this file is the **live mutation engine**.

## Important Constants

At the top of the file:

```c
#define DEFAULT_LISTEN_IP "127.0.0.6"
#define DEFAULT_LISTEN_PORT 38412
#define DEFAULT_AMF_IP "127.0.0.5"
#define DEFAULT_AMF_PORT 38412
#define DEFAULT_STREAMS 10
#define BUFFER_SIZE (1024 * 1024)
```

### What these mean

- `DEFAULT_LISTEN_IP` / `DEFAULT_LISTEN_PORT`
  - where the proxy listens for the gNB connection
- `DEFAULT_AMF_IP` / `DEFAULT_AMF_PORT`
  - where the real AMF is located
- `DEFAULT_STREAMS`
  - SCTP stream count
- `BUFFER_SIZE`
  - maximum packet buffer size used by the proxy

### Why two IPs on the same machine work

Both `127.0.0.5` and `127.0.0.6` are loopback addresses.

That means:

> both are local addresses on the same machine

This lets the gNB connect to the proxy on one loopback IP, while the proxy connects to the AMF on another loopback IP, without binding both processes to the same exact IP:port pair.

## Important Structures

### 1. `struct ProxyConfig`

**What it means**

This stores all runtime settings and mutation choices.

Example fields:

- listen IP/port
- AMF IP/port
- preview length
- which mutation is enabled
- target byte/word values
- nested optional IE tag/name

**In simple words**

```text
How should the proxy run?
Which mutation mode is enabled?
What value should be written?
```

**Example**

If you run:

```bash
./sctp_ngap_proxy --mutate-initial-nas-msgtype 0x5c
```

then inside `ProxyConfig`:

```text
mutate_initial_nas_msgtype = true
initial_nas_target_msgtype = 0x5c
```

### 2. `struct ProxyRuntime`

**What it means**

This stores changing runtime state while the proxy is running.

Currently the main field is:

```c
bool selected_nas_mutation_applied;
```

**In simple words**

```text
Did we already apply the selected mutation once?
```

**Why it matters**

This prevents the proxy from mutating many packets repeatedly in one run.

So usually:

- first matching target packet gets mutated
- later packets are only forwarded

## Important Functions

### 3. `parse_args(int argc, char **argv)`

**What it does**

It reads the CLI arguments and fills `ProxyConfig`.

**Input**

Example command:

```bash
./sctp_ngap_proxy --preview-bytes 24 --mutate-mobile-identity-type-bits
```

**Output**

A `ProxyConfig` object like:

```text
preview_bytes = 24
mutate_mobile_identity_type_bits = true
all other mutation flags = false
```

**In simple words**

```text
Read the command line and decide what mutation mode the proxy should use.
```

**Very important detail**

This function also makes sure only **one mutation mode** is enabled at a time.

So if you try to combine too many mutation flags, it exits with an error.

### 4. `parse_nested_optional_ie_spec(...)`

This is important for the newer generic later-packet mutations.

**What it does**

It reads a generic nested optional-IE mutation specification.

**Input**

Example:

```text
field:requested_nssai,action:bad-length,length:0xff
```

**Output**

It sets config fields like:

```text
nested_optional_ie_tag = 0x2f
nested_optional_ie_name = "Requested NSSAI"
mutate_nested_optional_ie_bad_length = true
nested_optional_ie_bad_length_target = 0xff
```

**In simple words**

```text
Take the generic spec string and convert it into concrete config flags.
```

**Why it matters**

This is what lets the newer system support generic flags like:

```bash
--mutate-nested-optional-ie field:fivegmm_capability,action:omit
```

instead of only old hardcoded flags.

### 5. `configure_nested_optional_ie_field(...)`

**What it does**

It maps a field name to the correct optional IE tag.

**Input**

Example:

```c
configure_nested_optional_ie_field(&cfg, "requested_nssai");
```

**Output**

It sets:

```text
nested_optional_ie_tag = 0x2f
nested_optional_ie_name = "Requested NSSAI"
```

Another example:

```c
configure_nested_optional_ie_field(&cfg, "fivegmm_capability");
```

**Output**

```text
nested_optional_ie_tag = 0x10
nested_optional_ie_name = "5GMM capability"
```

**In simple words**

```text
If the user asked for Requested NSSAI, which IE tag should we search for?
```

### 6. `relay_loop_with_config(...)`

This is one of the most important functions.

**What it does**

This is the main forwarding loop.

**Input**

It receives:

- config
- runtime
- `gnb_fd`
- `amf_fd`

**What it does internally**

It waits on both sockets using `select()`:

- if gNB sent a packet, process it
- if AMF sent a packet, process it

Then it calls:

```c
forward_one_message(...)
```

**In simple words**

```text
Keep listening to both sides and keep forwarding packets until the session ends.
```

**Why it matters**

This is the core loop that keeps the proxy alive.

### 7. `forward_one_message(...)`

This is another very important function.

**What it does**

It handles one SCTP packet.

**Steps inside**

1. receive SCTP packet using `sctp_recvmsg`
2. ignore SCTP notifications
3. print direction, byte count, stream, PPID
4. print preview bytes
5. call mutation function:
   ```c
   maybe_patch_selected_nas(...)
   ```
6. send packet onward using `sctp_sendmsg`

**Input**

Conceptually:

```text
from_fd = gNB socket
to_fd = AMF socket
buffer = raw SCTP payload
```

**Output**

It forwards the same packet, or the mutated packet.

**In simple words**

```text
Receive one packet, maybe mutate it, then send it to the other side.
```

**Why it matters**

This is the packet-level worker function.

### 8. `maybe_patch_selected_nas(...)`

This is the **most important mutation function in the file**.

**What it does**

It looks inside the raw packet bytes and applies the selected mutation if it finds the target NAS message.

**Very important guards**

It first checks:

- is any mutation enabled?
- was mutation already applied once?
- is the packet going from gNB to AMF?
- is packet large enough?

So the mutation only happens when:

```text
uplink packet
first matching target
selected mutation enabled
```

## How Initial Registration Request Mutations Work

For early mutations like:

- message type
- security header
- registration-type/ngKSI
- mobile identity length
- mobile identity tail
- identity type bits

the code scans the packet for a baseline pattern like:

```text
0x7e 0x00 0x41
```

or sometimes:

```text
0x7e 0x00 0x41 0x79 0x00 0x0d
```

Meaning:

```text
0x7e = 5GS MM EPD
0x00 = plain security header
0x41 = Registration Request
0x79 = registration-type/ngKSI
0x000d = mobile identity length
```

Then it changes the relevant byte.

### Example A: Message Type Mutation

**Matching logic**

The code searches for:

```c
buffer[i] == 0x7e
buffer[i + 1] == 0x00
buffer[i + 2] == 0x41
```

**Mutation**

Then it does:

```c
buffer[i + 2] = cfg->initial_nas_target_msgtype;
```

**Input example**

Before:

```text
7e 00 41 79 00 0d ...
```

After:

```text
7e 00 5c 79 00 0d ...
```

**In simple words**

```text
Find the Registration Request message type byte and replace it.
```

### Example B: Security Header Mutation

**Mutation**

It changes:

```c
buffer[i + 1] = cfg->initial_nas_target_security_header;
```

**Example**

Before:

```text
7e 00 41 ...
```

After:

```text
7e 02 41 ...
```

**In simple words**

```text
Find the plain security header and replace it with a protected/invalid value.
```

### Example C: Registration-Type/ngKSI Mutation

**Mutation**

It changes:

```c
buffer[i + 3] = cfg->registration_type_and_ngksi_target;
```

**Example**

Before:

```text
7e 00 41 79 ...
```

After:

```text
7e 00 41 00 ...
```

### Example D: Mobile Identity Length Mutation

**Mutation**

It changes two bytes:

```c
buffer[i + 4] = high byte
buffer[i + 5] = low byte
```

**Example**

Before:

```text
7e 00 41 79 00 0d ...
```

After:

```text
7e 00 41 79 00 ff ...
```

### Example E: Identity Type-Bit Toggle

**Mutation**

It changes:

```c
buffer[i + 6] = 0x06;
```

**Example**

Before:

```text
7e 00 41 79 00 0d 01 ...
```

After:

```text
7e 00 41 79 00 0d 06 ...
```

This was the Demo 1 mutation.

## How Later Nested Registration Request Mutations Work

This is the newer and more interesting part.

Inside `maybe_patch_selected_nas(...)`, the code has a branch for:

- omit IE
- bad length
- duplicate IE
- unsupported SST/SD
- duplicate payload entries
- set reserved bits
- truncate payload

**Matching logic**

It scans the packet for a nested Registration Request pattern:

```c
buffer[start]     == 0x7e
buffer[start + 1] == 0x00
buffer[start + 2] == 0x41
buffer[start + 3] == 0x79
```

So it is looking for a later embedded plain Registration Request body.

**Then it computes:**

```c
mobile_identity_length = ((buffer[start + 4] << 8) | buffer[start + 5]);
tlv_offset = start + 6 + mobile_identity_length;
```

Meaning:

```text
start + 6 = beginning of mobile identity value
+ mobile_identity_length = end of mandatory identity field
after that = optional TLV region begins
```

Then it walks the optional IE region as:

```text
tag length value
tag length value
tag length value
...
```

### Example F: Requested NSSAI Omit

If it finds:

```text
tag == 0x2f
```

and omit mode is enabled, it does:

```c
remove_octet_span(buffer, n_inout, pos, total_length);
```

**Before**

```text
... 2f 02 01 01 ...
```

**After**

```text
... [that whole IE removed] ...
```

This was one of the live later-packet mutations.

### Example G: Requested NSSAI Bad Length

If it finds tag `0x2f` and bad-length mode is enabled, it changes:

```c
buffer[pos + 1] = cfg->nested_optional_ie_bad_length_target;
```

**Before**

```text
... 2f 02 01 01 ...
```

**After**

```text
... 2f ff 01 01 ...
```

This was the `timeout-retry` case.

### Example H: 5GMM Capability Omit

If it finds tag `0x10` and omit mode is enabled, it removes the IE.

**Before**

```text
... 10 01 00 ...
```

**After**

```text
... [removed] ...
```

This was Demo 2.

## Helper Functions for Byte Editing

### 9. `remove_octet_span(...)`

**What it does**

It deletes a span of bytes from the buffer.

**Code idea**

It uses `memmove` to shift later bytes left:

```c
memmove(buffer + offset,
        buffer + offset + length,
        *n_inout - (offset + length));
*n_inout -= length;
```

**In simple words**

```text
Remove these bytes and close the gap.
```

**Why it matters**

Used for:

- omit IE
- truncate payload

### 10. `duplicate_octet_span(...)`

**What it does**

It copies a span of bytes and inserts it again somewhere else in the same packet.

**In simple words**

```text
Take these bytes and duplicate them into the packet.
```

**Why it matters**

Used for:

- duplicate IE
- duplicate payload entries

## `main(...)`

### 11. `main(int argc, char **argv)`

**What it does**

This sets up and starts the proxy.

**Steps**

1. install signal handlers
2. parse CLI args into `ProxyConfig`
3. print enabled mutation mode
4. create SCTP listener
5. accept gNB connection
6. connect to real AMF
7. initialize runtime
8. enter relay loop

**In simple words**

```text
Start the proxy, wait for gNB, connect to AMF, then begin forwarding and mutating packets.
```


Imp functions:

1. `struct ProxyConfig`
2. `parse_args(...)`
3. `relay_loop_with_config(...)`
4. `forward_one_message(...)`
5. `maybe_patch_selected_nas(...)`
6. `remove_octet_span(...)`
7. `main(...)`

Other functions:

- `parse_nested_optional_ie_spec(...)`
- `configure_nested_optional_ie_field(...)`
- `duplicate_octet_span(...)`

## Conclusion

> `sctp_ngap_proxy.c` is the live packet-mutation engine. It sits between the gNB and the AMF, forwards SCTP NGAP traffic in both directions, and applies one selected mutation to an uplink NAS message before forwarding it to the AMF. The main loop receives packets, logs preview bytes, calls the mutation function, and sends the modified packet onward. Early mutations directly patch the first plain Registration Request, while newer later-packet mutations scan for a nested Registration Request and edit optional IEs such as Requested NSSAI and 5GMM capability.
