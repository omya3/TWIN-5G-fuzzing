# `result_classifier.py`

## Big Picture

What this file does:

> It reads proxy, AMF, gNB, and UE logs and classifies the run into a result like `early-semantic-reject`, `deep-decoder-failure`, `unexpected-accept`, or `timeout-retry`.

In simple words:

- the proxy mutates a packet
- Open5GS/UERANSIM produce logs
- this file reads those logs
- it decides what kind of behavior happened

So this file is the **result-labeling engine**.

## Important Data Structure

### 1. `ProxyNasResultSuggestion`

**What it means**

This is the final classification output.

Example:

```python
ProxyNasResultSuggestion(
    result_class="unexpected-accept",
    note="UE log shows Initial Registration is successful",
    confidence="medium",
    evidence=[
        "ue: Initial Registration is successful",
        "gnb: Initial Context Setup Request received",
    ],
)
```

**In simple words**

```text
This run looks like unexpected-accept.
Here is the short explanation.
Here is the confidence.
Here is the evidence from logs.
```

**Why it matters**

This is what the CLI prints after classification.

## Important Helper Idea

This file uses **patterns**.

Example pattern groups:

- `_CRASH_PATTERNS`
- `_DEEP_DECODER_PATTERNS`
- `_EARLY_REJECT_PATTERNS`
- `_UE_TIMER_RETRY_PATTERNS`
- `_UE_SUCCESS_PATTERNS`

That means the classifier is basically asking:

```text
Do the logs contain text that looks like a crash?
Do they contain text that looks like decoder failure?
Do they contain text that looks like early semantic rejection?
Do they contain timer expiry?
Do they contain registration success?
```

So this is a **rule-based log classifier**.

## Important Functions

### 2. `classify_proxy_nas_result_logs(logs_dir)`

This is the simplest top-level function.

**What it does**

It loads the four log files from a run directory:

- `proxy.log`
- `amf.log`
- `gnb.log`
- `ue.log`

Then it passes their text to the main classifier.

**Input**

Example:

```python
classify_proxy_nas_result_logs(
    Path("~/twin-traces/nas-campaign/demo-initial-mobile-identity-toggle").expanduser()
)
```

**Output**

Something like:

```python
ProxyNasResultSuggestion(
    result_class="unexpected-accept",
    note="UE log shows Initial Registration is successful",
    confidence="medium",
    evidence=[
        "ue: Initial Registration is successful",
        "gnb: Initial Context Setup Request received",
    ],
)
```

**In simple words**

```text
Read the logs from this run directory and classify the result.
```

**Why it matters**

This is the function your CLI command eventually uses.

### 3. `classify_proxy_nas_result_texts(...)`

This is the **most important function in the file**.

**What it does**

It contains the real decision logic.

It takes raw text for:

- AMF log
- UE log
- gNB log
- proxy log

and decides the result class.

**Input**

Example:

```python
classify_proxy_nas_result_texts(
    amf_text="...Unknown Mobile Identity type [6]...\n...Registration complete...",
    ue_text="...Initial Registration is successful...",
    gnb_text="...Initial Context Setup Request received...",
    proxy_text="...toggling mobile identity type bits...",
)
```

**Output**

Example:

```python
ProxyNasResultSuggestion(
    result_class="unexpected-accept",
    note="UE log shows Initial Registration is successful",
    confidence="high",
    evidence=[
        "amf: Unknown Mobile Identity type [6]",
        "ue: Initial Registration is successful",
        "gnb: Initial Context Setup Request received",
    ],
)
```

**In simple words**

```text
Look at all the logs together and decide what kind of behavior happened.
```

**Why it matters**

This is the heart of the classifier.

## Important Internal Logic

### 4. `_first_attempt_amf_window(...)`
### 5. `_first_attempt_ue_window(...)`
### 6. `_first_attempt_gnb_window(...)`

These are very important conceptually.

**What they do**

They try to isolate only the **first registration attempt** from the logs.

Example logic:

- AMF window starts at first `InitialUEMessage`
- UE window starts at first `Sending Initial Registration`
- gNB window starts at first `Initial NAS message received`

If a second registration attempt happens later, these helpers try to cut the log window before that.

**Why this matters**

Otherwise the classifier could get confused.

Example:

- first attempt failed
- UE retried
- second attempt succeeded

Without windowing, classifier might wrongly think the first attempt was simply successful.

**In simple words**

They say:

```text
Only look at the first attempt first, not the whole long log at once.
```

This is especially important for `timeout-retry`.

### 7. `_matching_event_message(...)` and `_matching_text_line(...)`

**What they do**

They search log messages for the first matching pattern.

### Example

If patterns include:

```text
Invalid 5GMM message type
Invalid extended_protocol_discriminator
Unknown reg_type
```

then these functions scan the messages and return the first matching line.

**In simple words**

They say:

```text
Find me the first important line in the logs that matches this behavior.
```

### 8. `_clean_note(prefix, message)`

**What it does**

It cleans a raw log line and turns it into a short note.

**Input**

Example:

```python
_clean_note("AMF log shows", "Invalid 5GMM message type [92] (../src/...)")
```

**Output**

```python
"AMF log shows Invalid 5GMM message type [92]"
```

**In simple words**

It says:

```text
Take a noisy log line and turn it into a cleaner summary sentence.
```

### 9. `_gnb_first_attempt_success_message(...)`

**What it does**

It checks whether gNB log contains success-like signs, such as:

- `PDU session resource(s) setup`
- `Initial Context Setup Request received`

**Why it matters**

Sometimes AMF logs show errors, but gNB/UE logs show that the system still moved forward.

That is one of the clues for:

```text
unexpected-accept
```

## How the Classifier Decides the Result

This is the most important part.

Inside `classify_proxy_nas_result_texts(...)`, it checks roughly in this order:

### Case A: Proxy crash

If proxy log matches crash patterns like:

- segmentation fault
- core dumped
- fatal
- assert

then result becomes:

```text
proxy-crash
```

### Case B: AMF crash

If AMF log matches crash patterns:

```text
amf-crash
```

### Case C: Deep decoder failure

If AMF log contains patterns like:

- `ogs_nas_5gs_decode_... failed`
- `ogs_pkbuf_pull() failed`
- `decode_5gs_mobile_identity`
- `Unknown type(0x..) or not implemented`

then result becomes:

```text
deep-decoder-failure
```

But if decoder-failure evidence is present **and** UE success is also present, then it upgrades to:

```text
unexpected-accept
```

because the malformed input still ended in success.

### Case D: Early semantic reject

If AMF log contains patterns like:

- `Invalid 5GMM message type`
- `Invalid extended_protocol_discriminator`
- `Not implemented(security header type:...)`
- `Unknown reg_type[...]`
- `Registration reject [...]`

then result becomes:

```text
early-semantic-reject
```

But again, if early-reject evidence is present **and** UE success is also present, then it becomes:

```text
unexpected-accept
```

because the system still accepted/recovered enough for success.

### Case E: Success without strong AMF error

If UE log shows:

- `Initial Registration is successful`
- or `PDU Session establishment is successful`

then result becomes:

```text
unexpected-accept
```

with medium confidence.

Why? Because in the mutation setting, successful completion of a malformed case is considered interesting permissive behavior.

### Case F: Timer expiry / retry

If UE log shows:

- `NAS timer[3510] expired`
- `NAS timer[3511] expired`

then result becomes:

```text
timeout-retry
```

This was your Requested NSSAI invalid-length case.

### Case G: Fallback

If none of the stronger patterns match, but AMF has some error, it falls back to:

```text
early-semantic-reject
```

If nothing decisive exists, it falls back to:

```text
timeout-retry
```

with low confidence.

## Concrete Examples from the Project

### Example 1: Message Type Substitution

AMF log:

```text
Invalid 5GMM message type [92]
```

UE success lines absent.

**Classification**

```text
early-semantic-reject
```

### Example 2: Mobile Identity Type-Bit Toggle

AMF log:

```text
Unknown Mobile Identity type [6]
Unknown SUCI type [6]
```

UE log:

```text
Initial Registration is successful
PDU Session establishment is successful
```

**Classification**

```text
unexpected-accept
```

Why?

Because the AMF clearly saw malformed identity semantics, but the UE still completed registration.

### Example 3: Requested NSSAI Invalid Length

UE log:

```text
NAS timer[3510] expired [1]
```

Later there may be success after retry.

**Classification**

```text
timeout-retry
```

Because the first attempt stalled and retried.



Imp functions:

1. `ProxyNasResultSuggestion`
2. `classify_proxy_nas_result_logs(...)`
3. `classify_proxy_nas_result_texts(...)`
4. `_first_attempt_amf_window(...)`
5. `_first_attempt_ue_window(...)`
6. `_first_attempt_gnb_window(...)`

Other functions:

7. `_matching_event_message(...)`
8. `_matching_text_line(...)`
9. result pattern groups like `_EARLY_REJECT_PATTERNS`, `_DEEP_DECODER_PATTERNS`, `_UE_SUCCESS_PATTERNS`

## Conclusion

> `result_classifier.py` is the result-labeling layer of the framework. It reads AMF, UE, gNB, and proxy logs from one run, extracts the first-attempt log window, searches for known error and success patterns, and converts the raw logs into a structured result such as early-semantic-reject, deep-decoder-failure, unexpected-accept, timeout-retry, amf-crash, or proxy-crash. This gives the campaign a consistent way to summarize outcomes from live mutation runs.
