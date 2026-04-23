# `nas_execution_bridge.py`

## Big Picture

What this file does:

> It connects a mutation idea from the catalog to a real execution method.

In simple words:

- `nas_catalog.py` says what mutations exist
- `nas_execution_bridge.py` says how a given mutation can actually run

the bridge uses:

- the knowledge base from the catalog
- the runtime support rules encoded in the bridge
- the actual proxy mutation IDs / CLI flags

So this file answers questions like:

- Is this operator executable now?
- Will it run in live proxy mode or only simulation?
- What proxy mutation ID should be used?
- What command-line flag should be generated?

This file is basically the **bridge between mutation definition and actual execution**.

## The Most Important Data Structure

### 1. `NasExecutionBridge`

**What it means**

This is one mapping rule between:

- message name
- mutation family
- operator pattern
- execution mode
- proxy mutation ID

Example:

```python
NasExecutionBridge(
    message_name="Registration Request",
    family_name="message-type substitution",
    proxy_mutation="message-type",
    execution_mode="proxy",
    operator_pattern=r"replace 0x41 with (0x[0-9a-f]+)",
)
```

**In simple words**

```text
If the message is Registration Request
and the family is message-type substitution
and the operator looks like "replace 0x41 with something",
then:
- this is executable
- it runs in live proxy mode
- the internal proxy mutation id is "message-type"
```

**Why it matters**

This is how the framework knows:

> this human-readable mutation operator corresponds to this runtime behavior

## Important Functions

### 2. `_matching_bridge(message_name, family_name, operator)`

**What it does**

This function searches the internal bridge table and finds the matching runtime mapping.

**Input**

Example:

```python
_matching_bridge(
    "Registration Request",
    "message-type substitution",
    "replace 0x41 with 0x5c",
)
```

**Output**

Something like:

```python
NasExecutionBridge(
    message_name="Registration Request",
    family_name="message-type substitution",
    proxy_mutation="message-type",
    execution_mode="proxy",
    operator_pattern=r"replace 0x41 with (0x[0-9a-f]+)",
)
```

If nothing matches:

```python
None
```

**In simple words**

```text
Look at this operator and tell me whether we already know how to execute it.
```

**Why it matters**

This is the first step in resolving execution.

### 3. `resolve_operator_execution(...)`

This is the **most important function in the file**.

**What it does**

It decides how a mutation operator should run.

**Input**

Example 1:

```python
resolve_operator_execution(
    message_name="Registration Request",
    family_name="message-type substitution",
    operator="replace 0x41 with 0x5c",
)
```

**Output**

Example 1:

```python
(True, "proxy", "message-type", "0x5c")
```

Meaning:

```text
True          -> executable now
"proxy"       -> run it live in proxy mode
"message-type"-> internal runtime mutation id
"0x5c"        -> value to pass to the proxy
```

---

### Another Input

Example 2:

```python
resolve_operator_execution(
    message_name="Registration Request",
    family_name="mobile-identity value corruption",
    operator="toggle identity type bits inconsistently",
)
```

**Output**

Example 2:

```python
(True, "proxy", "mobile-identity-toggle-type-bits", None)
```

Meaning:

```text
This is executable now
It runs live in proxy mode
The runtime mutation id is mobile-identity-toggle-type-bits
No numeric extra value is needed
```

---

### Another Input

Example 3:

```python
resolve_operator_execution(
    message_name="Identity Response",
    family_name="identity payload corruption",
    operator="truncation",
)
```

**Output**

Example 3:

```python
(True, "plain-simulation", "plain-nas-field-simulation", "...")
```

The last `"..."` is a serialized mutation-plan string.

Meaning:

```text
This operator is supported
But not as a live proxy mutation yet
It should run in plain-simulation mode
```

---

### If unsupported

Example 4:

```python
resolve_operator_execution(
    message_name="Some Message",
    family_name="Unknown Family",
    operator="Unknown Operator",
)
```

**Output**

```python
(False, "planned", None, None)
```

Meaning:

```text
Not executable now
Still only planned
No runtime mapping exists yet
```

**In simple words**

This function says:

```text
For this mutation operator:
- can we run it?
- how do we run it?
- what runtime id/value should be used?
```

**Why it matters**

This is the core decision point that turns a mutation idea into an execution plan.

### 4. `_live_nested_optional_ie_value(...)`

**What it does**

This creates the serialized value for live nested optional-IE mutations.

This is used for things like:

- Requested NSSAI omit
- Requested NSSAI invalid length
- 5GMM capability omit
- 5GMM capability bad length
- reserved bits
- truncation

**Input**

Example:

```python
_live_nested_optional_ie_value(
    message_name="Registration Request",
    family_name="requested NSSAI corruption",
    operator="omit IE entirely",
)
```

**Output**

Something like:

```python
"field:requested_nssai,action:omit"
```

Another example:

```python
_live_nested_optional_ie_value(
    message_name="Registration Request",
    family_name="5GMM capability corruption",
    operator="oversized length",
)
```

**Output**

Something like:

```python
"field:fivegmm_capability,action:bad-length,length:0xff"
```

**In simple words**

```text
Take a human operator like "omit IE entirely"
and convert it into the exact structured value the proxy understands.
```

**Why it matters**

This is what enables the newer generic nested optional-IE live flag.

### 5. `observation_runtime_key(...)`

**What it does**

This creates a normalized identity key for one run/observation.

**Input**

Example:

```python
observation_runtime_key(
    message_name="Registration Request",
    family_name="requested NSSAI corruption",
    operator="omit IE entirely",
    proxy_mutation="nested-requested-nssai-omit",
    proxy_value=None,
)
```

**Output**

Something like:

```python
(
    "Registration Request",
    "requested NSSAI corruption",
    "nested-registration-request-optional-ie-live",
    "field:requested_nssai,action:omit",
)
```

**What happened here?**

Even if the old run used the legacy mutation name:

```text
nested-requested-nssai-omit
```

this function normalizes it into the newer generic runtime form:

```text
nested-registration-request-optional-ie-live
field:requested_nssai,action:omit
```

**In simple words**

```text
Give me one stable normalized identity for this run,
so history comparison and bookkeeping stay consistent.
```

**Why it matters**

This helps old runs and new runs be recorded under the same consistent runtime identity.

### 6. `_normalize_legacy_proxy_runtime(...)`

**What it does**

This converts older specific proxy mutation ids into the newer generic format.

**Input**

Example:

```python
_normalize_legacy_proxy_runtime(
    "nested-fivegmm-capability-omit",
    None,
)
```

**Output**

Something like:

```python
(
    "nested-registration-request-optional-ie-live",
    "field:fivegmm_capability,action:omit",
)
```

**In simple words**

```text
If an old run used an old mutation name,
convert it into the new generic mutation format.
```

**Why it matters**

This is important for compatibility with older history entries and older scripts.

You probably only need to explain this if someone asks about:

- backward compatibility
- bookkeeping consistency
- why old and new runtime IDs both appear in history

### 7. `render_operator_for_value(base_operator, proxy_mutation, value)`

**What it does**

This rebuilds a human-readable operator string from runtime mutation info.

**Input**

Example:

```python
render_operator_for_value(
    base_operator="replace 0x41 with ?",
    proxy_mutation="message-type",
    value="0x5c",
)
```

**Output**

```python
"replace 0x41 with 0x5c"
```

Another example:

```python
render_operator_for_value(
    base_operator="set security header",
    proxy_mutation="security-header",
    value="0x02",
)
```

**Output**

```python
"set security header 0x00 -> 0x02"
```

**In simple words**

```text
Take internal runtime info and rebuild the clean human-readable operator text.
```

**Why it matters**

Useful when generating reports, summaries, or showing selected runs back to the user.

### 8. `render_proxy_command_flag(proxy_mutation, value)`

This is another very important function.

**What it does**

It converts the internal runtime mutation info into the actual proxy CLI flag.

**Input**

Example 1:

```python
render_proxy_command_flag("message-type", "0x5c")
```

**Output**

```python
" --mutate-initial-nas-msgtype 0x5c"
```

---

### Input

Example 2:

```python
render_proxy_command_flag(
    "mobile-identity-toggle-type-bits",
    None,
)
```

**Output**

```python
" --mutate-mobile-identity-type-bits"
```

---

### Input

Example 3:

```python
render_proxy_command_flag(
    "nested-registration-request-optional-ie-live",
    "field:requested_nssai,action:omit",
)
```

**Output**

```python
" --mutate-nested-optional-ie field:requested_nssai,action:omit"
```

**In simple words**

```text
Convert the framework’s internal mutation id into the exact command-line flag for the proxy.
```

**Why it matters**

This is what makes the campaign planner able to generate runnable shell commands.



Imp functions:

1. `NasExecutionBridge`
2. `_matching_bridge(...)`
3. `resolve_operator_execution(...)`
4. `render_proxy_command_flag(...)`
5. `observation_runtime_key(...)`

Other functions:

6. `_live_nested_optional_ie_value(...)`
7. `_normalize_legacy_proxy_runtime(...)`

## Summary

> `nas_execution_bridge.py` is the file that connects mutation definitions to actual runtime execution. It checks whether a human-readable operator can run now, decides whether it should run in live proxy mode or simulation mode, assigns the correct internal runtime mutation id, and generates the exact proxy CLI flag. It also normalizes old and new runtime identifiers so experiment history and bookkeeping stay consistent.
