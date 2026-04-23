# `nas_catalog.py`

## Big Picture

What this file does:

> It stores what NAS messages we know, what fields they contain, and what mutation families/operators are meaningful for them.

So this file does **not** mutate packets itself. Instead, it answers questions like:

- What is a `Registration Request`?
- What fields does it contain?
- What mutations are allowed for those fields?
- Which optional IE tag corresponds to `requested_nssai`?

## The 3 Important Data Structures

### 1. `NasMutationFamily`

**What it means**

This is one mutation category.

```python
NasMutationFamily(
    name="message-type substitution",
    target="5GMM message type octet",
    mutation_operators=("replace 0x41 with 0x5c", "replace 0x41 with 0x56"),
    priority="high",
    rationale="tests whether the AMF safely rejects a wrong first NAS semantic type",
)
```

**In simple words**

```text
Here is one family of fuzzing ideas.
Its name is message-type substitution.
These are the concrete operators inside it.
```

> `NasMutationFamily` is the research-level grouping. It organizes related mutations together.

### 2. `NasFieldDefinition`

**What it means**

This describes one field inside a NAS message.

```python
NasFieldDefinition(
    name="message_type",
    kind="enum",
    mandatory=True,
    baseline_value="0x41",
    location_hint="byte 2 in baseline signature 7e 00 41",
    notes="identifies the message as Registration Request",
)
```

**In simple words**

```text
This field is called message_type.
It is mandatory.
Its normal value is 0x41.
It is located near byte 2 in the baseline packet.
```

> `NasFieldDefinition` is the field-level description. It tells us what the field is, where it usually appears, and how we may mutate it.

### 3. `NasMessageProfile`

**What it means**

This describes one whole NAS message.

```python
NasMessageProfile(
    message_name="Registration Request",
    message_type_code="0x41",
    direction="UE -> AMF",
    procedure_phase="initial registration entry point",
    expected_precondition="first uplink NAS message in normal registration",
    ...
)
```

**In simple words**

```text
This message is Registration Request.
It normally goes from UE to AMF.
It appears in the initial registration phase.
These are its fields.
These are its mutation families.
```

> `NasMessageProfile` is the top-level description for one NAS message type.

## Important Functions

### 4. `get_nas_message_profiles()`

**What it does**

This returns **all NAS message profiles** known to the framework.

**Input**

```python
get_nas_message_profiles()
```

No input arguments.

**Output**

```python
(
    NasMessageProfile(message_name="Registration Request", ...),
    NasMessageProfile(message_name="Identity Response", ...),
    NasMessageProfile(message_name="Authentication Response", ...),
    NasMessageProfile(message_name="Security Mode Complete", ...),
    NasMessageProfile(message_name="PDU Session Establishment Request", ...),
)
```

**In simple words**

```text
Give me the full catalog of NAS messages that this framework currently knows.
```

**Why it matters**

This is the function that the rest of the system uses to load the catalog.

> `get_nas_message_profiles()` is the main entry point of the NAS catalog. It returns all supported NAS message profiles, including Registration Request and the newer message types like Identity Response and Authentication Response.

### 5. `get_nas_message_profile(message_name)`

**What it does**

This returns the profile for one specific NAS message.

**Input**

```python
get_nas_message_profile("Registration Request")
```

**Output**

```python
NasMessageProfile(
    message_name="Registration Request",
    message_type_code="0x41",
    direction="UE -> AMF",
    procedure_phase="initial registration entry point",
    ...
)
```

**In simple words**

```text
Give me only the catalog entry for Registration Request.
```

**Why it matters**

If the scheduler or planner wants to work only on one message, this is the function it uses.

> `get_nas_message_profile()` is used when we want details for one specific NAS message instead of the whole catalog.

### 6. `get_nas_field_definition(message_name, field_name)`

**What it does**

This returns one field definition inside one message.

**Input**

```python
get_nas_field_definition("Registration Request", "requested_nssai")
```

**Output**

```python
NasFieldDefinition(
    name="requested_nssai",
    kind="optional_tlv",
    mandatory=False,
    baseline_value="optional Requested NSSAI IE when present",
    location_hint="later optional TLV region in Registration Request body",
    iei_tag="0x2f",
    ...
)
```

**In simple words**

```text
Inside Registration Request, tell me about the Requested NSSAI field.
```

**Why it matters**

This is useful when the framework wants to know:

- whether the field is optional
- what kind of encoding it has
- where it is located
- what mutations are meaningful

> `get_nas_field_definition()` gives field-level metadata. For example, it can tell us that Requested NSSAI is an optional TLV field with IEI tag `0x2f`.

### 7. `get_optional_iei_tag_map(message_name)`

**What it does**

This creates a mapping from optional IE tag numbers to field names.

**Input**

```python
get_optional_iei_tag_map("Registration Request")
```

**Output**

```python
{
    0x2f: "requested_nssai",
    0x10: "fivegmm_capability",
}
```

In actual Python integer values:

```python
{
    47: "requested_nssai",
    16: "fivegmm_capability",
}
```

**In simple words**

```text
If I see IE tag 0x2f in Registration Request, what field is that?
If I see IE tag 0x10, what field is that?
```

**Why it matters**

This is very important for nested optional IE mutation.

The proxy or locator can see raw bytes like:

```text
0x2f ...
```

and know:

```text
this is Requested NSSAI
```

> `get_optional_iei_tag_map()` helps the system recognize optional IE tags in the raw NAS bytes. For Registration Request, it maps tags like `0x2f` to `requested_nssai` and `0x10` to `fivegmm_capability`.

## One Slightly Deeper Function

> How are mutation families/operators created?

Then explain this one.

### 8. `_family_from_generation_rule(field_def, rule)`

**What it does**

This converts a field rule into a mutation family.

**Input example**

```python
field_def = NasFieldDefinition(
    name="message_type",
    kind="enum",
    baseline_value="0x41",
    ...
)

rule = NasFieldGenerationRule(
    family_name="message-type substitution",
    strategy="enum-substitution",
    candidate_values=("0x5c", "0x56", "0x57", "0x5d", "0x5e", "0x00"),
    ...
)
```

**Output**

```python
NasMutationFamily(
    name="message-type substitution",
    target="5GMM message type octet",
    mutation_operators=(
        "replace 0x41 with 0x5c",
        "replace 0x41 with 0x56",
        "replace 0x41 with 0x57",
        ...
    ),
    priority="high",
    rationale="tests whether the AMF safely rejects a wrong first NAS semantic type",
)
```

**In simple words**

```text
Take one field and one rule, and turn them into actual mutation operators.
```

**Why it matters**

This is part of the move toward schema-driven generalization.

Instead of hardcoding every operator manually, we can generate them from rules.

> `_family_from_generation_rule()` is part of the schema-driven direction. It takes a field definition plus a generation rule and automatically produces a mutation family with concrete operators.

## Conclusion

> `nas_catalog.py` is the knowledge base of the framework. It defines each NAS message as a `NasMessageProfile`, each field inside it as a `NasFieldDefinition`, and each mutation category as a `NasMutationFamily`. The main API is `get_nas_message_profiles()`, which returns the full supported NAS catalog. Then functions like `get_nas_field_definition()` and `get_optional_iei_tag_map()` let the rest of the framework look up field metadata and optional IE tags, which is especially useful for structured mutations such as Requested NSSAI and 5GMM capability.
