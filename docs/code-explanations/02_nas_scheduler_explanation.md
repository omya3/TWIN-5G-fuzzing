# `nas_scheduler.py`

## Big Picture

What this file does:

> It turns the mutation catalog plus history into ranked recommendations.

In simple words:

- `nas_catalog.py` says what mutations exist
- `nas_execution_bridge.py` says how they can run
- `nas_scheduler.py` decides which mutations are most worth trying next

So this file answers questions like:

- What are all candidate mutations for a message?
- Which ones were already tried?
- Which families are saturated?
- Which families showed interesting mixed behavior?
- Which candidate should be suggested next?

This file is basically the **ranking and suggestion engine**.

## Important Data Structures

### 1. `NasMutationCandidate`

**What it means**

This is one possible mutation candidate.

Example idea:

```python
NasMutationCandidate(
    message_name="Registration Request",
    message_type_code="0x41",
    family_name="message-type substitution",
    operator="replace 0x41 with 0x5c",
    priority="high",
    rationale="tests whether the AMF safely rejects a wrong first NAS semantic type",
    executable_now=True,
    live_proxy_capable=True,
    execution_mode="proxy",
    proxy_mutation="message-type",
    proxy_value="0x5c",
)
```

**In simple words**

```text
Here is one possible experiment we could run.
This is the message.
This is the family.
This is the exact operator.
This is whether we can run it now.
```

**Why it matters**

This is the scheduler’s basic unit of work.

### 2. `NasCampaignObservation`

**What it means**

This is one past result from history.

Example:

```python
NasCampaignObservation(
    message_name="Registration Request",
    family_name="message-type substitution",
    operator="replace 0x41 with 0x5c",
    result_class="early-semantic-reject",
    notes="AMF log shows Invalid 5GMM message type [92]",
    proxy_mutation="message-type",
    proxy_value="0x5c",
)
```

**In simple words**

```text
We already ran this mutation before,
and this was the result.
```

**Why it matters**

This is how the scheduler knows what has already been explored.

### 3. `NasSchedulerRecommendation`

**What it means**

This is the final ranked recommendation.

Example:

```python
NasSchedulerRecommendation(
    candidate=NasMutationCandidate(...),
    score=34,
    reasons=[
        "base priority medium",
        "supported by current proxy",
        "untried operator",
        "family previously produced unexpected accept",
    ],
)
```

**In simple words**

```text
This is a candidate mutation,
this is its score,
and these are the reasons why it was ranked here.
```

**Why it matters**

This is what the CLI prints when you run recommendation commands.

### 4. `NasFamilySummary`

**What it means**

This summarizes the history of one mutation family.

Example idea:

```python
NasFamilySummary(
    message_name="Registration Request",
    family_name="mobile-identity value corruption",
    total_known_operators=5,
    executable_known_operators=5,
    tried_operators=5,
    result_counts={"unexpected-accept": 2, "deep-decoder-failure": 1, "early-semantic-reject": 1},
    dominant_result_class="unexpected-accept",
    unique_result_classes=("deep-decoder-failure", "early-semantic-reject", "unexpected-accept"),
    saturation="diverse behavior observed",
)
```

**In simple words**

```text
For this mutation family,
how much did we cover,
what results did we see,
and does this family still look interesting?
```

**Why it matters**

This is what powers campaign summaries and saturation logic.

## Important Functions

### 5. `list_candidates_for_message(message_name)`

**What it does**

It expands one NAS message into all possible mutation candidates.

**Input**

Example:

```python
list_candidates_for_message("Registration Request")
```

**Output**

A list like:

```python
[
    NasMutationCandidate(
        family_name="message-type substitution",
        operator="replace 0x41 with 0x5c",
        ...
    ),
    NasMutationCandidate(
        family_name="security-header mutation",
        operator="set security header 0x00 -> 0x02",
        ...
    ),
    ...
]
```

**In simple words**

```text
For this message, show me every candidate mutation we currently know.
```

**Why it matters**

This is the starting point for scheduling.

### 6. `_candidate_from_operator(...)`

**What it does**

It takes one operator from the catalog and converts it into a full `NasMutationCandidate`.

**Input**

Example idea:

```python
_candidate_from_operator(
    profile=RegistrationRequestProfile,
    family_name="message-type substitution",
    priority="high",
    rationale="...",
    operator="replace 0x41 with 0x5c",
)
```

**Output**

Something like:

```python
NasMutationCandidate(
    message_name="Registration Request",
    family_name="message-type substitution",
    operator="replace 0x41 with 0x5c",
    executable_now=True,
    execution_mode="proxy",
    proxy_mutation="message-type",
    proxy_value="0x5c",
)
```

**In simple words**

```text
Take one catalog operator and turn it into a full candidate with execution info.
```

**Why it matters**

This is where the scheduler uses the execution bridge.

So this function connects:

```text
catalog operator -> executable candidate
```

### 7. `summarize_campaign_history(...)`

This is one of the most important functions.

**What it does**

It summarizes past history family by family.

**Input**

Example:

```python
summarize_campaign_history(
    history=my_history,
    message_name="Registration Request",
)
```

**Output**

A list like:

```python
[
    NasFamilySummary(
        family_name="message-type substitution",
        total_known_operators=6,
        tried_operators=6,
        dominant_result_class="early-semantic-reject",
        saturation="likely saturated (early-semantic-reject)",
        ...
    ),
    NasFamilySummary(
        family_name="mobile-identity value corruption",
        total_known_operators=5,
        tried_operators=5,
        unique_result_classes=("deep-decoder-failure", "early-semantic-reject", "unexpected-accept"),
        saturation="diverse behavior observed",
        ...
    ),
]
```

**In simple words**

```text
Look at the whole history and tell me:
- what we already tested
- what happened
- which families are saturated
- which families still show interesting behavior
```

**Why it matters**

This is what makes the framework history-aware instead of random.

### 8. `_family_saturation_label(...)`

**What it does**

It decides a human-readable saturation status for one family.

**Input**

Example:

```python
_family_saturation_label(
    total_known_operators=6,
    tried_operators=6,
    unique_result_count=1,
    dominant_result_class="early-semantic-reject",
)
```

**Output**

```python
"likely saturated (early-semantic-reject)"
```

Another example:

```python
_family_saturation_label(
    total_known_operators=5,
    tried_operators=5,
    unique_result_count=3,
    dominant_result_class="unexpected-accept",
)
```

**Output**

```python
"fully explored with mixed outcomes"
```

**In simple words**

```text
Based on coverage and results, is this family still worth exploring?
```

**Why it matters**

This directly affects ranking.

### 9. `recommend_next_candidates(...)`

This is the **most important function in the whole file**.

**What it does**

It ranks candidates and returns the best next ones to try.

**Input**

Example:

```python
recommend_next_candidates(
    "Registration Request",
    history=my_history,
    limit=5,
    executable_only=True,
)
```

**Output**

Something like:

```python
[
    NasSchedulerRecommendation(
        candidate=NasMutationCandidate(
            family_name="requested NSSAI corruption",
            operator="invalid length",
            execution_mode="proxy",
            proxy_mutation="nested-registration-request-optional-ie-live",
            proxy_value="field:requested_nssai,action:bad-length,length:0xff",
            ...
        ),
        score=34,
        reasons=[
            "base priority medium",
            "supported by current proxy",
            "untried operator",
            "family already characterized by 6 observed operators",
            "family previously produced unexpected accept",
        ],
    )
]
```

**In simple words**

```text
Take all candidates,
look at history,
score them,
sort them,
and return the best next suggestions.
```

## How Scoring Works

This is the heart of the scheduler.

The function uses:

### A. Base priority

From the catalog:

```python
PRIORITY_WEIGHT = {
    "high": 30,
    "medium": 20,
    "low": 10,
}
```

So:

- high-priority families start higher
- medium start lower
- low start lowest

### B. Executable support

If candidate is executable now:

- score increases
- reason added like:
  - `supported by current proxy`
  - or `supported by current implementation via plain-simulation`

### C. Tried vs untried

If not tried before:

- score gets a bonus
- reason: `untried operator`

If already tried:

- score gets a penalty
- reason: `already tried with result ...`

### D. Family history

The scheduler also checks the whole family:

- how many operators were already explored
- what outcomes were seen
- whether family looks saturated
- whether family showed diverse behavior

Examples:

- repeated `early-semantic-reject` may reduce score
- previous `unexpected-accept` may increase score for fresh operators
- previous `AMF crash` increases interest strongly
- saturated family gets penalized
- diverse family may get bonus for fresh operators

### E. Result-specific weights

There is also a result weight table:

```python
RESULT_WEIGHT = {
    "early-semantic-reject": 0,
    "deep-decoder-failure": 15,
    "timeout-retry": 8,
    "unexpected-accept": 20,
    "amf-crash": 25,
    "proxy-crash": 12,
    "simulation-artifact": 0,
}
```

This means:

- more interesting outcomes get more influence
- `unexpected-accept` and `amf-crash` are treated as especially valuable

## One Concrete Scoring Example

Take this candidate:

```text
Message: Registration Request
Family: requested NSSAI corruption
Operator: invalid length
Execution mode: proxy
```

Assume the history already shows:

- the family priority is `medium`
- this operator is still untried
- the family already has 6 observed operators
- the family previously produced `unexpected-accept`
- the family is live-supported now

Then the score is built step by step like this:

### Step 1: Base priority

```text
medium priority = +20
score = 20
```

### Step 2: Executable now in proxy

```text
supported by current proxy = +8
score = 28
```

### Step 3: Untried operator

```text
untried operator = +10
score = 38
```

### Step 4: Family already characterized

The scheduler applies a characterization penalty when many operators in the same family were already explored.

With 6 observed operators:

```text
penalty = min(16, (6 - 1) * 4) = 16
score = 22
```

### Step 5: Family previously produced unexpected-accept

Because this family already showed an interesting permissive result and this operator is still fresh:

```text
previous unexpected-accept bonus = +12
score = 34
```

### Final score

```text
Final score = 34
```

### Final reasons

```text
- base priority medium
- supported by current proxy
- untried operator
- family already characterized by 6 observed operators
- family previously produced unexpected accept
```

This is exactly the kind of recommendation output you saw in your project.

## Example from the Project

Suppose the scheduler suggests:

```text
Requested NSSAI corruption
operator: invalid length
score: 34
```

That may happen because:

- family priority = medium
- operator is now live-supported
- operator is untried
- family already showed interesting behavior
- family previously produced `unexpected-accept`

So the scheduler thinks:

> this family is already promising, and this fresh operator may reveal even more useful behavior

### 10. `_observation_identity_key(...)` and `_candidate_runtime_key(...)`

You do not need to explain these deeply, but their idea is important.

**What they do**

They create stable keys for comparing:

- candidates
- past observations

**In simple words**

They say:

```text
How do we know whether a candidate is the same as something already tried?
```

**Why it matters**

This prevents the scheduler from being confused by old vs new runtime naming styles.


Imp functions:

1. `NasMutationCandidate`
2. `NasCampaignObservation`
3. `NasSchedulerRecommendation`
4. `list_candidates_for_message(...)`
5. `summarize_campaign_history(...)`
6. `recommend_next_candidates(...)`

Other functions:

7. `_family_saturation_label(...)`
8. `_candidate_from_operator(...)`
9. result weights / priority weights

## Conclusion

> `nas_scheduler.py` is the ranking engine of the framework. It takes all known mutation candidates for a message, combines them with past campaign history, and scores them based on priority, implementation support, whether they were already tried, and what outcomes were previously observed. Then it returns the best next mutations to run. This makes the workflow systematic and history-aware instead of random.
