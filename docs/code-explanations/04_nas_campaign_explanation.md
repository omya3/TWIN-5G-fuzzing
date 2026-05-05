# `nas_campaign.py`

## Big Picture

What this file does:

> It converts a recommended mutation into a runnable experiment plan and helps turn finished runs back into history entries.

In simple words:

- `nas_catalog.py` says what mutations exist
- `nas_execution_bridge.py` says how they can run
- `nas_campaign.py` builds the actual experiment plan

So this file answers questions like:

- What exact run should we do next?
- What log directory should we create?
- What proxy / AMF / gNB / UE commands should be run?
- How do we save/load a campaign plan?
- How do we record the result back into history?
- How does the automated runner consume a saved plan?

This file is basically the **experiment planner, plan serializer, and recorder helper**.

## Most Important Data Structures

### 1. `ProxyRunSpec`

**What it means**

This describes **one live run**.

Example idea:

```python
ProxyRunSpec(
    run_id="registration-request-message-type-substitution-0x5c",
    message_name="Registration Request",
    family_name="message-type substitution",
    operator="replace 0x41 with 0x5c",
    rationale="tests whether the AMF safely rejects a wrong first NAS semantic type",
    score=42,
    result_hint="expected early semantic reject",
    proxy_mutation="message-type",
    proxy_value="0x5c",
    logs_dir="~/twin-traces/nas-campaign/registration-request-message-type-substitution-0x5c",
    proxy_command="...",
    amf_log_command="...",
    gnb_command="...",
    ue_command="...",
)
```

**In simple words**

```text
Here is one real experiment run.
This is the mutation.
These are the commands.
These are the logs.
This is the expected type of result.
```

**Why it matters**

This is the main object for live campaign runs.

### 2. `ProxyCampaignPlan`

**What it means**

This is a collection of live runs for one message.

Example idea:

```python
ProxyCampaignPlan(
    message_name="Registration Request",
    history_count=42,
    runs=[ProxyRunSpec(...), ProxyRunSpec(...)]
)
```

**In simple words**

```text
This is the full live experiment plan for one message.
It may contain one or more recommended runs.
```

**Why it matters**

This is what gets saved to JSON when you generate a plan.

### 3. `SimulationRunSpec` and `SimulationCampaignPlan`

**What they mean**

These are the same idea, but for simulation-based runs instead of live proxy runs.

**In simple words**

```text
Here is one simulated mutation run,
or here is the full simulation plan.
```

**Why they matter**

Useful for nested/protected NAS cases or future plain-NAS simulation work.

For your demo, you do not need to explain these deeply unless asked.

## Important Functions

### 4. `build_proxy_campaign_plan(...)`

This is the **most important function in the file**.

**What it does**

It takes a message name and history, asks the scheduler for recommendations, and converts them into actual runnable live experiment commands.

**Input**

Example:

```python
build_proxy_campaign_plan(
    "Registration Request",
    history=my_history,
    limit=2,
    base_log_root="~/twin-traces/nas-campaign",
)
```

**Output**

Something like:

```python
ProxyCampaignPlan(
    message_name="Registration Request",
    history_count=42,
    runs=[
        ProxyRunSpec(
            run_id="registration-request-message-type-substitution-0x5c",
            operator="replace 0x41 with 0x5c",
            proxy_mutation="message-type",
            proxy_value="0x5c",
            logs_dir="~/twin-traces/nas-campaign/registration-request-message-type-substitution-0x5c",
            proxy_command="cd ~/TWIN/proxy\n./sctp_ngap_proxy --preview-bytes 24 --mutate-initial-nas-msgtype 0x5c ...",
            amf_log_command="sudo journalctl -u open5gs-amfd -n 0 -f | tee ...",
            gnb_command="cd ~/UERANSIM/build\nsudo ./nr-gnb ...",
            ue_command="cd ~/UERANSIM/build\nsudo ./nr-ue ...",
        )
    ]
)
```

**In simple words**

```text
Take the best next mutation ideas,
and convert them into a real run plan with actual commands.
```

**Why it matters**

This is the main experiment-planning function.

**Important update about the current workflow**

The output of `build_proxy_campaign_plan(...)` is no longer used only for manual terminal-by-terminal execution.

Today the generated `ProxyCampaignPlan` is consumed in two common ways:

1. manual execution using the printed proxy / AMF / gNB / UE commands
2. automated execution through `cli.py` via `run-proxy-nas-case`

So the plan file is now the shared handoff point between:

```text
recommendation
    ->
saved run spec
    ->
manual or automated execution
```

**Very important internal flow**

Inside this function:

1. it calls `recommend_next_candidates(...)`
2. takes each recommendation
3. creates a `run_id`
4. creates a `logs_dir`
5. generates:
   - proxy command
   - AMF log command
   - gNB command
   - UE command
6. stores all this in `ProxyRunSpec`

So this is the step where:

```text
recommendation -> runnable experiment
```

### 5. `_proxy_command(logs_dir, proxy_mutation, value)`

**What it does**

It builds the actual proxy shell command.

**Input**

Example:

```python
_proxy_command(
    "~/twin-traces/nas-campaign/demo1",
    "message-type",
    "0x5c",
)
```

**Output**

Something like:

```python
cd ~/TWIN/proxy
./sctp_ngap_proxy --preview-bytes 24 --mutate-initial-nas-msgtype 0x5c 2>&1 | tee ~/twin-traces/nas-campaign/demo1/proxy.log
```

**In simple words**

```text
Give me the exact shell command to start the proxy for this mutation.
```

**Why it matters**

This is where `nas_campaign.py` uses `render_proxy_command_flag(...)` from the execution bridge.

So this function is where the planner turns runtime mutation info into a real proxy command.

### 6. `_amf_log_command(logs_dir)`

**What it does**

It creates the AMF log capture command.

**Input**

Example:

```python
_amf_log_command("~/twin-traces/nas-campaign/demo1")
```

**Output**

```python
sudo journalctl -u open5gs-amfd -n 0 -f | tee ~/twin-traces/nas-campaign/demo1/amf.log
```

**In simple words**

```text
Give me the exact shell command to capture AMF logs for this run.
```

**Why it matters**

AMF evidence is central to classification.

### 7. `_gnb_command(logs_dir)` and `_ue_command(logs_dir)`

**What they do**

They create the gNB and UE run commands.

**Input**

Example:

```python
_gnb_command("~/twin-traces/nas-campaign/demo1")
_ue_command("~/twin-traces/nas-campaign/demo1")
```

**Output**

Example:

```python
cd ~/UERANSIM/build
sudo ./nr-gnb -c ../config/twin-gnb-proxy.yaml 2>&1 | tee ~/.../gnb.log
```

and

```python
cd ~/UERANSIM/build
sudo ./nr-ue -c ../config/twin-ue.yaml 2>&1 | tee ~/.../ue.log
```

**In simple words**

They say:

```text
Give me the exact commands to start gNB and UE and save their logs.
```

**Why they matter**

Together with AMF and proxy commands, these complete the live run setup.

### 8. `_result_hint(proxy_mutation)`

**What it does**

It gives a human-readable expectation about the kind of result we may see.

**Input**

Example:

```python
_result_hint("message-type")
```

**Output**

```python
"expected early semantic reject"
```

Another example:

```python
_result_hint("mobile-identity-length")
```

**Output**

```python
"expected deep decoder failure"
```

**In simple words**

```text
Based on the mutation type, what kind of result do we roughly expect?
```

**Why it matters**

Useful in the printed plan and in your demo output.

### 9. `save_campaign_plan(path, plan)` and `load_campaign_plan(path)`

**What they do**

They save/load the live plan as JSON.

**Input**

Example:

```python
save_campaign_plan(Path("next-plan.json"), my_plan)
```

**Output**

No return value, but it writes JSON to disk.

Example load:

```python
plan = load_campaign_plan(Path("next-plan.json"))
```

**Output**

```python
ProxyCampaignPlan(...)
```

**In simple words**

```text
Store the experiment plan on disk,
or load it back later.
```

**Why they matter**

This is why CLI commands like `next-proxy-nas-case` can write a reusable plan file.

### 10. `find_run_spec(plan, run_id)`

**What it does**

It looks inside a campaign plan and returns one specific run.

**Input**

Example:

```python
find_run_spec(plan, "registration-request-message-type-substitution-0x5c")
```

**Output**

```python
ProxyRunSpec(...)
```

**In simple words**

```text
Inside this campaign plan, find the exact run with this ID.
```

**Why it matters**

Other functions use this when they need one specific run.

This is also the lookup step used before automated execution. The CLI runner loads the saved plan, finds the selected `run_id`, and then launches the matching experiment.

### 11. `render_record_command(...)`

This is very important for bookkeeping.

**What it does**

It creates the command that can be run to record the result after the experiment finishes.

**Input**

Example:

```python
render_record_command(
    plan,
    "registration-request-message-type-substitution-0x5c",
    plan_path="/home/omkar/twin-traces/nas-campaign/next-plan.json",
    history_path="/home/omkar/twin-traces/nas-campaign/history.json",
)
```

**Output**

Something like:

```bash
python3 -m src.ngap_nas_fuzz.cli record-proxy-nas-observation \
  --plan /home/omkar/twin-traces/nas-campaign/next-plan.json \
  --run-id registration-request-message-type-substitution-0x5c \
  --result-class <result-class> \
  --history /home/omkar/twin-traces/nas-campaign/history.json \
  --message-name 'Registration Request' \
  --family-name 'message-type substitution' \
  --operator 'replace 0x41 with 0x5c' \
  --proxy-mutation message-type \
  --proxy-value 0x5c \
  --notes "<replace with key AMF line>"
```

**In simple words**

```text
After finishing the run, here is the exact command to record the result in history.
```

**Why it matters**

This is the part that fixed the bookkeeping problem you asked about before.

Because the command includes:

- message name
- family name
- operator
- proxy mutation
- proxy value

the result can still be recorded correctly even if the plan file changes later.

### 12. `render_filled_record_command(...)`

**What it does**

This is like `render_record_command(...)`, but with the result and notes already filled in.

**Input**

Example:

```python
render_filled_record_command(
    plan,
    "registration-request-message-type-substitution-0x5c",
    result_class="early-semantic-reject",
    notes="AMF log shows Invalid 5GMM message type [92]",
    plan_path="...",
    history_path="...",
)
```

**Output**

A complete ready-to-run record command.

**In simple words**

```text
Give me the final complete command to record this run result immediately.
```

**Why it matters**

Very useful in automation and report generation.

In the current repo, `run-proxy-nas-case` prints this kind of filled record command automatically after log classification.

### 13. `append_observation_from_run(...)`

**What it does**

It turns a finished run into a `NasCampaignObservation`.

**Input**

Example:

```python
append_observation_from_run(
    plan,
    "registration-request-message-type-substitution-0x5c",
    "early-semantic-reject",
    "AMF log shows Invalid 5GMM message type [92]",
)
```

**Output**

Something like:

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
Take the finished experiment result
and turn it into one history entry.
```

**Why it matters**

This connects the campaign plan to the scheduler history.

### 14. How `nas_campaign.py` fits into the automated runner

This file does not directly start processes itself. That part lives in `cli.py`.

But the current automated runner depends on this file heavily:

```text
cmd_run_proxy_nas_case()   [from cli.py]
    ->
load_campaign_plan()       [from nas_campaign.py]
    ->
find_run_spec()            [from nas_campaign.py]
    ->
use ProxyRunSpec fields:
    - proxy_command
    - amf_log_command
    - gnb_command
    - ue_command
```

So even though `cli.py` performs the orchestration, `nas_campaign.py` is still the file that defines what one runnable experiment actually is.


Imp functions:

1. `ProxyRunSpec`
2. `ProxyCampaignPlan`
3. `build_proxy_campaign_plan(...)`
4. `_proxy_command(...)`
5. `_amf_log_command(...)`
6. `_gnb_command(...)`
7. `_ue_command(...)`
8. `render_record_command(...)`
9. `render_filled_record_command(...)`

Other functions:

10. `_result_hint(...)`
11. `append_observation_from_run(...)`
12. `save_campaign_plan(...)` / `load_campaign_plan(...)`
13. `find_run_spec(...)`

## Conclusion

> `nas_campaign.py` is the experiment-planning layer of the framework. It takes scheduler recommendations and turns them into runnable live experiments with a run ID, log directory, proxy command, AMF log command, gNB command, and UE command. It also serializes those runs into reusable JSON plans and generates the bookkeeping helpers needed to write completed runs back into history. In short, this file converts mutation recommendations into executable campaign artifacts that can be run manually or through the automated CLI workflow.
