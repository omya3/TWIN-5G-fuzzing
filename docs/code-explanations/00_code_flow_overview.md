# Code Flow Overview


## High-Level Layer Order

```text
nas_catalog.py
    ->
nas_scheduler.py
    ->
nas_domain_explorer.py
    ->
nas_execution_bridge.py
    ->
nas_campaign.py
    ->
cli.py
    ->
sctp_ngap_proxy.c
    ->
result_classifier.py
    ->
history.json / campaign summaries / reports
```

In words:

- `nas_catalog.py` defines what exists
- `nas_scheduler.py` decides what to try next
- `nas_domain_explorer.py` summarizes reachable coverage and frontiers
- `nas_execution_bridge.py` decides how it can run
- `nas_campaign.py` builds real commands and plan files
- `cli.py` orchestrates the end-to-end workflow
- `sctp_ngap_proxy.c` performs the live packet mutation
- `result_classifier.py` reads logs and labels the result
- history and reporting commands persist the observation and refresh summaries

## Current End-to-End CLI Flow

Today the normal demo path is not just "print commands and run them manually."

The most important current CLI flow is:

```text
next-proxy-nas-case
    ->
run-proxy-nas-case
    ->
classify-and-render-proxy-nas-record
or record-proxy-nas-observation
    ->
summarize-nas-campaign
```

In simple words:

- `next-proxy-nas-case` or `plan-proxy-nas-campaign` picks the next runnable experiment
- `run-proxy-nas-case` consumes the saved plan and launches AMF log capture, proxy, gNB, and UE
- the classifier suggests the result class from the collected logs
- the observation is written into `history.json`
- campaign summaries and exported reports reflect the new run

## 1. Catalog Layer

File:

- `src/ngap_nas_fuzz/nas_catalog.py`

Main functions:

- `get_nas_message_profiles()`
- `get_nas_message_profile(message_name)`
- `get_nas_field_definition(message_name, field_name)`
- `get_optional_iei_tag_map(message_name)`

What happens here:

- the framework loads NAS message profiles
- each profile contains mutation families
- each family contains mutation operators

Main outward use:

```text
nas_scheduler.py calls get_nas_message_profiles()
nas_scheduler.py uses message profiles to build candidates
```

## 2. Scheduler Layer

File:

- `src/ngap_nas_fuzz/nas_scheduler.py`

Main functions:

- `list_candidates_for_message(message_name)`
- `_candidate_from_operator(...)`
- `summarize_campaign_history(...)`
- `recommend_next_candidates(...)`

Important call flow:

```text
list_candidates_for_message()
    ->
_candidate_from_operator()
    ->
resolve_operator_execution()   [from nas_execution_bridge.py]
```

What this means:

- scheduler gets mutation definitions from the catalog
- for each operator, it asks the execution bridge whether it is executable
- then it builds `NasMutationCandidate` objects

Ranking flow:

```text
recommend_next_candidates()
    ->
list_candidates_for_message()
    ->
history analysis
    ->
scoring
    ->
NasSchedulerRecommendation list
```

Main outward use:

```text
nas_campaign.py calls recommend_next_candidates()
```

## 3. Execution Bridge Layer

File:

- `src/ngap_nas_fuzz/nas_execution_bridge.py`

Main functions:

- `_matching_bridge(...)`
- `resolve_operator_execution(...)`
- `render_proxy_command_flag(...)`
- `observation_runtime_key(...)`

Important call flow:

```text
resolve_operator_execution()
    ->
_matching_bridge()
```

and for generic nested live mutations:

```text
resolve_operator_execution()
    ->
_live_nested_optional_ie_value()
    ->
resolve_nested_optional_ie_plan()   [from nas_schema.py]
    ->
serialize_mutation_plan_value()     [from nas_schema.py]
```

What this means:

- this layer decides whether an operator is:
  - `proxy`
  - `nested-simulation`
  - `plain-simulation`
  - `planned`
- it also decides:
  - `proxy_mutation`
  - `proxy_value`

Command rendering flow:

```text
render_proxy_command_flag(proxy_mutation, value)
    ->
returns the exact CLI fragment for sctp_ngap_proxy
```

Main outward use:

```text
nas_scheduler.py calls resolve_operator_execution()
nas_campaign.py calls render_proxy_command_flag()
nas_scheduler.py and history logic call observation_runtime_key()
```

## 4. Campaign Planning Layer

File:

- `src/ngap_nas_fuzz/nas_campaign.py`

Main functions:

- `build_proxy_campaign_plan(...)`
- `_proxy_command(...)`
- `_amf_log_command(...)`
- `_gnb_command(...)`
- `_ue_command(...)`
- `render_record_command(...)`
- `append_observation_from_run(...)`

Important call flow:

```text
build_proxy_campaign_plan()
    ->
recommend_next_candidates()         [from nas_scheduler.py]
    ->
render_operator_for_value()         [from nas_execution_bridge.py]
    ->
_proxy_command()
        ->
    render_proxy_command_flag()     [from nas_execution_bridge.py]
    ->
_amf_log_command()
    ->
_gnb_command()
    ->
_ue_command()
```

What this means:

- campaign layer asks scheduler for the best next candidates
- for each one, it builds:
  - run id
  - logs directory
  - proxy command
  - AMF command
  - gNB command
  - UE command

Recording flow:

```text
render_record_command()
    ->
find_run_spec()
    ->
build ready-to-run record command
```

and:

```text
append_observation_from_run()
    ->
find_run_spec()
    ->
NasCampaignObservation
```

Main outward use:

```text
CLI command next-proxy-nas-case calls build_proxy_campaign_plan()
CLI command plan-proxy-nas-campaign writes reusable multi-run plans
CLI command run-proxy-nas-case consumes ProxyCampaignPlan entries and executes them
History recording uses render_record_command(), render_filled_record_command(), or append_observation_from_run()
```

## 5. Live Proxy Runtime Layer

File:

- `proxy/sctp_ngap_proxy.c`

Main functions:

- `parse_args(...)`
- `parse_nested_optional_ie_spec(...)`
- `relay_loop_with_config(...)`
- `forward_one_message(...)`
- `maybe_patch_selected_nas(...)`
- `remove_octet_span(...)`
- `duplicate_octet_span(...)`
- `main(...)`

Important call flow:

```text
main()
    ->
parse_args()
    ->
create_listener()
    ->
accept gNB connection
    ->
connect_to_amf()
    ->
relay_loop_with_config()
        ->
    forward_one_message()
        ->
    maybe_patch_selected_nas()
        ->
    remove_octet_span() / duplicate_octet_span()   [for some mutation modes]
```

What this means:

- the campaign planner produces a proxy CLI command
- the proxy parses that command into `ProxyConfig`
- the relay loop forwards SCTP packets
- `maybe_patch_selected_nas()` searches the raw bytes and mutates the selected target

Main outward use:

```text
nas_campaign.py generates the shell command
that shell command starts sctp_ngap_proxy.c
```

## 6. Result Classification Layer

File:

- `src/ngap_nas_fuzz/result_classifier.py`

Main functions:

- `classify_proxy_nas_result_logs(logs_dir)`
- `classify_proxy_nas_result_texts(...)`
- `_first_attempt_amf_window(...)`
- `_first_attempt_ue_window(...)`
- `_first_attempt_gnb_window(...)`

Important call flow:

```text
classify_proxy_nas_result_logs(logs_dir)
    ->
read proxy.log / amf.log / gnb.log / ue.log
    ->
classify_proxy_nas_result_texts(...)
        ->
    parse_amf_log()                 [from logs.py]
    parse_ueransim_log()            [from logs.py]
        ->
    _first_attempt_amf_window()
    _first_attempt_ue_window()
    _first_attempt_gnb_window()
        ->
    pattern matching
        ->
    ProxyNasResultSuggestion
```

What this means:

- classifier reads the logs from the run
- narrows them to the first attempt window
- searches for known error/success patterns
- returns a structured result suggestion

Main outward use:

```text
CLI classify-proxy-nas-result calls classify_proxy_nas_result_logs()
Campaign history then stores the chosen result class
```

## End-to-End Story

Here is the practical end-to-end story for one live mutation:

```text
1. nas_catalog.py defines the mutation family and operator
2. nas_scheduler.py turns it into a candidate and ranks it
3. nas_execution_bridge.py decides how it can run and which runtime ID it uses
4. nas_campaign.py generates the real commands and log paths
5. sctp_ngap_proxy.c runs, intercepts the packet, mutates it, and forwards it
6. Open5GS / UERANSIM produce logs
7. result_classifier.py reads the logs and suggests the result class
8. the observation is recorded back into history
```

## Summary

```text
Catalog knows
Scheduler chooses
Bridge maps
Campaign plans
Proxy mutates
Classifier labels
```
