# `cli.py`

## Big Picture

What this file does:

> It is the main user-facing entrypoint of the whole framework.

In simple words:

- the catalog defines what mutations exist
- the scheduler ranks what to try next
- the campaign layer builds runnable plans
- the classifier labels results
- `cli.py` connects all of these into real commands you can run

So this file answers questions like:

- How do I inspect the NAS catalog?
- How do I ask for the next runnable live case?
- How do I generate a multi-run plan?
- How do I execute one selected run automatically?
- How do I record the result into history?
- How do I summarize the current campaign state?

This file is basically the **workflow orchestrator**.

## Most Important Idea

`cli.py` does not contain the NAS mutation logic itself.

Instead, it wires together the core layers:

```text
catalog / scheduler / execution bridge / campaign planner / proxy runtime / classifier
```

That is why this file is so useful during the demo:

> it shows how the whole system is used from the command line.

## Important Functions

### 1. `build_parser()`

**What it does**

It defines all supported CLI subcommands.

Important current commands include:

- `show-nas-catalog`
- `show-nas-candidates`
- `show-nas-domains`
- `show-nas-frontiers`
- `summarize-nas-campaign`
- `plan-proxy-nas-campaign`
- `next-proxy-nas-case`
- `run-proxy-nas-case`
- `record-proxy-nas-observation`
- `classify-proxy-nas-result`
- `classify-and-render-proxy-nas-record`

**In simple words**

```text
This function defines the public command-line API of the project.
```

**Why it matters**

If someone asks "how do you actually use the system?", this is the first file to show.

### 2. `cmd_plan_proxy_nas_campaign(args)`

**What it does**

It generates a reusable live-execution plan for one message.

**In simple words**

```text
Take scheduler recommendations and write them into a JSON plan file with runnable commands.
```

**Why it matters**

This is the multi-run planning interface used before a live campaign.

### 3. `cmd_next_proxy_nas_case(args)`

**What it does**

It chooses the best single runnable live case and writes a one-run plan file.

**In simple words**

```text
Give me the next best runnable mutation case for this message.
```

**Why it matters**

This is the cleanest command for a live demo.

### 4. `cmd_run_proxy_nas_case(args)`

This is one of the most important commands in the whole repo.

**What it does**

It loads a saved plan, finds the selected run, launches the required background processes, waits for success or timeout, stops everything cleanly, and then classifies the logs.

**Very important internal flow**

```text
load_campaign_plan()
    ->
find_run_spec()
    ->
spawn AMF log capture
    ->
spawn proxy
    ->
spawn gNB
    ->
spawn UE
    ->
wait for success pattern or timeout
    ->
classify_proxy_nas_result_logs()
    ->
render_filled_record_command()
```

**In simple words**

```text
This is the automated live runner.
It takes a planned mutation case and executes the whole experiment for you.
```

**Why it matters**

This is the main reason the current project is more than a manual proxy script.

### 5. `cmd_record_proxy_nas_observation(args)`

**What it does**

It turns a finished run into a history entry and appends it to `history.json`.

**In simple words**

```text
After the run is done, save the result permanently in campaign history.
```

**Why it matters**

This is what makes the scheduler history-aware in later runs.

### 6. `cmd_summarize_nas_campaign(args)`

**What it does**

It reads campaign history and prints family-level coverage and outcomes.

**In simple words**

```text
Show me what has been explored, what remains, and what kinds of results we observed.
```

**Why it matters**

This command is central to the freeze-state reporting story.

### 7. `cmd_show_nas_domains(args)` and `cmd_show_nas_frontiers(args)`

**What they do**

These newer commands expose domain-level exploration and frontier selection.

**In simple words**

```text
show-nas-domains    -> what mutation domains exist for a message
show-nas-frontiers  -> which unexplored or high-value frontiers remain
```

**Why they matter**

These commands are useful when someone asks how the project reasons about remaining coverage instead of only the next single case.

## Best Demo-Oriented Commands

If you need to explain only the most important current workflow, show these:

1. `next-proxy-nas-case`
2. `run-proxy-nas-case`
3. `record-proxy-nas-observation`
4. `summarize-nas-campaign`

That gives the clean story:

```text
recommend
    ->
execute
    ->
record
    ->
summarize
```

## Conclusion

> `cli.py` is the orchestration layer of the project. It exposes the NAS catalog, campaign planning, automated live execution, classification, history recording, and campaign summarization through one command-line interface. In practice, this is the file that turns the rest of the codebase into a usable fuzzing workflow.
