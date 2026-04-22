from __future__ import annotations

import json
import re
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .nas_execution_bridge import render_operator_for_value, render_proxy_command_flag
from .nas_field_locator import detect_plain_5gmm_message_name
from .models import ProcedureTrace
from .nas_nested_inspector import scan_for_nested_registration_requests
from .nas_schema import (
    build_nested_optional_ie_mutation_plan,
    build_nested_registration_request_selector,
    build_plain_field_mutation_plan,
    build_plain_nas_selector,
    deserialize_mutation_plan_value,
    serialize_mutation_plan_value,
)
from .nas_scheduler import (
    NasCampaignObservation,
    NasSchedulerRecommendation,
    recommend_next_candidates,
)


@dataclass
class ProxyRunSpec:
    run_id: str
    message_name: str
    family_name: str
    operator: str
    rationale: str
    score: int
    result_hint: str
    proxy_mutation: str
    proxy_value: str | None
    logs_dir: str
    proxy_command: str
    amf_log_command: str
    gnb_command: str
    ue_command: str
    recommendation_reasons: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProxyRunSpec":
        return cls(
            run_id=data["run_id"],
            message_name=data["message_name"],
            family_name=data["family_name"],
            operator=data["operator"],
            rationale=data["rationale"],
            score=int(data["score"]),
            result_hint=data["result_hint"],
            proxy_mutation=data["proxy_mutation"],
            proxy_value=data.get("proxy_value"),
            logs_dir=data["logs_dir"],
            proxy_command=data["proxy_command"],
            amf_log_command=data["amf_log_command"],
            gnb_command=data["gnb_command"],
            ue_command=data["ue_command"],
            recommendation_reasons=list(data.get("recommendation_reasons", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProxyCampaignPlan:
    message_name: str
    history_count: int
    runs: list[ProxyRunSpec] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProxyCampaignPlan":
        return cls(
            message_name=data["message_name"],
            history_count=int(data.get("history_count", 0)),
            runs=[ProxyRunSpec.from_dict(item) for item in data.get("runs", [])],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_name": self.message_name,
            "history_count": self.history_count,
            "runs": [run.to_dict() for run in self.runs],
        }


@dataclass
class SimulationRunSpec:
    run_id: str
    message_name: str
    family_name: str
    operator: str
    rationale: str
    score: int
    container_type: str
    field_name: str
    action: str
    mutation_value: str | None
    target_message_index: int
    nested_hit_index: int
    baseline_trace: str
    output_trace: str
    simulate_command: str
    diff_command: str
    recommendation_reasons: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SimulationRunSpec":
        return cls(
            run_id=data["run_id"],
            message_name=data["message_name"],
            family_name=data["family_name"],
            operator=data["operator"],
            rationale=data["rationale"],
            score=int(data["score"]),
            container_type=data.get("container_type", "nested-registration-request"),
            field_name=data["field_name"],
            action=data["action"],
            mutation_value=data.get("mutation_value", data.get("length_value")),
            target_message_index=int(
                data.get("target_message_index", data.get("outer_message_index", 0))
            ),
            nested_hit_index=int(data.get("nested_hit_index", 0)),
            baseline_trace=data["baseline_trace"],
            output_trace=data["output_trace"],
            simulate_command=data["simulate_command"],
            diff_command=data["diff_command"],
            recommendation_reasons=list(data.get("recommendation_reasons", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SimulationCampaignPlan:
    message_name: str
    history_count: int
    baseline_trace: str
    runs: list[SimulationRunSpec] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SimulationCampaignPlan":
        return cls(
            message_name=data["message_name"],
            history_count=int(data.get("history_count", 0)),
            baseline_trace=data["baseline_trace"],
            runs=[SimulationRunSpec.from_dict(item) for item in data.get("runs", [])],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_name": self.message_name,
            "history_count": self.history_count,
            "baseline_trace": self.baseline_trace,
            "runs": [run.to_dict() for run in self.runs],
        }


def _sanitize_fragment(value: str) -> str:
    lowered = value.lower()
    lowered = lowered.replace("->", "-to-")
    lowered = re.sub(r"[^a-z0-9]+", "-", lowered)
    lowered = lowered.strip("-")
    return lowered or "case"


def _campaign_values(raw_value: str | None) -> list[str | None]:
    if raw_value is None:
        return [None]
    if raw_value.startswith("campaign-set:{") and raw_value.endswith("}"):
        inner = raw_value[len("campaign-set:{") : -1]
        return [part.strip() for part in inner.split(",") if part.strip()]
    return [raw_value]


def _decode_nested_simulation_value(raw_value: str | None) -> tuple[str, str | None]:
    plan = deserialize_mutation_plan_value(
        raw_value,
        selector=build_nested_registration_request_selector(),
        default_field_name="simulation-placeholder",
    )
    return (plan.action, plan.value)


def _decode_plain_simulation_value(
    message_name: str,
    raw_value: str | None,
) -> tuple[str, str, str | None]:
    plan = deserialize_mutation_plan_value(
        raw_value,
        selector=build_plain_nas_selector(message_name=message_name),
    )
    return (plan.field_name, plan.action, plan.value)


def _nested_simulation_field_name(candidate: NasSchedulerRecommendation | Any) -> str:
    family_name = candidate.candidate.family_name if hasattr(candidate, "candidate") else candidate.family_name
    if family_name == "requested NSSAI corruption":
        return "requested_nssai"
    if family_name == "5GMM capability corruption":
        return "fivegmm_capability"
    raise ValueError(f"Unsupported nested simulation family '{family_name}'.")


def _find_nested_rr_target(trace: ProcedureTrace, field_name: str) -> tuple[int, int]:
    for message_index, message in enumerate(trace.messages, start=1):
        if message.nas is None:
            continue
        raw_pdu_hex = message.nas.get("raw_pdu_hex")
        if not isinstance(raw_pdu_hex, str) or not raw_pdu_hex:
            continue
        scan = scan_for_nested_registration_requests(raw_pdu_hex)
        for hit_index, hit in enumerate(scan.hits, start=1):
            if field_name in hit.optional_fields_present:
                return (message_index, hit_index)
    raise ValueError(f"No nested Registration Request carrying optional field '{field_name}' was found.")


def _find_plain_nas_target(trace: ProcedureTrace, message_name: str) -> int:
    for message_index, message in enumerate(trace.messages, start=1):
        if message.nas is None:
            continue
        raw_pdu_hex = message.nas.get("raw_pdu_hex")
        if not isinstance(raw_pdu_hex, str) or not raw_pdu_hex:
            continue
        try:
            detected = detect_plain_5gmm_message_name(raw_pdu_hex)
        except ValueError:
            continue
        if detected == message_name:
            return message_index
    raise ValueError(f"No plain NAS message '{message_name}' was found in the baseline trace.")


def _result_hint(proxy_mutation: str) -> str:
    if proxy_mutation == "message-type":
        return "expected early semantic reject"
    if proxy_mutation == "registration-type-and-ngksi":
        return "expected registration-state semantic result"
    if proxy_mutation == "mobile-identity-length":
        return "expected deep decoder failure"
    if proxy_mutation == "mobile-identity-invalid-bcd-tail":
        return "expected mobile identity decode failure"
    if proxy_mutation == "mobile-identity-toggle-type-bits":
        return "expected mobile identity decode failure"
    if proxy_mutation.startswith("nested-"):
        return "expected later nested optional-IE handling result"
    if proxy_mutation == "security-header":
        return "expected security-header handling result"
    return "expected NAS handling result"


def _proxy_command(logs_dir: str, proxy_mutation: str, value: str | None) -> str:
    parts = [
        "cd ~/TWIN/proxy",
        "./sctp_ngap_proxy --preview-bytes 24",
    ]
    parts[-1] += render_proxy_command_flag(proxy_mutation, value)

    parts[-1] += f" 2>&1 | tee {logs_dir}/proxy.log"
    return "\n".join(parts)


def _amf_log_command(logs_dir: str) -> str:
    return (
        "sudo journalctl -u open5gs-amfd -n 0 -f "
        f"| tee {logs_dir}/amf.log"
    )


def _gnb_command(logs_dir: str) -> str:
    return "\n".join(
        [
            "cd ~/UERANSIM/build",
            f"sudo ./nr-gnb -c ../config/twin-gnb-proxy.yaml 2>&1 | tee {logs_dir}/gnb.log",
        ]
    )


def _ue_command(logs_dir: str) -> str:
    return "\n".join(
        [
            "cd ~/UERANSIM/build",
            f"sudo ./nr-ue -c ../config/twin-ue.yaml 2>&1 | tee {logs_dir}/ue.log",
        ]
    )


def build_proxy_campaign_plan(
    message_name: str,
    history: list[NasCampaignObservation] | None = None,
    *,
    limit: int = 6,
    base_log_root: str = "~/twin-traces/nas-campaign",
) -> ProxyCampaignPlan:
    history = history or []
    recommendations = recommend_next_candidates(
        message_name,
        history,
        limit=limit,
        executable_only=True,
    )

    runs: list[ProxyRunSpec] = []
    for rec in recommendations:
        candidate = rec.candidate
        if not candidate.executable_now or candidate.proxy_mutation is None:
            continue

        for value in _campaign_values(candidate.proxy_value):
            value_fragment = _sanitize_fragment(value or candidate.proxy_mutation)
            family_fragment = _sanitize_fragment(candidate.family_name)
            run_id = f"{_sanitize_fragment(candidate.message_name)}-{family_fragment}-{value_fragment}"
            logs_dir = f"{base_log_root}/{run_id}"

            runs.append(
                ProxyRunSpec(
                    run_id=run_id,
                    message_name=candidate.message_name,
                    family_name=candidate.family_name,
                    operator=render_operator_for_value(candidate.operator, candidate.proxy_mutation, value),
                    rationale=candidate.rationale,
                    score=rec.score,
                    result_hint=_result_hint(candidate.proxy_mutation),
                    proxy_mutation=candidate.proxy_mutation,
                    proxy_value=value,
                    logs_dir=logs_dir,
                    proxy_command=_proxy_command(logs_dir, candidate.proxy_mutation, value),
                    amf_log_command=_amf_log_command(logs_dir),
                    gnb_command=_gnb_command(logs_dir),
                    ue_command=_ue_command(logs_dir),
                    recommendation_reasons=list(rec.reasons),
                )
            )

    return ProxyCampaignPlan(
        message_name=message_name,
        history_count=len(history),
        runs=runs,
    )


def build_simulation_campaign_plan(
    message_name: str,
    history: list[NasCampaignObservation] | None = None,
    *,
    baseline_trace: str,
    limit: int = 6,
    base_output_root: str = "~/twin-traces/nas-campaign",
) -> SimulationCampaignPlan:
    history = history or []
    baseline_path = Path(baseline_trace).expanduser()
    trace = ProcedureTrace.from_dict(json.loads(baseline_path.read_text()))
    recommendations = recommend_next_candidates(
        message_name,
        history,
        limit=max(limit * 20, 100),
        executable_only=False,
    )

    runs: list[SimulationRunSpec] = []
    for rec in recommendations:
        candidate = rec.candidate
        if candidate.proxy_mutation is None:
            continue
        if not candidate.executable_now:
            continue

        family_fragment = _sanitize_fragment(candidate.family_name)
        operator_fragment = _sanitize_fragment(candidate.operator)
        run_id = f"{_sanitize_fragment(candidate.message_name)}-{family_fragment}-{operator_fragment}"
        output_trace = f"{base_output_root}/{run_id}.json"

        if candidate.execution_mode == "nested-simulation":
            field_name = _nested_simulation_field_name(rec)
            try:
                target_message_index, nested_hit_index = _find_nested_rr_target(trace, field_name)
                action, mutation_value = _decode_nested_simulation_value(candidate.proxy_value)
            except ValueError:
                continue

            simulate_parts = [
                "python3 -m src.ngap_nas_fuzz.cli simulate-nested-registration-request-optional-ie-mutation",
                f"  --input {baseline_trace}",
                f"  --output {output_trace}",
                f"  --index {target_message_index}",
                f"  --hit {nested_hit_index}",
                f"  --field {field_name}",
                f"  --action {action}",
            ]
            if mutation_value is not None:
                simulate_parts.append(f"  --length-value {mutation_value}")
            container_type = "nested-registration-request"
        elif candidate.execution_mode == "plain-simulation":
            try:
                target_message_index = _find_plain_nas_target(trace, candidate.message_name)
                field_name, action, mutation_value = _decode_plain_simulation_value(
                    candidate.message_name,
                    candidate.proxy_value,
                )
            except ValueError:
                continue
            nested_hit_index = 0
            simulate_parts = [
                "python3 -m src.ngap_nas_fuzz.cli simulate-plain-nas-field-mutation",
                f"  --input {baseline_trace}",
                f"  --output {output_trace}",
                f"  --index {target_message_index}",
                f"  --message-name {shlex.quote(candidate.message_name)}",
                f"  --field {field_name}",
                f"  --action {action}",
            ]
            if mutation_value is not None:
                simulate_parts.append(f"  --value {mutation_value}")
            container_type = "plain-nas-message"
        else:
            continue

        simulate_command = " \\\n".join(simulate_parts)
        diff_command = "\n".join(
            [
                "python3 -m src.ngap_nas_fuzz.cli diff-traces \\",
                f"  --base {baseline_trace} \\",
                f"  --mutated {output_trace}",
            ]
        )

        runs.append(
            SimulationRunSpec(
                run_id=run_id,
                message_name=candidate.message_name,
                family_name=candidate.family_name,
                operator=candidate.operator,
                rationale=candidate.rationale,
                score=rec.score,
                container_type=container_type,
                field_name=field_name,
                action=action,
                mutation_value=mutation_value,
                target_message_index=target_message_index,
                nested_hit_index=nested_hit_index,
                baseline_trace=baseline_trace,
                output_trace=output_trace,
                simulate_command=simulate_command,
                diff_command=diff_command,
                recommendation_reasons=list(rec.reasons),
            )
        )
        if len(runs) >= limit:
            break

    return SimulationCampaignPlan(
        message_name=message_name,
        history_count=len(history),
        baseline_trace=baseline_trace,
        runs=runs,
    )


def save_campaign_plan(path: Path, plan: ProxyCampaignPlan) -> None:
    path.write_text(json.dumps(plan.to_dict(), indent=2) + "\n")


def load_campaign_plan(path: Path) -> ProxyCampaignPlan:
    return ProxyCampaignPlan.from_dict(json.loads(path.read_text()))


def save_simulation_campaign_plan(path: Path, plan: SimulationCampaignPlan) -> None:
    path.write_text(json.dumps(plan.to_dict(), indent=2) + "\n")


def load_simulation_campaign_plan(path: Path) -> SimulationCampaignPlan:
    return SimulationCampaignPlan.from_dict(json.loads(path.read_text()))


def append_observation_from_run(
    plan: ProxyCampaignPlan,
    run_id: str,
    result_class: str,
    notes: str = "",
) -> NasCampaignObservation:
    matching = [run for run in plan.runs if run.run_id == run_id]
    if not matching:
        raise ValueError(f"Run id '{run_id}' is not present in the campaign plan.")
    run = matching[0]
    return NasCampaignObservation(
        message_name=run.message_name,
        family_name=run.family_name,
        operator=run.operator,
        result_class=result_class,
        notes=notes,
        proxy_mutation=run.proxy_mutation,
        proxy_value=run.proxy_value,
    )


def build_observation(
    *,
    message_name: str,
    family_name: str,
    operator: str,
    result_class: str,
    notes: str = "",
    proxy_mutation: str | None = None,
    proxy_value: str | None = None,
) -> NasCampaignObservation:
    return NasCampaignObservation(
        message_name=message_name,
        family_name=family_name,
        operator=operator,
        result_class=result_class,
        notes=notes,
        proxy_mutation=proxy_mutation,
        proxy_value=proxy_value,
    )


def append_observation_from_simulation_run(
    plan: SimulationCampaignPlan,
    run_id: str,
    result_class: str,
    notes: str = "",
) -> NasCampaignObservation:
    matching = [run for run in plan.runs if run.run_id == run_id]
    if not matching:
        raise ValueError(f"Run id '{run_id}' is not present in the simulation campaign plan.")
    run = matching[0]

    if run.container_type == "nested-registration-request":
        proxy_mutation = "nested-registration-request-optional-ie"
        proxy_value = serialize_mutation_plan_value(
            build_nested_optional_ie_mutation_plan(
                field_name=run.field_name,
                action=run.action,
                value=run.mutation_value,
            ),
            include_field=False,
        )
    elif run.container_type == "plain-nas-message":
        proxy_mutation = "plain-nas-field-simulation"
        proxy_value = serialize_mutation_plan_value(
            build_plain_field_mutation_plan(
                message_name=run.message_name,
                field_name=run.field_name,
                action=run.action,
                value=run.mutation_value,
            ),
            include_field=True,
        )
    else:
        raise ValueError(
            f"Unsupported simulation container type '{run.container_type}' in campaign plan."
        )

    return NasCampaignObservation(
        message_name=run.message_name,
        family_name=run.family_name,
        operator=run.operator,
        result_class=result_class,
        notes=notes,
        proxy_mutation=proxy_mutation,
        proxy_value=proxy_value,
    )


def find_run_spec(plan: ProxyCampaignPlan, run_id: str) -> ProxyRunSpec:
    matching = [run for run in plan.runs if run.run_id == run_id]
    if not matching:
        raise ValueError(f"Run id '{run_id}' is not present in the campaign plan.")
    return matching[0]


def render_tmux_launcher_script(
    plan: ProxyCampaignPlan,
    run_id: str,
    *,
    session_name: str | None = None,
) -> str:
    run = find_run_spec(plan, run_id)
    session = session_name or f"nas-{run.run_id}"[:60]

    script = f"""#!/usr/bin/env bash
set -euo pipefail

SESSION_NAME="{session}"
RUN_ID="{run.run_id}"
LOGS_DIR="{run.logs_dir}"

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required for this launcher." >&2
  exit 1
fi

mkdir -p "{run.logs_dir}"

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "tmux session $SESSION_NAME already exists. Attach with: tmux attach -t $SESSION_NAME"
  exit 1
fi

tmux new-session -d -s "$SESSION_NAME" -n campaign
tmux split-window -h -t "$SESSION_NAME":0
tmux split-window -v -t "$SESSION_NAME":0.0
tmux split-window -v -t "$SESSION_NAME":0.1
tmux select-layout -t "$SESSION_NAME":0 tiled

tmux send-keys -t "$SESSION_NAME":0.0 'echo "[proxy] $RUN_ID"; {run.proxy_command}' C-m
tmux send-keys -t "$SESSION_NAME":0.1 'echo "[amf] $RUN_ID"; {run.amf_log_command}' C-m
tmux send-keys -t "$SESSION_NAME":0.2 'echo "[gnb] $RUN_ID"; {run.gnb_command.replace(chr(10), "; ")}' C-m
tmux send-keys -t "$SESSION_NAME":0.3 'echo "[ue] $RUN_ID"; {run.ue_command.replace(chr(10), "; ")}' C-m

echo "Launched tmux session: $SESSION_NAME"
echo "Attach with: tmux attach -t $SESSION_NAME"
echo
echo "When the run is finished, capture logs with:"
echo "  sed -n '1,160p' {run.logs_dir}/proxy.log"
echo "  sed -n '1,120p' {run.logs_dir}/amf.log"
echo "  sed -n '1,120p' {run.logs_dir}/gnb.log"
echo "  sed -n '1,120p' {run.logs_dir}/ue.log"
"""
    return script


def render_record_command(
    plan: ProxyCampaignPlan,
    run_id: str,
    *,
    plan_path: str,
    history_path: str,
) -> str:
    run = find_run_spec(plan, run_id)
    return "\n".join(
        [
            "python3 -m src.ngap_nas_fuzz.cli record-proxy-nas-observation \\",
            f"  --plan {plan_path} \\",
            f"  --run-id {run.run_id} \\",
            "  --result-class <result-class> \\",
            f"  --history {history_path} \\",
            f"  --message-name {shlex.quote(run.message_name)} \\",
            f"  --family-name {shlex.quote(run.family_name)} \\",
            f"  --operator {shlex.quote(run.operator)} \\",
            f"  --proxy-mutation {shlex.quote(run.proxy_mutation)} \\",
            *(
                [f"  --proxy-value {shlex.quote(run.proxy_value)} \\"]
                if run.proxy_value is not None
                else []
            ),
            '  --notes "<replace with key AMF line>"',
        ]
    )


def render_filled_record_command(
    plan: ProxyCampaignPlan,
    run_id: str,
    *,
    result_class: str,
    notes: str,
    plan_path: str,
    history_path: str,
) -> str:
    run = find_run_spec(plan, run_id)
    return "\n".join(
        [
            "python3 -m src.ngap_nas_fuzz.cli record-proxy-nas-observation \\",
            f"  --plan {shlex.quote(plan_path)} \\",
            f"  --run-id {shlex.quote(run.run_id)} \\",
            f"  --result-class {shlex.quote(result_class)} \\",
            f"  --history {shlex.quote(history_path)} \\",
            f"  --message-name {shlex.quote(run.message_name)} \\",
            f"  --family-name {shlex.quote(run.family_name)} \\",
            f"  --operator {shlex.quote(run.operator)} \\",
            f"  --proxy-mutation {shlex.quote(run.proxy_mutation)} \\",
            *(
                [f"  --proxy-value {shlex.quote(run.proxy_value)} \\"]
                if run.proxy_value is not None
                else []
            ),
            f"  --notes {shlex.quote(notes)}",
        ]
    )
