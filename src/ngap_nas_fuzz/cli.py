from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path
from typing import Any

from .extractors import augment_trace_with_tshark_json, extract_trace_from_tshark_text
from .nas_field_locator import (
    detect_plain_5gmm_message_name,
    inspect_nas_message_fields,
    inspect_registration_request_fields,
    locate_registration_request_optional_ie,
)
from .nas_nested_inspector import (
    preview_nested_registration_request_mutation,
    scan_for_nested_registration_requests,
)
from .logs import summarize_amf_log, summarize_ueransim_log
from .models import ProcedureTrace
from .nas_catalog import get_nas_message_profiles
from .nas_campaign import (
    ProxyCampaignPlan,
    SimulationCampaignPlan,
    append_observation_from_run,
    append_observation_from_simulation_run,
    build_observation,
    build_proxy_campaign_plan,
    build_simulation_campaign_plan,
    load_campaign_plan,
    load_simulation_campaign_plan,
    render_filled_record_command,
    render_record_command,
    render_tmux_launcher_script,
    save_campaign_plan,
    save_simulation_campaign_plan,
)
from .nas_scheduler import (
    ALL_RESULT_CLASSES,
    NasCampaignObservation,
    NasSchedulerError,
    list_all_candidates,
    list_candidates_for_message,
    recommend_next_candidates,
    summarize_campaign_history,
)
from .mutators import (
    MutationError,
    drop_message,
    duplicate_message,
    nas_message_type,
    nas_security_header,
    patch_plain_nas_message_type,
    reorder_messages,
    set_ngap_field,
    slice_trace,
    stale_id,
    toggle_optional_ie,
)
from .proxy_policy import (
    InitialNasMutationSpec,
    ProxyMutationError,
    apply_initial_registration_mutation,
    apply_registration_request_optional_ie_mutation,
)
from .proxy_runtime import ProxyExecutionConfig, simulate_initial_nas_proxy
from .proxy_runtime import simulate_nested_registration_request_optional_ie_mutation
from .result_classifier import classify_proxy_nas_result_logs


def load_trace(path: Path) -> ProcedureTrace:
    return ProcedureTrace.from_dict(json.loads(path.read_text()))


def save_trace(path: Path, trace: ProcedureTrace) -> None:
    path.write_text(json.dumps(trace.to_dict(), indent=2) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Structured NGAP/NAS mutation prototype")
    subparsers = parser.add_subparsers(dest="command", required=True)

    show = subparsers.add_parser("show", help="Print a compact summary of a trace")
    show.add_argument("--input", required=True, type=Path)

    show_nas_catalog = subparsers.add_parser(
        "show-nas-catalog",
        help="Print the current NAS message/state mutation catalog",
    )

    show_nas_candidates = subparsers.add_parser(
        "show-nas-candidates",
        help="List concrete NAS mutation candidates for one message or for the whole catalog",
    )
    show_nas_candidates.add_argument("--message", help="Message name, for example 'Registration Request'")
    show_nas_candidates.add_argument(
        "--executable-only",
        action="store_true",
        help="Show only candidates that are executable in the current implementation",
    )

    summarize_nas_campaign = subparsers.add_parser(
        "summarize-nas-campaign",
        help="Summarize NAS campaign history by message and mutation family",
    )
    summarize_nas_campaign.add_argument(
        "--history",
        required=True,
        type=Path,
        help="JSON history file containing prior campaign observations",
    )
    summarize_nas_campaign.add_argument(
        "--message",
        help="Optional message name, for example 'Registration Request'",
    )

    export_nas_campaign_report = subparsers.add_parser(
        "export-nas-campaign-report",
        help="Write a paper-friendly Markdown report for one NAS campaign message",
    )
    export_nas_campaign_report.add_argument(
        "--history",
        required=True,
        type=Path,
        help="JSON history file containing prior campaign observations",
    )
    export_nas_campaign_report.add_argument(
        "--message",
        required=True,
        help="Message name, for example 'Registration Request'",
    )
    export_nas_campaign_report.add_argument("--output", required=True, type=Path)

    inspect_registration_fields = subparsers.add_parser(
        "inspect-initial-registration-fields",
        help="Inspect the first plain Registration Request raw NAS PDU and report modeled field presence/offsets",
    )
    inspect_registration_fields.add_argument("--input", required=True, type=Path)
    inspect_registration_fields.add_argument(
        "--index",
        type=int,
        help="Optional 1-based message index to inspect directly instead of auto-finding the first Registration Request",
    )

    inspect_nas_fields = subparsers.add_parser(
        "inspect-nas-fields",
        help="Inspect a plain NAS message raw PDU and report located fields using the generic locator API",
    )
    inspect_nas_fields.add_argument("--input", required=True, type=Path)
    inspect_nas_fields.add_argument(
        "--index",
        type=int,
        required=True,
        help="1-based message index to inspect",
    )
    inspect_nas_fields.add_argument(
        "--message",
        help="Optional NAS message name override, for example 'Identity Response'",
    )

    inspect_optional_ie = subparsers.add_parser(
        "inspect-registration-request-optional-ie",
        help="Locate one optional IE in the first plain Registration Request using schema-defined IEI metadata",
    )
    inspect_optional_ie.add_argument("--input", required=True, type=Path)
    inspect_optional_ie.add_argument(
        "--field",
        required=True,
        choices=["requested_nssai", "fivegmm_capability"],
        help="Optional field name to look for in the trailing TLV region",
    )
    inspect_optional_ie.add_argument(
        "--index",
        type=int,
        help="Optional 1-based message index to inspect directly instead of auto-finding the first Registration Request",
    )

    scan_nested_rr = subparsers.add_parser(
        "scan-nested-registration-requests",
        help="Scan NAS raw PDUs in a trace for nested plain Registration Request payloads inside protected messages",
    )
    scan_nested_rr.add_argument("--input", required=True, type=Path)
    scan_nested_rr.add_argument(
        "--index",
        type=int,
        help="Optional 1-based message index to inspect only one NAS-bearing message",
    )

    preview_nested_rr_optional_ie = subparsers.add_parser(
        "preview-nested-registration-request-optional-ie-mutation",
        help="Preview an optional-IE mutation against a nested Registration Request inside a protected NAS payload",
    )
    preview_nested_rr_optional_ie.add_argument("--input", required=True, type=Path)
    preview_nested_rr_optional_ie.add_argument(
        "--index",
        type=int,
        required=True,
        help="1-based outer message index that carries the nested Registration Request",
    )
    preview_nested_rr_optional_ie.add_argument(
        "--hit",
        type=int,
        default=1,
        help="1-based nested Registration Request hit index within the selected message",
    )
    preview_nested_rr_optional_ie.add_argument(
        "--field",
        required=True,
        choices=["requested_nssai", "fivegmm_capability"],
    )
    preview_nested_rr_optional_ie.add_argument(
        "--action",
        required=True,
        choices=[
            "omit",
            "duplicate",
            "bad-length",
            "unsupported-sst-sd",
            "duplicate-payload-entries",
            "set-reserved-bits",
            "truncate-payload",
        ],
    )
    preview_nested_rr_optional_ie.add_argument(
        "--length-value",
        help="Required only for bad-length, for example 0xff",
    )

    simulate_nested_rr_optional_ie = subparsers.add_parser(
        "simulate-nested-registration-request-optional-ie-mutation",
        help="Apply a nested Registration Request optional-IE mutation to a trace and write the mutated trace",
    )
    simulate_nested_rr_optional_ie.add_argument("--input", required=True, type=Path)
    simulate_nested_rr_optional_ie.add_argument("--output", required=True, type=Path)
    simulate_nested_rr_optional_ie.add_argument(
        "--index",
        type=int,
        required=True,
        help="1-based outer message index that carries the nested Registration Request",
    )
    simulate_nested_rr_optional_ie.add_argument(
        "--hit",
        type=int,
        default=1,
        help="1-based nested Registration Request hit index within the selected message",
    )
    simulate_nested_rr_optional_ie.add_argument(
        "--field",
        required=True,
        choices=["requested_nssai", "fivegmm_capability"],
    )
    simulate_nested_rr_optional_ie.add_argument(
        "--action",
        required=True,
        choices=[
            "omit",
            "duplicate",
            "bad-length",
            "unsupported-sst-sd",
            "duplicate-payload-entries",
            "set-reserved-bits",
            "truncate-payload",
        ],
    )
    simulate_nested_rr_optional_ie.add_argument(
        "--length-value",
        help="Required only for bad-length, for example 0xff",
    )

    recommend_nas = subparsers.add_parser(
        "recommend-nas-next",
        help="Recommend the next NAS mutations based on message name and optional result history",
    )
    recommend_nas.add_argument("--message", required=True, help="Message name, for example 'Registration Request'")
    recommend_nas.add_argument(
        "--history",
        type=Path,
        help="Optional JSON file containing a list of prior campaign observations",
    )
    recommend_nas.add_argument("--limit", type=int, default=5)
    recommend_nas.add_argument(
        "--executable-only",
        action="store_true",
        help="Restrict recommendations to mutations supported by the current proxy implementation",
    )

    plan_proxy_campaign = subparsers.add_parser(
        "plan-proxy-nas-campaign",
        help="Expand scheduler recommendations into concrete proxy run specs and commands",
    )
    plan_proxy_campaign.add_argument(
        "--message",
        required=True,
        help="Message name, for example 'Registration Request'",
    )
    plan_proxy_campaign.add_argument("--output", required=True, type=Path)
    plan_proxy_campaign.add_argument(
        "--history",
        type=Path,
        help="Optional JSON file containing earlier campaign observations",
    )
    plan_proxy_campaign.add_argument("--limit", type=int, default=6)
    plan_proxy_campaign.add_argument(
        "--base-log-root",
        default="~/twin-traces/nas-campaign",
        help="Remote log root used when constructing per-run log folders",
    )
    plan_proxy_campaign.add_argument(
        "--fresh-only",
        action="store_true",
        help="Only include untried executable runs in the printed campaign plan",
    )

    next_proxy_case = subparsers.add_parser(
        "next-proxy-nas-case",
        help="Write a one-run plan and print the single best next proxy NAS case with commands",
    )
    next_proxy_case.add_argument(
        "--message",
        required=True,
        help="Message name, for example 'Registration Request'",
    )
    next_proxy_case.add_argument(
        "--history",
        required=True,
        type=Path,
        help="JSON file containing earlier campaign observations",
    )
    next_proxy_case.add_argument("--output", required=True, type=Path)
    next_proxy_case.add_argument(
        "--base-log-root",
        default="~/twin-traces/nas-campaign",
        help="Remote log root used when constructing the per-run log folder",
    )
    next_proxy_case.add_argument(
        "--allow-repeats",
        action="store_true",
        help="Allow already-tried operators when no fresh executable case should be suggested",
    )

    plan_simulation_campaign = subparsers.add_parser(
        "plan-simulated-nas-campaign",
        help="Expand nested-simulation NAS recommendations into concrete trace-simulation commands",
    )
    plan_simulation_campaign.add_argument(
        "--message",
        required=True,
        help="Message name, for example 'Registration Request'",
    )
    plan_simulation_campaign.add_argument("--output", required=True, type=Path)
    plan_simulation_campaign.add_argument(
        "--history",
        type=Path,
        help="Optional JSON file containing earlier campaign observations",
    )
    plan_simulation_campaign.add_argument("--limit", type=int, default=6)
    plan_simulation_campaign.add_argument(
        "--baseline-trace",
        default="~/TWIN/remote_traces/ngap-registration-core-augmented.json",
        help="Trace used to locate nested Registration Request payloads for simulation",
    )
    plan_simulation_campaign.add_argument(
        "--base-output-root",
        default="~/twin-traces/nas-campaign",
        help="Remote output root used when constructing simulated trace artifact paths",
    )

    next_simulated_case = subparsers.add_parser(
        "next-simulated-nas-case",
        help="Write a one-run nested-simulation plan and print the single best next simulated NAS case",
    )
    next_simulated_case.add_argument(
        "--message",
        required=True,
        help="Message name, for example 'Registration Request'",
    )
    next_simulated_case.add_argument(
        "--history",
        required=True,
        type=Path,
        help="JSON file containing earlier campaign observations",
    )
    next_simulated_case.add_argument("--output", required=True, type=Path)
    next_simulated_case.add_argument(
        "--baseline-trace",
        default="~/TWIN/remote_traces/ngap-registration-core-augmented.json",
        help="Trace used to locate nested Registration Request payloads for simulation",
    )
    next_simulated_case.add_argument(
        "--base-output-root",
        default="~/twin-traces/nas-campaign",
        help="Remote output root used when constructing simulated trace artifact paths",
    )

    record_proxy_observation = subparsers.add_parser(
        "record-proxy-nas-observation",
        help="Append the result of one executed proxy run back into structured scheduler history",
    )
    record_proxy_observation.add_argument("--plan", required=True, type=Path)
    record_proxy_observation.add_argument("--run-id", required=True)
    record_proxy_observation.add_argument(
        "--result-class",
        required=True,
        choices=ALL_RESULT_CLASSES,
    )
    record_proxy_observation.add_argument(
        "--history",
        required=True,
        type=Path,
        help="JSON history file to update or create",
    )
    record_proxy_observation.add_argument(
        "--notes",
        default="",
        help="Optional free-form note, for example the key AMF log line",
    )
    record_proxy_observation.add_argument("--message-name")
    record_proxy_observation.add_argument("--family-name")
    record_proxy_observation.add_argument("--operator")
    record_proxy_observation.add_argument("--proxy-mutation")
    record_proxy_observation.add_argument("--proxy-value")

    record_simulated_observation = subparsers.add_parser(
        "record-simulated-nas-observation",
        help="Append the result of one simulated NAS run back into structured scheduler history",
    )
    record_simulated_observation.add_argument("--plan", required=True, type=Path)
    record_simulated_observation.add_argument("--run-id", required=True)
    record_simulated_observation.add_argument(
        "--history",
        required=True,
        type=Path,
        help="JSON history file to update or create",
    )
    record_simulated_observation.add_argument(
        "--notes",
        default="",
        help="Optional free-form note, for example what changed in the simulated trace",
    )
    record_simulated_observation.add_argument("--message-name")
    record_simulated_observation.add_argument("--family-name")
    record_simulated_observation.add_argument("--operator")
    record_simulated_observation.add_argument("--proxy-mutation")
    record_simulated_observation.add_argument("--proxy-value")

    render_runner = subparsers.add_parser(
        "render-proxy-nas-runner",
        help="Render a single remote tmux launcher script for one planned proxy NAS run",
    )
    render_runner.add_argument("--plan", required=True, type=Path)
    render_runner.add_argument("--run-id", required=True)
    render_runner.add_argument("--output", required=True, type=Path)
    render_runner.add_argument(
        "--session-name",
        help="Optional tmux session name override",
    )

    render_record = subparsers.add_parser(
        "render-proxy-nas-record-command",
        help="Render the exact history-record command for one planned proxy NAS run",
    )
    render_record.add_argument("--plan", required=True, type=Path)
    render_record.add_argument("--run-id", required=True)
    render_record.add_argument(
        "--plan-path",
        required=True,
        help="Path string that should appear in the rendered command on the remote host",
    )
    render_record.add_argument(
        "--history-path",
        required=True,
        help="Path string that should appear in the rendered command on the remote host",
    )

    classify_proxy_result = subparsers.add_parser(
        "classify-proxy-nas-result",
        help="Classify one proxy NAS run from its collected logs and suggest note text",
    )
    classify_proxy_result.add_argument(
        "--logs-dir",
        required=True,
        type=Path,
        help="Directory containing proxy.log, amf.log, gnb.log, and ue.log",
    )

    classify_and_render_record = subparsers.add_parser(
        "classify-and-render-proxy-nas-record",
        help="Classify one proxy NAS run from its logs and print the exact history-record command",
    )
    classify_and_render_record.add_argument("--plan", required=True, type=Path)
    classify_and_render_record.add_argument("--run-id", required=True)
    classify_and_render_record.add_argument(
        "--logs-dir",
        required=True,
        type=Path,
        help="Directory containing proxy.log, amf.log, gnb.log, and ue.log",
    )
    classify_and_render_record.add_argument(
        "--plan-path",
        required=True,
        help="Path string that should appear in the rendered command on the remote host",
    )
    classify_and_render_record.add_argument(
        "--history-path",
        required=True,
        help="Path string that should appear in the rendered command on the remote host",
    )
    classify_and_render_record.add_argument("--message-name")
    classify_and_render_record.add_argument("--family-name")
    classify_and_render_record.add_argument("--operator")
    classify_and_render_record.add_argument("--proxy-mutation")
    classify_and_render_record.add_argument("--proxy-value")

    extract_text = subparsers.add_parser(
        "extract-text",
        help="Extract a structured trace from tshark -V text output",
    )
    extract_text.add_argument("--input", required=True, type=Path)
    extract_text.add_argument("--output", required=True, type=Path)
    extract_text.add_argument(
        "--procedure",
        default="Captured NGAP Trace",
        help="Procedure name to store in the output trace",
    )
    extract_text.add_argument(
        "--description",
        default="",
        help="Optional description stored in the output trace",
    )
    extract_text.add_argument(
        "--amf-ip",
        default="127.0.0.5",
        help="AMF IP used to infer message direction",
    )

    augment_json = subparsers.add_parser(
        "augment-json",
        help="Augment a structured trace using tshark JSON output",
    )
    augment_json.add_argument("--input", required=True, type=Path)
    augment_json.add_argument("--json-input", required=True, type=Path)
    augment_json.add_argument("--output", required=True, type=Path)

    summarize_log = subparsers.add_parser(
        "summarize-amf-log",
        help="Summarize key events from an Open5GS AMF journal log",
    )
    summarize_log.add_argument("--input", required=True, type=Path)

    summarize_ueransim = subparsers.add_parser(
        "summarize-ueransim-log",
        help="Summarize key events from a UERANSIM gNB or UE log",
    )
    summarize_ueransim.add_argument("--input", required=True, type=Path)

    diff_traces = subparsers.add_parser(
        "diff-traces",
        help="Show a compact message-by-message diff between two traces",
    )
    diff_traces.add_argument("--base", required=True, type=Path)
    diff_traces.add_argument("--mutated", required=True, type=Path)

    preview_proxy = subparsers.add_parser(
        "preview-initial-nas-mutation",
        help="Preview a proxy-style mutation against the first Registration Request NAS bytes",
    )
    preview_proxy.add_argument("--input", required=True, type=Path)
    preview_proxy.add_argument(
        "--mutation",
        required=True,
        choices=[
            "message-type",
            "registration-type-and-ngksi",
            "security-header",
            "mobile-identity-length-zero",
            "mobile-identity-invalid-bcd-tail",
            "mobile-identity-toggle-type-bits",
        ],
    )
    preview_proxy.add_argument(
        "--value",
        help="Byte value used by message-type or security-header mutations, for example 0x57",
    )
    preview_proxy.add_argument(
        "--index",
        type=int,
        default=1,
        help="1-based message index to inspect, defaults to the first message",
    )

    preview_optional_ie = subparsers.add_parser(
        "preview-registration-request-optional-ie-mutation",
        help="Preview a field-name-based optional IE mutation against a Registration Request NAS payload",
    )
    preview_optional_ie.add_argument("--input", required=True, type=Path)
    preview_optional_ie.add_argument(
        "--field",
        required=True,
        choices=["requested_nssai", "fivegmm_capability"],
    )
    preview_optional_ie.add_argument(
        "--action",
        required=True,
        choices=[
            "omit",
            "duplicate",
            "bad-length",
            "unsupported-sst-sd",
            "duplicate-payload-entries",
            "set-reserved-bits",
            "truncate-payload",
        ],
    )
    preview_optional_ie.add_argument(
        "--length-value",
        help="Required only for bad-length, for example 0xff",
    )
    preview_optional_ie.add_argument(
        "--index",
        type=int,
        default=1,
        help="1-based message index to inspect, defaults to the first message",
    )

    simulate_proxy = subparsers.add_parser(
        "simulate-proxy-initial-nas",
        help="Simulate how the future proxy would mutate InitialUEMessage and write the resulting trace",
    )
    simulate_proxy.add_argument("--input", required=True, type=Path)
    simulate_proxy.add_argument("--output", required=True, type=Path)
    simulate_proxy.add_argument(
        "--mutation",
        required=True,
        choices=[
            "message-type",
            "registration-type-and-ngksi",
            "security-header",
            "mobile-identity-length-zero",
            "mobile-identity-invalid-bcd-tail",
            "mobile-identity-toggle-type-bits",
        ],
    )
    simulate_proxy.add_argument(
        "--value",
        help="Byte value used by message-type or security-header mutations, for example 0x57",
    )
    simulate_proxy.add_argument(
        "--all-matches",
        action="store_true",
        help="Mutate every matching InitialUEMessage instead of only the first one",
    )

    mutate = subparsers.add_parser("mutate", help="Apply one mutation and write output")
    mutate.add_argument("--input", required=True, type=Path)
    mutate.add_argument("--output", required=True, type=Path)
    mutate.add_argument(
        "--mutation",
        required=True,
        choices=[
            "slice-trace",
            "duplicate-message",
            "drop-message",
            "reorder-messages",
            "stale-id",
            "set-ngap-field",
            "nas-message-type",
            "patch-plain-nas-message-type",
            "nas-security-header",
            "toggle-optional-ie",
        ],
    )
    mutate.add_argument("--index", type=int)
    mutate.add_argument("--other-index", type=int)
    mutate.add_argument("--field")
    mutate.add_argument("--value")

    return parser


def cmd_show(path: Path) -> int:
    trace = load_trace(path)
    print(f"Procedure: {trace.procedure}")
    if trace.description:
        print(f"Description: {trace.description}")
    print(f"Messages: {len(trace.messages)}")
    for msg in trace.messages:
        extra = []
        if msg.ngap_fields:
            ids = ", ".join(f"{k}={v}" for k, v in msg.ngap_fields.items())
            extra.append(ids)
        if msg.nas:
            extra.append(f"NAS={msg.nas.get('message_type')}")
        suffix = f" [{'; '.join(extra)}]" if extra else ""
        print(f"{msg.id:02d}. {msg.direction} {msg.message_type}{suffix}")
    if trace.mutation_history:
        print("Mutation history:")
        for entry in trace.mutation_history:
            print(f"  - {entry}")
    return 0


def cmd_show_nas_catalog() -> int:
    profiles = get_nas_message_profiles()
    print(f"NAS message profiles: {len(profiles)}")
    for profile in profiles:
        print()
        print(f"{profile.message_name} [{profile.message_type_code}]")
        print(f"  direction: {profile.direction}")
        print(f"  phase: {profile.procedure_phase}")
        print(f"  precondition: {profile.expected_precondition}")
        if profile.baseline_signature:
            print(f"  baseline_signature: {profile.baseline_signature}")
        if profile.field_definitions:
            print(f"  field_definitions: {len(profile.field_definitions)}")
            for field_def in profile.field_definitions:
                required = "mandatory" if field_def.mandatory else "optional"
                print(
                    f"    - {field_def.name} ({field_def.kind}, {required}) = {field_def.baseline_value}"
                )
                print(f"      location: {field_def.location_hint}")
                print(f"      notes: {field_def.notes}")
                if field_def.iei_tag:
                    print(f"      iei_tag: {field_def.iei_tag}")
                if field_def.generation_rules:
                    print(f"      generation_rules: {len(field_def.generation_rules)}")
                    for rule in field_def.generation_rules:
                        print(
                            f"        - {rule.family_name} [{rule.strategy}, {rule.priority}]"
                        )
                        print(f"          rationale: {rule.rationale}")
                        if rule.candidate_values:
                            print(
                                "          candidate_values: "
                                + ", ".join(rule.candidate_values)
                            )
                        if rule.operators:
                            print(
                                "          operators: "
                                + ", ".join(rule.operators)
                            )
        print(f"  mutation families: {len(profile.mutation_families)}")
        for family in profile.mutation_families:
            print(f"    - {family.name} ({family.priority})")
            print(f"      target: {family.target}")
            print(f"      rationale: {family.rationale}")
            for operator in family.mutation_operators:
                print(f"      operator: {operator}")
    return 0


def cmd_show_nas_candidates(args: argparse.Namespace) -> int:
    try:
        candidates = (
            list_candidates_for_message(args.message)
            if args.message
            else list_all_candidates()
        )
    except NasSchedulerError as exc:
        raise SystemExit(str(exc)) from exc

    if args.executable_only:
        candidates = [candidate for candidate in candidates if candidate.executable_now]

    print(f"NAS mutation candidates: {len(candidates)}")
    for candidate in candidates:
        print()
        print(
            f"{candidate.message_name} [{candidate.message_type_code}] :: {candidate.family_name}"
        )
        print(f"  operator: {candidate.operator}")
        print(f"  priority: {candidate.priority}")
        print(f"  mode: {candidate.execution_mode}")
        print(f"  supported_by_current_impl: {candidate.executable_now}")
        print(f"  live_proxy_capable: {candidate.live_proxy_capable}")
        print(f"  rationale: {candidate.rationale}")
        if candidate.proxy_mutation:
            print(f"  proxy_mutation: {candidate.proxy_mutation}")
        if candidate.proxy_value:
            print(f"  proxy_value: {candidate.proxy_value}")
    return 0


def _format_result_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ", ".join(f"{name}={count}" for name, count in ordered)


def cmd_summarize_nas_campaign(args: argparse.Namespace) -> int:
    history = _load_history(args.history)
    try:
        summaries = summarize_campaign_history(history, message_name=args.message)
    except NasSchedulerError as exc:
        raise SystemExit(str(exc)) from exc

    if args.message:
        print(f"NAS campaign summary for {args.message}")
    else:
        print("NAS campaign summary")
    print(f"History observations considered: {len(history)}")
    print(f"Families summarized: {len(summaries)}")

    current_message = None
    for summary in summaries:
        if summary.message_name != current_message:
            current_message = summary.message_name
            print()
            print(f"{summary.message_name}")
        print(f"  - {summary.family_name}")
        print(
            f"    operators tried: {summary.tried_operators}/{summary.total_known_operators}"
        )
        print(
            f"    supported known operators: {summary.executable_known_operators}/{summary.total_known_operators}"
        )
        if summary.live_tried_operators or summary.simulation_tried_operators:
            print(
                "    tried by mode: "
                f"live={summary.live_tried_operators}, simulation={summary.simulation_tried_operators}"
            )
        print(f"    result counts: {_format_result_counts(summary.result_counts)}")
        print(f"    live result counts: {_format_result_counts(summary.live_result_counts)}")
        print(
            "    simulation result counts: "
            f"{_format_result_counts(summary.simulation_result_counts)}"
        )
        dominant = (
            sorted(summary.live_result_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
            if summary.live_result_counts
            else "none"
        )
        print(f"    dominant live result: {dominant}")
        unique = ", ".join(sorted(summary.live_result_counts)) if summary.live_result_counts else "none"
        print(f"    unique live results: {unique}")
        print(f"    saturation: {summary.saturation}")
    return 0


def _render_campaign_report_markdown(
    *,
    message_name: str,
    history_count: int,
    summaries: list[Any],
) -> str:
    live_exhausted = [
        summary
        for summary in summaries
        if summary.live_tried_operators
        and summary.live_tried_operators >= summary.executable_known_operators > 0
    ]
    simulation_complete = [
        summary
        for summary in summaries
        if summary.simulation_tried_operators
        and summary.saturation == "simulation coverage complete (no live outcome yet)"
    ]
    mixed_live = [summary for summary in summaries if len(summary.live_result_counts) >= 2]

    lines: list[str] = [
        f"# NAS Campaign Report: {message_name}",
        "",
        "## Snapshot",
        f"- History observations considered: {history_count}",
        f"- Mutation families summarized: {len(summaries)}",
        f"- Live families exhausted for current implementation: {len(live_exhausted)}",
        f"- Simulation-only families with complete supported coverage: {len(simulation_complete)}",
        "",
        "## Headline Findings",
    ]

    if live_exhausted:
        lines.append(
            f"- Live `{message_name}` coverage is exhausted for the current implemented operator set."
        )
    if simulation_complete:
        lines.append(
            f"- Nested optional-IE families for `{message_name}` are fully covered in simulation, but still lack live execution outcomes."
        )
    if mixed_live:
        families = ", ".join(f"`{summary.family_name}`" for summary in mixed_live)
        lines.append(
            f"- Mixed live outcomes were observed in {families}, showing that malformed inputs do not collapse into a single failure mode."
        )

    for summary in summaries:
        if summary.family_name == "mobile-identity value corruption":
            lines.append(
                "- `mobile-identity value corruption` is the strongest live finding: it produced both rejection/failure outcomes and repeated malformed-but-accepted behavior."
            )
        elif summary.family_name == "registration-type-and-ngksi mutation" and summary.live_result_counts:
            dominant = sorted(
                summary.live_result_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )[0][0]
            lines.append(
                f"- `registration-type-and-ngksi mutation` was dominated by `{dominant}`, indicating permissive handling for the current tested values."
            )
        elif summary.family_name == "message-type substitution" and summary.live_result_counts:
            lines.append(
                "- `message-type substitution` consistently triggered early semantic rejection, providing a stable negative-control family."
            )

    lines.extend(["", "## Family Breakdown", ""])

    for summary in summaries:
        dominant_live = (
            sorted(summary.live_result_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
            if summary.live_result_counts
            else "none"
        )
        unique_live = ", ".join(sorted(summary.live_result_counts)) if summary.live_result_counts else "none"
        lines.extend(
            [
                f"### {summary.family_name}",
                f"- Operators tried: {summary.tried_operators}/{summary.total_known_operators}",
                f"- Supported known operators: {summary.executable_known_operators}/{summary.total_known_operators}",
                f"- Tried by mode: live={summary.live_tried_operators}, simulation={summary.simulation_tried_operators}",
                f"- Result counts: {_format_result_counts(summary.result_counts)}",
                f"- Live result counts: {_format_result_counts(summary.live_result_counts)}",
                f"- Simulation result counts: {_format_result_counts(summary.simulation_result_counts)}",
                f"- Dominant live result: {dominant_live}",
                f"- Unique live results: {unique_live}",
                f"- Saturation: {summary.saturation}",
                "",
            ]
        )

    lines.extend(
        [
            "## Boundary Of Current Implementation",
            "- Plain live `Registration Request` mutations are strongly covered for the currently supported operator set.",
            "- Nested optional-IE mutations are supported through trace simulation and campaign bookkeeping.",
            "- Live execution for nested/protected NAS mutations remains the main open engineering gap.",
            "",
        ]
    )
    return "\n".join(lines)


def cmd_export_nas_campaign_report(args: argparse.Namespace) -> int:
    history = _load_history(args.history)
    try:
        summaries = summarize_campaign_history(history, message_name=args.message)
    except NasSchedulerError as exc:
        raise SystemExit(str(exc)) from exc

    report = _render_campaign_report_markdown(
        message_name=args.message,
        history_count=len(history),
        summaries=summaries,
    )
    args.output.write_text(report + "\n")
    print(f"Wrote NAS campaign report to {args.output}")
    print(f"Message: {args.message}")
    print(f"Families included: {len(summaries)}")
    print(f"History observations considered: {len(history)}")
    return 0


def _find_initial_registration_message(trace: ProcedureTrace) -> tuple[int, object]:
    for index, message in enumerate(trace.messages, start=1):
        if message.nas is None:
            continue
        raw_pdu_hex = message.nas.get("raw_pdu_hex")
        if not isinstance(raw_pdu_hex, str) or not raw_pdu_hex:
            continue
        parts = [part.strip().lower() for part in raw_pdu_hex.split(":") if part.strip()]
        if len(parts) >= 3 and parts[0] == "7e" and parts[2] == "41":
            return index, message
    raise SystemExit("No plain Registration Request raw_pdu_hex was found in the trace.")


def _render_located_field_report(
    *,
    trace_path: Path,
    index: int,
    message: object,
    report: object,
) -> None:
    print(f"Trace: {trace_path}")
    print(f"Message index: {index}")
    print(f"Message type: {message.message_type}")
    if message.nas and message.nas.get("message_type"):
        print(f"NAS label: {message.nas.get('message_type')}")
    if getattr(report, "message_name", ""):
        print(f"Locator message name: {report.message_name}")
    print(f"Raw PDU octets: {report.total_octets}")
    print(f"Raw PDU: {report.raw_pdu_hex}")

    print("Fields:")
    for field in report.fields:
        presence = "present" if field.present else "absent"
        line = f"  - {field.name} ({field.kind}): {presence}"
        if field.start_offset is not None:
            line += f", offset={field.start_offset}"
        if field.length is not None:
            line += f", length={field.length}"
        if field.value_hex:
            line += f", value={field.value_hex}"
        print(line)
        if field.details:
            print(f"    details: {field.details}")

    print("Trailing TLVs:")
    if not report.tlvs:
        print("  none detected")
    else:
        for tlv in report.tlvs:
            mapped = f", maps_to={tlv.mapped_field_name}" if tlv.mapped_field_name else ""
            print(
                f"  - tag={tlv.tag}, offset={tlv.start_offset}, value_offset={tlv.value_offset}, "
                f"value_length={tlv.value_length}, value={tlv.value_hex}{mapped}"
            )

    if report.warnings:
        print("Warnings:")
        for warning in report.warnings:
            print(f"  - {warning}")


def cmd_inspect_initial_registration_fields(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    if args.index is not None:
        if args.index < 1 or args.index > len(trace.messages):
            raise SystemExit(
                f"Message index {args.index} is outside the trace length {len(trace.messages)}."
            )
        index = args.index
        message = trace.messages[index - 1]
    else:
        index, message = _find_initial_registration_message(trace)

    if message.nas is None:
        raise SystemExit("Selected message does not carry NAS payload.")

    raw_pdu_hex = message.nas.get("raw_pdu_hex")
    if not isinstance(raw_pdu_hex, str) or not raw_pdu_hex:
        raise SystemExit("Selected NAS payload does not contain raw_pdu_hex.")

    try:
        report = inspect_registration_request_fields(raw_pdu_hex)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    _render_located_field_report(
        trace_path=args.input,
        index=index,
        message=message,
        report=report,
    )
    return 0


def cmd_inspect_nas_fields(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    if args.index < 1 or args.index > len(trace.messages):
        raise SystemExit(
            f"Message index {args.index} is outside the trace length {len(trace.messages)}."
        )

    message = trace.messages[args.index - 1]
    if message.nas is None:
        raise SystemExit("Selected message does not carry NAS payload.")

    raw_pdu_hex = message.nas.get("raw_pdu_hex")
    if not isinstance(raw_pdu_hex, str) or not raw_pdu_hex:
        raise SystemExit("Selected NAS payload does not contain raw_pdu_hex.")

    message_name = args.message
    if message_name is None:
        try:
            message_name = detect_plain_5gmm_message_name(raw_pdu_hex)
        except ValueError:
            message_name = None

    try:
        report = inspect_nas_message_fields(raw_pdu_hex, message_name=message_name)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    _render_located_field_report(
        trace_path=args.input,
        index=args.index,
        message=message,
        report=report,
    )
    return 0


def cmd_inspect_registration_request_optional_ie(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    if args.index is not None:
        if args.index < 1 or args.index > len(trace.messages):
            raise SystemExit(
                f"Message index {args.index} is outside the trace length {len(trace.messages)}."
            )
        index = args.index
        message = trace.messages[index - 1]
    else:
        index, message = _find_initial_registration_message(trace)

    if message.nas is None:
        raise SystemExit("Selected message does not carry NAS payload.")

    raw_pdu_hex = message.nas.get("raw_pdu_hex")
    if not isinstance(raw_pdu_hex, str) or not raw_pdu_hex:
        raise SystemExit("Selected NAS payload does not contain raw_pdu_hex.")

    try:
        located = locate_registration_request_optional_ie(raw_pdu_hex, args.field)
    except (ValueError, KeyError) as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Trace: {args.input}")
    print(f"Message index: {index}")
    print(f"Message type: {message.message_type}")
    if message.nas.get("message_type"):
        print(f"NAS label: {message.nas.get('message_type')}")
    print(f"Optional IE field: {args.field}")

    if located is None:
        print("Presence: absent")
        print("Details: schema-defined IE tag was not found in the trailing TLV region")
        return 0

    print("Presence: present")
    print(f"Tag: {located.tag}")
    print(f"Offset: {located.start_offset}")
    print(f"Value offset: {located.value_offset}")
    print(f"Value length: {located.value_length}")
    print(f"Value: {located.value_hex}")
    return 0


def cmd_scan_nested_registration_requests(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    if args.index is not None:
        if args.index < 1 or args.index > len(trace.messages):
            raise SystemExit(
                f"Message index {args.index} is outside the trace length {len(trace.messages)}."
            )
        indexed_messages = [(args.index, trace.messages[args.index - 1])]
    else:
        indexed_messages = list(enumerate(trace.messages, start=1))

    total_hits = 0
    for index, message in indexed_messages:
        if message.nas is None:
            continue
        raw_pdu_hex = message.nas.get("raw_pdu_hex")
        if not isinstance(raw_pdu_hex, str) or not raw_pdu_hex:
            continue

        scan = scan_for_nested_registration_requests(raw_pdu_hex)
        if not scan.hits:
            continue

        print(f"Trace: {args.input}")
        print(f"Message index: {index}")
        print(f"Message type: {message.message_type}")
        if message.nas.get("message_type"):
            print(f"NAS label: {message.nas.get('message_type')}")
        print(f"Nested Registration Request hits: {len(scan.hits)}")
        for hit_index, hit in enumerate(scan.hits, start=1):
            print(f"  Hit {hit_index}:")
            print(f"    start_offset: {hit.start_offset}")
            print(f"    raw_pdu: {hit.raw_pdu_hex}")
            if hit.optional_fields_present:
                print(
                    "    optional_fields_present: "
                    + ", ".join(hit.optional_fields_present)
                )
            else:
                print("    optional_fields_present: none")
        if scan.warnings:
            print("Warnings:")
            for warning in scan.warnings:
                print(f"  - {warning}")
        print()
        total_hits += len(scan.hits)

    if total_hits == 0:
        print("No nested plain Registration Request payloads were detected.")
    return 0


def cmd_preview_nested_registration_request_optional_ie_mutation(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    if args.index < 1 or args.index > len(trace.messages):
        raise SystemExit(
            f"Message index {args.index} is outside the trace length {len(trace.messages)}."
        )

    message = trace.messages[args.index - 1]
    if message.nas is None:
        raise SystemExit("Selected message does not carry NAS payload.")

    outer_raw_pdu_hex = message.nas.get("raw_pdu_hex")
    if not isinstance(outer_raw_pdu_hex, str) or not outer_raw_pdu_hex:
        raise SystemExit("Selected NAS payload does not contain raw_pdu_hex.")

    scan = scan_for_nested_registration_requests(outer_raw_pdu_hex)
    if args.hit < 1 or args.hit > len(scan.hits):
        raise SystemExit(
            f"--hit {args.hit} is outside the detected nested Registration Request count {len(scan.hits)}."
        )

    nested_hit = scan.hits[args.hit - 1]
    try:
        nested_result = apply_registration_request_optional_ie_mutation(
            nested_hit.raw_pdu_hex,
            field_name=args.field,
            action=args.action,
            length_value=args.length_value,
        )
        preview = preview_nested_registration_request_mutation(
            outer_raw_pdu_hex,
            hit_index=args.hit,
            after_nested_raw_pdu_hex=nested_result.after_raw_pdu_hex,
        )
    except ProxyMutationError as exc:
        raise SystemExit(str(exc)) from exc
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Trace: {args.input}")
    print(f"Outer message index: {args.index}")
    print(f"Outer message type: {message.message_type}")
    if message.nas.get("message_type"):
        print(f"Outer NAS label: {message.nas.get('message_type')}")
    print(f"Nested hit: {preview.hit_index}")
    print(f"Nested start offset: {preview.start_offset}")
    print(f"Optional IE field: {args.field}")
    print(f"Action: {args.action}")
    if args.length_value is not None:
        print(f"Length value: {args.length_value}")
    print(f"Outer before: {preview.before_outer_raw_pdu_hex}")
    print(f"Outer after:  {preview.after_outer_raw_pdu_hex}")
    print(f"Nested before: {preview.before_nested_raw_pdu_hex}")
    print(f"Nested after:  {preview.after_nested_raw_pdu_hex}")
    if nested_result.notes:
        print("Notes:")
        for note in nested_result.notes:
            print(f"  - {note}")
    return 0


def cmd_simulate_nested_registration_request_optional_ie_mutation(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    try:
        result = simulate_nested_registration_request_optional_ie_mutation(
            trace,
            message_index=args.index,
            hit_index=args.hit,
            field_name=args.field,
            action=args.action,
            length_value=args.length_value,
        )
    except ProxyMutationError as exc:
        raise SystemExit(str(exc)) from exc

    save_trace(args.output, result.trace)
    print(f"Wrote nested-RR-mutated trace to {args.output}")
    print(f"Mutated events: {len(result.events)}")
    for event in result.events:
        print(f"  - message {event.message_index}: {event.direction} {event.message_type}")
        print(f"    before: {event.before_raw_pdu_hex}")
        print(f"    after:  {event.after_raw_pdu_hex}")
        for note in event.notes:
            print(f"    note: {note}")
    return 0


def _load_history(path: Path | None) -> list[NasCampaignObservation]:
    if path is None:
        return []
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"History file {path} is not valid JSON.") from exc

    if not isinstance(payload, list):
        raise SystemExit(f"History file {path} must contain a JSON list.")

    try:
        return [NasCampaignObservation.from_dict(entry) for entry in payload]
    except (TypeError, KeyError, NasSchedulerError) as exc:
        raise SystemExit(f"History file {path} contains an invalid observation: {exc}") from exc


def _write_history(path: Path, history: list[NasCampaignObservation]) -> None:
    path.write_text(json.dumps([entry.to_dict() for entry in history], indent=2) + "\n")


def cmd_recommend_nas_next(args: argparse.Namespace) -> int:
    history = _load_history(args.history)
    try:
        recommendations = recommend_next_candidates(
            args.message,
            history,
            limit=args.limit,
            executable_only=args.executable_only,
        )
    except NasSchedulerError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Recommendations for {args.message}: {len(recommendations)}")
    for index, rec in enumerate(recommendations, start=1):
        candidate = rec.candidate
        print()
        print(f"{index}. {candidate.message_name} :: {candidate.family_name}")
        print(f"   operator: {candidate.operator}")
        print(f"   score: {rec.score}")
        print(f"   mode: {candidate.execution_mode}")
        print(f"   supported_by_current_impl: {candidate.executable_now}")
        print(f"   live_proxy_capable: {candidate.live_proxy_capable}")
        if candidate.proxy_mutation:
            value_part = (
                f" value={candidate.proxy_value}" if candidate.proxy_value is not None else ""
            )
            print(f"   proxy: {candidate.proxy_mutation}{value_part}")
        print(f"   rationale: {candidate.rationale}")
        for reason in rec.reasons:
            print(f"   reason: {reason}")
    return 0


def cmd_plan_proxy_nas_campaign(args: argparse.Namespace) -> int:
    history = _load_history(args.history)
    try:
        initial_limit = max(args.limit * 10, args.limit) if args.fresh_only else args.limit
        plan = build_proxy_campaign_plan(
            args.message,
            history,
            limit=initial_limit,
            base_log_root=args.base_log_root,
        )
    except NasSchedulerError as exc:
        raise SystemExit(str(exc)) from exc

    if args.fresh_only:
        plan = ProxyCampaignPlan(
            message_name=plan.message_name,
            history_count=plan.history_count,
            runs=[
                run
                for run in plan.runs
                if "untried operator" in run.recommendation_reasons
            ][: args.limit],
        )

    save_campaign_plan(args.output, plan)
    print(f"Wrote proxy NAS campaign plan to {args.output}")
    print(f"Message: {plan.message_name}")
    print(f"History observations considered: {plan.history_count}")
    print(f"Runs planned: {len(plan.runs)}")
    if args.fresh_only and not plan.runs:
        print("No fresh executable proxy NAS runs are currently available.")
        return 0

    for index, run in enumerate(plan.runs, start=1):
        print()
        print(f"{index}. {run.run_id}")
        print(f"   family: {run.family_name}")
        print(f"   operator: {run.operator}")
        print(f"   score: {run.score}")
        print(f"   result_hint: {run.result_hint}")
        print(f"   logs_dir: {run.logs_dir}")
        print(f"   rationale: {run.rationale}")
        for reason in run.recommendation_reasons:
            print(f"   reason: {reason}")
        print("   setup:")
        print(f"     mkdir -p {run.logs_dir}")
        print("   terminal1 proxy:")
        for line in run.proxy_command.splitlines():
            print(f"     {line}")
        print("   terminal2 amf log:")
        print(f"     {run.amf_log_command}")
        print("   terminal3 gNB:")
        for line in run.gnb_command.splitlines():
            print(f"     {line}")
        print("   terminal4 UE:")
        for line in run.ue_command.splitlines():
            print(f"     {line}")
    return 0


def cmd_next_proxy_nas_case(args: argparse.Namespace) -> int:
    history = _load_history(args.history)
    try:
        expanded_plan = build_proxy_campaign_plan(
            args.message,
            history,
            limit=25,
            base_log_root=args.base_log_root,
        )
    except NasSchedulerError as exc:
        raise SystemExit(str(exc)) from exc

    selected_run = None
    if args.allow_repeats:
        if expanded_plan.runs:
            selected_run = expanded_plan.runs[0]
    else:
        selected_run = next(
            (
                run
                for run in expanded_plan.runs
                if "untried operator" in run.recommendation_reasons
            ),
            None,
        )

    plan = ProxyCampaignPlan(
        message_name=expanded_plan.message_name,
        history_count=expanded_plan.history_count,
        runs=[selected_run] if selected_run is not None else [],
    )

    save_campaign_plan(args.output, plan)
    print(f"Wrote one-run proxy NAS plan to {args.output}")
    print(f"Message: {plan.message_name}")
    print(f"History observations considered: {plan.history_count}")

    if not plan.runs:
        if args.allow_repeats:
            print("No executable proxy NAS run is currently available.")
        else:
            print("No fresh executable proxy NAS run is currently available.")
            print("Use --allow-repeats if you want the best already-tried revisit candidate.")
        return 0

    run = plan.runs[0]
    print()
    print(f"Next run: {run.run_id}")
    print(f"Family: {run.family_name}")
    print(f"Operator: {run.operator}")
    print(f"Score: {run.score}")
    print(f"Result hint: {run.result_hint}")
    print(f"Logs dir: {run.logs_dir}")
    print(f"Rationale: {run.rationale}")
    for reason in run.recommendation_reasons:
        print(f"Reason: {reason}")

    print()
    print("Setup:")
    print(f"  mkdir -p {run.logs_dir}")
    print("AMF log:")
    print(f"  {run.amf_log_command}")
    print("Proxy:")
    for line in run.proxy_command.splitlines():
        print(f"  {line}")
    print("gNB:")
    for line in run.gnb_command.splitlines():
        print(f"  {line}")
    print("UE:")
    for line in run.ue_command.splitlines():
        print(f"  {line}")

    print()
    print("After the run:")
    classify_lines = [
        "  python3 -m src.ngap_nas_fuzz.cli classify-and-render-proxy-nas-record \\",
        f"    --plan {args.output} \\",
        f"    --run-id {run.run_id} \\",
        f"    --logs-dir {run.logs_dir} \\",
        f"    --plan-path {args.output} \\",
        f"    --history-path {args.history} \\",
        f"    --message-name {shlex.quote(run.message_name)} \\",
        f"    --family-name {shlex.quote(run.family_name)} \\",
        f"    --operator {shlex.quote(run.operator)} \\",
        f"    --proxy-mutation {shlex.quote(run.proxy_mutation)}",
    ]
    if run.proxy_value is not None:
        classify_lines[-1] += " \\"
        classify_lines.append(f"    --proxy-value {shlex.quote(run.proxy_value)}")
    for line in classify_lines:
        print(line)
    return 0


def cmd_plan_simulated_nas_campaign(args: argparse.Namespace) -> int:
    history = _load_history(args.history)
    try:
        plan = build_simulation_campaign_plan(
            args.message,
            history,
            baseline_trace=args.baseline_trace,
            limit=args.limit,
            base_output_root=args.base_output_root,
        )
    except (NasSchedulerError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc

    save_simulation_campaign_plan(args.output, plan)
    print(f"Wrote simulated NAS campaign plan to {args.output}")
    print(f"Message: {plan.message_name}")
    print(f"History observations considered: {plan.history_count}")
    print(f"Baseline trace: {plan.baseline_trace}")
    print(f"Runs planned: {len(plan.runs)}")
    if not plan.runs:
        print("No supported nested-simulation NAS runs are currently available.")
        return 0

    for index, run in enumerate(plan.runs, start=1):
        print()
        print(f"{index}. {run.run_id}")
        print(f"   family: {run.family_name}")
        print(f"   operator: {run.operator}")
        print(f"   score: {run.score}")
        print(f"   field: {run.field_name}")
        print(f"   action: {run.action}")
        if run.length_value is not None:
            print(f"   length_value: {run.length_value}")
        print(f"   outer_message_index: {run.outer_message_index}")
        print(f"   nested_hit_index: {run.nested_hit_index}")
        print(f"   output_trace: {run.output_trace}")
        print(f"   rationale: {run.rationale}")
        for reason in run.recommendation_reasons:
            print(f"   reason: {reason}")
        print("   simulate:")
        for line in run.simulate_command.splitlines():
            print(f"     {line}")
        print("   diff:")
        for line in run.diff_command.splitlines():
            print(f"     {line}")
    return 0


def cmd_next_simulated_nas_case(args: argparse.Namespace) -> int:
    history = _load_history(args.history)
    try:
        expanded_plan = build_simulation_campaign_plan(
            args.message,
            history,
            baseline_trace=args.baseline_trace,
            limit=25,
            base_output_root=args.base_output_root,
        )
    except (NasSchedulerError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc

    selected_run = next(
        (
            run
            for run in expanded_plan.runs
            if "untried operator" in run.recommendation_reasons
        ),
        None,
    )

    plan = SimulationCampaignPlan(
        message_name=expanded_plan.message_name,
        history_count=expanded_plan.history_count,
        baseline_trace=expanded_plan.baseline_trace,
        runs=[selected_run] if selected_run is not None else [],
    )

    save_simulation_campaign_plan(args.output, plan)
    print(f"Wrote one-run simulated NAS plan to {args.output}")
    print(f"Message: {plan.message_name}")
    print(f"History observations considered: {plan.history_count}")
    print(f"Baseline trace: {plan.baseline_trace}")

    if not plan.runs:
        print("No fresh supported nested-simulation NAS run is currently available.")
        return 0

    run = plan.runs[0]
    print()
    print(f"Next simulation: {run.run_id}")
    print(f"Family: {run.family_name}")
    print(f"Operator: {run.operator}")
    print(f"Score: {run.score}")
    print(f"Field: {run.field_name}")
    print(f"Action: {run.action}")
    if run.length_value is not None:
        print(f"Length value: {run.length_value}")
    print(f"Outer message index: {run.outer_message_index}")
    print(f"Nested hit index: {run.nested_hit_index}")
    print(f"Output trace: {run.output_trace}")
    print(f"Rationale: {run.rationale}")
    for reason in run.recommendation_reasons:
        print(f"Reason: {reason}")

    print()
    print("Simulate:")
    for line in run.simulate_command.splitlines():
        print(f"  {line}")
    print("Inspect diff:")
    for line in run.diff_command.splitlines():
        print(f"  {line}")
    print()
    print("After the simulation:")
    print("  python3 -m src.ngap_nas_fuzz.cli record-simulated-nas-observation \\")
    print(f"    --plan {args.output} \\")
    print(f"    --run-id {run.run_id} \\")
    print(f"    --history {args.history} \\")
    print(f"    --message-name {shlex.quote(run.message_name)} \\")
    print(f"    --family-name {shlex.quote(run.family_name)} \\")
    print(f"    --operator {shlex.quote(run.operator)} \\")
    print("    --proxy-mutation nested-registration-request-optional-ie \\")
    proxy_value = f"action:{run.action}"
    if run.length_value is not None:
        proxy_value += f",length:{run.length_value}"
    print(f"    --proxy-value {shlex.quote(proxy_value)} \\")
    print('    --notes "<replace with what changed in the simulated trace>"')
    return 0


def cmd_record_proxy_nas_observation(args: argparse.Namespace) -> int:
    try:
        plan = load_campaign_plan(args.plan)
        observation = append_observation_from_run(
            plan,
            args.run_id,
            args.result_class,
            notes=args.notes,
        )
    except ValueError as exc:
        required = [
            args.message_name,
            args.family_name,
            args.operator,
            args.proxy_mutation,
        ]
        if not all(required):
            raise SystemExit(str(exc)) from exc
        observation = build_observation(
            message_name=args.message_name,
            family_name=args.family_name,
            operator=args.operator,
            result_class=args.result_class,
            notes=args.notes,
            proxy_mutation=args.proxy_mutation,
            proxy_value=args.proxy_value,
        )
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc

    history = _load_history(args.history) if args.history.exists() else []
    history.append(observation)
    _write_history(args.history, history)

    print(f"Appended observation to {args.history}")
    print(f"Message: {observation.message_name}")
    print(f"Family: {observation.family_name}")
    print(f"Operator: {observation.operator}")
    print(f"Result: {observation.result_class}")
    if observation.notes:
        print(f"Notes: {observation.notes}")
    print(f"Total history entries: {len(history)}")
    return 0


def cmd_record_simulated_nas_observation(args: argparse.Namespace) -> int:
    try:
        plan = load_simulation_campaign_plan(args.plan)
        observation = append_observation_from_simulation_run(
            plan,
            args.run_id,
            "simulation-artifact",
            notes=args.notes,
        )
    except ValueError as exc:
        required = [
            args.message_name,
            args.family_name,
            args.operator,
            args.proxy_mutation,
        ]
        if not all(required):
            raise SystemExit(str(exc)) from exc
        observation = build_observation(
            message_name=args.message_name,
            family_name=args.family_name,
            operator=args.operator,
            result_class="simulation-artifact",
            notes=args.notes,
            proxy_mutation=args.proxy_mutation,
            proxy_value=args.proxy_value,
        )
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc

    history = _load_history(args.history) if args.history.exists() else []
    history.append(observation)
    _write_history(args.history, history)

    print(f"Appended simulated observation to {args.history}")
    print(f"Message: {observation.message_name}")
    print(f"Family: {observation.family_name}")
    print(f"Operator: {observation.operator}")
    print(f"Result: {observation.result_class}")
    if observation.notes:
        print(f"Notes: {observation.notes}")
    print(f"Total history entries: {len(history)}")
    return 0


def cmd_render_proxy_nas_runner(args: argparse.Namespace) -> int:
    try:
        plan = load_campaign_plan(args.plan)
        script = render_tmux_launcher_script(
            plan,
            args.run_id,
            session_name=args.session_name,
        )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc

    args.output.write_text(script)
    args.output.chmod(0o755)
    print(f"Wrote remote tmux launcher to {args.output}")
    print(f"Run id: {args.run_id}")
    return 0


def cmd_render_proxy_nas_record_command(args: argparse.Namespace) -> int:
    try:
        plan = load_campaign_plan(args.plan)
        command = render_record_command(
            plan,
            args.run_id,
            plan_path=args.plan_path,
            history_path=args.history_path,
        )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc

    print(command)
    return 0


def cmd_classify_proxy_nas_result(args: argparse.Namespace) -> int:
    suggestion = classify_proxy_nas_result_logs(args.logs_dir)
    print(f"Logs dir: {args.logs_dir}")
    print(f"Suggested result class: {suggestion.result_class}")
    print(f"Suggested note: {suggestion.note}")
    print(f"Confidence: {suggestion.confidence}")
    if suggestion.evidence:
        print("Evidence:")
        for item in suggestion.evidence:
            print(f"  - {item}")
    return 0


def cmd_classify_and_render_proxy_nas_record(args: argparse.Namespace) -> int:
    suggestion = classify_proxy_nas_result_logs(args.logs_dir)
    try:
        plan = load_campaign_plan(args.plan)
        command = render_filled_record_command(
            plan,
            args.run_id,
            result_class=suggestion.result_class,
            notes=suggestion.note,
            plan_path=args.plan_path,
            history_path=args.history_path,
        )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        required = [
            args.message_name,
            args.family_name,
            args.operator,
            args.proxy_mutation,
        ]
        if not all(required):
            raise SystemExit(
                "Run metadata could not be recovered from the plan. "
                "Re-run with --message-name, --family-name, --operator, and --proxy-mutation."
            )
        command_lines = [
            "python3 -m src.ngap_nas_fuzz.cli record-proxy-nas-observation \\",
            f"  --plan {shlex.quote(args.plan_path)} \\",
            f"  --run-id {shlex.quote(args.run_id)} \\",
            f"  --result-class {shlex.quote(suggestion.result_class)} \\",
            f"  --history {shlex.quote(args.history_path)} \\",
            f"  --message-name {shlex.quote(args.message_name)} \\",
            f"  --family-name {shlex.quote(args.family_name)} \\",
            f"  --operator {shlex.quote(args.operator)} \\",
            f"  --proxy-mutation {shlex.quote(args.proxy_mutation)} \\",
        ]
        if args.proxy_value is not None:
            command_lines.append(f"  --proxy-value {shlex.quote(args.proxy_value)} \\")
        command_lines.append(f"  --notes {shlex.quote(suggestion.note)}")
        command = "\n".join(command_lines)

    print(f"Logs dir: {args.logs_dir}")
    print(f"Suggested result class: {suggestion.result_class}")
    print(f"Suggested note: {suggestion.note}")
    print(f"Confidence: {suggestion.confidence}")
    if suggestion.evidence:
        print("Evidence:")
        for item in suggestion.evidence:
            print(f"  - {item}")
    print()
    print("Record command:")
    print(command)
    return 0


def cmd_extract_text(args: argparse.Namespace) -> int:
    trace = extract_trace_from_tshark_text(
        args.input.read_text(),
        procedure_name=args.procedure,
        description=args.description,
        amf_ip=args.amf_ip,
    )
    save_trace(args.output, trace)
    print(f"Wrote extracted trace to {args.output}")
    print(f"Messages extracted: {len(trace.messages)}")
    return 0


def cmd_augment_json(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    result = augment_trace_with_tshark_json(trace, args.json_input.read_text())
    save_trace(args.output, result)
    print(f"Wrote augmented trace to {args.output}")
    print(f"Messages augmented: {len(result.messages)}")
    return 0


def cmd_summarize_amf_log(path: Path) -> int:
    summary = summarize_amf_log(path.read_text())
    print(f"Total parsed events: {summary['total_events']}")
    print("By level:")
    for level, count in sorted(summary["by_level"].items()):
        print(f"  {level}: {count}")

    print("Key events:")
    for name, events in summary["key_events"].items():
        if not events:
            continue
        print(f"  {name}: {len(events)}")
        for event in events[:5]:
            print(f"    L{event.line_number} [{event.component}/{event.level}] {event.message}")
    return 0


def cmd_summarize_ueransim_log(path: Path) -> int:
    summary = summarize_ueransim_log(path.read_text())
    print(f"Total parsed events: {summary['total_events']}")
    print("By level:")
    for level, count in sorted(summary["by_level"].items()):
        print(f"  {level}: {count}")

    print("Key events:")
    for name, events in summary["key_events"].items():
        if not events:
            continue
        print(f"  {name}: {len(events)}")
        for event in events[:5]:
            print(f"    L{event.line_number} [{event.component}/{event.level}] {event.message}")
    return 0


def _format_value(value) -> str:
    return json.dumps(value, sort_keys=True)


def _diff_mapping(prefix: str, base_mapping, mutated_mapping) -> list[str]:
    lines: list[str] = []
    all_keys = sorted(set(base_mapping.keys()) | set(mutated_mapping.keys()))
    for key in all_keys:
        base_value = base_mapping.get(key)
        mutated_value = mutated_mapping.get(key)
        if base_value != mutated_value:
            lines.append(
                f"{prefix}.{key}: {_format_value(base_value)} -> {_format_value(mutated_value)}"
            )
    return lines


def cmd_diff_traces(base_path: Path, mutated_path: Path) -> int:
    base = load_trace(base_path)
    mutated = load_trace(mutated_path)

    print(f"Base trace: {base_path}")
    print(f"Mutated trace: {mutated_path}")
    print(f"Message count: {len(base.messages)} -> {len(mutated.messages)}")

    changed = 0
    max_len = max(len(base.messages), len(mutated.messages))
    for index in range(max_len):
        base_msg = base.messages[index] if index < len(base.messages) else None
        mutated_msg = mutated.messages[index] if index < len(mutated.messages) else None
        if base_msg is None:
            changed += 1
            print(f"\nMessage {index + 1:02d}: added in mutated trace")
            print(f"  mutated: {mutated_msg.direction} {mutated_msg.message_type}")
            continue
        if mutated_msg is None:
            changed += 1
            print(f"\nMessage {index + 1:02d}: removed from mutated trace")
            print(f"  base: {base_msg.direction} {base_msg.message_type}")
            continue

        diff_lines: list[str] = []
        if base_msg.direction != mutated_msg.direction:
            diff_lines.append(f"direction: {base_msg.direction} -> {mutated_msg.direction}")
        if base_msg.protocol != mutated_msg.protocol:
            diff_lines.append(f"protocol: {base_msg.protocol} -> {mutated_msg.protocol}")
        if base_msg.message_type != mutated_msg.message_type:
            diff_lines.append(f"message_type: {base_msg.message_type} -> {mutated_msg.message_type}")
        diff_lines.extend(_diff_mapping("ngap", base_msg.ngap_fields, mutated_msg.ngap_fields))
        diff_lines.extend(
            _diff_mapping("nas", base_msg.nas or {}, mutated_msg.nas or {})
        )

        base_note = base_msg.metadata.get("mutation_note")
        mutated_note = mutated_msg.metadata.get("mutation_note")
        if base_note != mutated_note:
            diff_lines.append(
                f"metadata.mutation_note: {_format_value(base_note)} -> {_format_value(mutated_note)}"
            )

        if diff_lines:
            changed += 1
            print(f"\nMessage {index + 1:02d}:")
            print(f"  base:    {base_msg.direction} {base_msg.message_type}")
            print(f"  mutated: {mutated_msg.direction} {mutated_msg.message_type}")
            for line in diff_lines:
                print(f"  - {line}")

    if changed == 0:
        print("No differences found.")
    else:
        print(f"\nChanged message positions: {changed}")
    return 0


def cmd_preview_initial_nas_mutation(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    if args.index < 1:
        raise SystemExit("--index must be a 1-based positive integer.")
    try:
        message = trace.messages[args.index - 1]
    except IndexError as exc:
        raise SystemExit(
            f"Message index {args.index} is outside the trace length {len(trace.messages)}."
        ) from exc

    if message.nas is None:
        raise SystemExit("Selected message does not carry NAS payload.")

    raw_pdu_hex = message.nas.get("raw_pdu_hex")
    if not raw_pdu_hex:
        raise SystemExit("Selected NAS payload does not contain raw_pdu_hex.")

    spec = InitialNasMutationSpec(mutation=args.mutation, value=args.value)
    try:
        result = apply_initial_registration_mutation(raw_pdu_hex, spec)
    except ProxyMutationError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Trace: {args.input}")
    print(f"Message index: {args.index}")
    print(f"Message type: {message.message_type}")
    print(f"NAS label: {message.nas.get('message_type')}")
    print(f"Mutation: {args.mutation}")
    if args.value is not None:
        print(f"Value: {args.value}")
    print(f"Before: {result.before_raw_pdu_hex}")
    print(f"After:  {result.after_raw_pdu_hex}")
    if result.notes:
        print("Notes:")
        for note in result.notes:
            print(f"  - {note}")
    return 0


def cmd_preview_registration_request_optional_ie_mutation(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    if args.index < 1:
        raise SystemExit("--index must be a 1-based positive integer.")
    try:
        message = trace.messages[args.index - 1]
    except IndexError as exc:
        raise SystemExit(
            f"Message index {args.index} is outside the trace length {len(trace.messages)}."
        ) from exc

    if message.nas is None:
        raise SystemExit("Selected message does not carry NAS payload.")

    raw_pdu_hex = message.nas.get("raw_pdu_hex")
    if not raw_pdu_hex:
        raise SystemExit("Selected NAS payload does not contain raw_pdu_hex.")

    try:
        result = apply_registration_request_optional_ie_mutation(
            raw_pdu_hex,
            field_name=args.field,
            action=args.action,
            length_value=args.length_value,
        )
    except ProxyMutationError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Trace: {args.input}")
    print(f"Message index: {args.index}")
    print(f"Message type: {message.message_type}")
    print(f"NAS label: {message.nas.get('message_type')}")
    print(f"Optional IE field: {args.field}")
    print(f"Action: {args.action}")
    if args.length_value is not None:
        print(f"Length value: {args.length_value}")
    print(f"Before: {result.before_raw_pdu_hex}")
    print(f"After:  {result.after_raw_pdu_hex}")
    if result.notes:
        print("Notes:")
        for note in result.notes:
            print(f"  - {note}")
    return 0


def cmd_simulate_proxy_initial_nas(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    spec = InitialNasMutationSpec(mutation=args.mutation, value=args.value)
    cfg = ProxyExecutionConfig(match_once=not args.all_matches)
    try:
        result = simulate_initial_nas_proxy(trace, spec, cfg)
    except ProxyMutationError as exc:
        raise SystemExit(str(exc)) from exc

    save_trace(args.output, result.trace)
    print(f"Wrote proxy-simulated trace to {args.output}")
    print(f"Mutated matches: {len(result.events)}")
    for event in result.events:
        print(
            f"  - message {event.message_index}: {event.direction} {event.message_type}"
        )
        print(f"    before: {event.before_raw_pdu_hex}")
        print(f"    after:  {event.after_raw_pdu_hex}")
        for note in event.notes:
            print(f"    note:   {note}")
    return 0


def cmd_mutate(args: argparse.Namespace) -> int:
    trace = load_trace(args.input)
    try:
        if args.mutation == "slice-trace":
            result = slice_trace(trace, args.index, args.other_index)
        elif args.mutation == "duplicate-message":
            result = duplicate_message(trace, args.index)
        elif args.mutation == "drop-message":
            result = drop_message(trace, args.index)
        elif args.mutation == "reorder-messages":
            result = reorder_messages(trace, args.index, args.other_index)
        elif args.mutation == "stale-id":
            result = stale_id(trace, args.index, args.field, args.other_index)
        elif args.mutation == "set-ngap-field":
            result = set_ngap_field(trace, args.index, args.field, args.value)
        elif args.mutation == "nas-message-type":
            result = nas_message_type(trace, args.index, args.value)
        elif args.mutation == "patch-plain-nas-message-type":
            result = patch_plain_nas_message_type(trace, args.index, args.value, args.field)
        elif args.mutation == "nas-security-header":
            result = nas_security_header(trace, args.index, args.value)
        elif args.mutation == "toggle-optional-ie":
            result = toggle_optional_ie(trace, args.index, args.value)
        else:
            raise MutationError(f"Unsupported mutation '{args.mutation}'.")
    except MutationError as exc:
        raise SystemExit(str(exc))

    save_trace(args.output, result)
    print(f"Wrote mutated trace to {args.output}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "show":
        return cmd_show(args.input)
    if args.command == "show-nas-catalog":
        return cmd_show_nas_catalog()
    if args.command == "show-nas-candidates":
        return cmd_show_nas_candidates(args)
    if args.command == "summarize-nas-campaign":
        return cmd_summarize_nas_campaign(args)
    if args.command == "export-nas-campaign-report":
        return cmd_export_nas_campaign_report(args)
    if args.command == "inspect-initial-registration-fields":
        return cmd_inspect_initial_registration_fields(args)
    if args.command == "inspect-nas-fields":
        return cmd_inspect_nas_fields(args)
    if args.command == "inspect-registration-request-optional-ie":
        return cmd_inspect_registration_request_optional_ie(args)
    if args.command == "scan-nested-registration-requests":
        return cmd_scan_nested_registration_requests(args)
    if args.command == "preview-nested-registration-request-optional-ie-mutation":
        return cmd_preview_nested_registration_request_optional_ie_mutation(args)
    if args.command == "simulate-nested-registration-request-optional-ie-mutation":
        return cmd_simulate_nested_registration_request_optional_ie_mutation(args)
    if args.command == "recommend-nas-next":
        return cmd_recommend_nas_next(args)
    if args.command == "plan-proxy-nas-campaign":
        return cmd_plan_proxy_nas_campaign(args)
    if args.command == "next-proxy-nas-case":
        return cmd_next_proxy_nas_case(args)
    if args.command == "plan-simulated-nas-campaign":
        return cmd_plan_simulated_nas_campaign(args)
    if args.command == "next-simulated-nas-case":
        return cmd_next_simulated_nas_case(args)
    if args.command == "record-proxy-nas-observation":
        return cmd_record_proxy_nas_observation(args)
    if args.command == "record-simulated-nas-observation":
        return cmd_record_simulated_nas_observation(args)
    if args.command == "render-proxy-nas-runner":
        return cmd_render_proxy_nas_runner(args)
    if args.command == "render-proxy-nas-record-command":
        return cmd_render_proxy_nas_record_command(args)
    if args.command == "classify-proxy-nas-result":
        return cmd_classify_proxy_nas_result(args)
    if args.command == "classify-and-render-proxy-nas-record":
        return cmd_classify_and_render_proxy_nas_record(args)
    if args.command == "extract-text":
        return cmd_extract_text(args)
    if args.command == "augment-json":
        return cmd_augment_json(args)
    if args.command == "summarize-amf-log":
        return cmd_summarize_amf_log(args.input)
    if args.command == "summarize-ueransim-log":
        return cmd_summarize_ueransim_log(args.input)
    if args.command == "diff-traces":
        return cmd_diff_traces(args.base, args.mutated)
    if args.command == "preview-initial-nas-mutation":
        return cmd_preview_initial_nas_mutation(args)
    if args.command == "preview-registration-request-optional-ie-mutation":
        return cmd_preview_registration_request_optional_ie_mutation(args)
    if args.command == "simulate-proxy-initial-nas":
        return cmd_simulate_proxy_initial_nas(args)
    if args.command == "mutate":
        return cmd_mutate(args)
    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
