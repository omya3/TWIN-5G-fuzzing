from __future__ import annotations

from dataclasses import dataclass, field

from .models import ProcedureTrace
from .nas_nested_inspector import (
    preview_nested_registration_request_mutation,
    scan_for_nested_registration_requests,
)
from .proxy_policy import (
    InitialNasMutationResult,
    InitialNasMutationSpec,
    ProxyMutationError,
    apply_initial_registration_mutation,
    apply_registration_request_optional_ie_mutation,
)

_KNOWN_5GMM_MESSAGE_TYPES = {
    0x41: "Registration request",
    0x56: "Authentication request",
    0x57: "Authentication response",
    0x5C: "Identity response",
    0x5D: "Security mode command",
}

_KNOWN_SECURITY_HEADERS = {
    0x00: "Plain NAS message, not security protected (0)",
    0x01: "Integrity protected (1)",
    0x02: "Integrity protected and ciphered (2)",
    0x03: "Integrity protected with new 5GS security context (3)",
    0x04: "Integrity protected and ciphered with new 5GS security context (4)",
}


@dataclass(frozen=True)
class ProxyExecutionConfig:
    target_direction: str = "gNB->AMF"
    target_message_type: str = "InitialUEMessage"
    match_once: bool = True


@dataclass
class ProxyMutationEvent:
    message_index: int
    direction: str
    message_type: str
    before_raw_pdu_hex: str
    after_raw_pdu_hex: str
    notes: list[str] = field(default_factory=list)


@dataclass
class ProxySimulationResult:
    trace: ProcedureTrace
    events: list[ProxyMutationEvent] = field(default_factory=list)


def _parse_byte_value(raw_value: str | None, name: str, *, max_value: int = 0xFF) -> int:
    if raw_value is None or raw_value == "":
        raise ProxyMutationError(f"{name} requires a value such as 0x5c.")
    try:
        parsed = int(raw_value, 0)
    except ValueError as exc:
        raise ProxyMutationError(f"{name} value '{raw_value}' is not a valid integer.") from exc
    if parsed < 0 or parsed > max_value:
        raise ProxyMutationError(
            f"{name} value '{raw_value}' is outside the allowed range 0..{max_value}."
        )
    return parsed


def _apply_message_annotations(
    nas: dict[str, object],
    spec: InitialNasMutationSpec,
    result: InitialNasMutationResult,
) -> None:
    nas["raw_pdu_hex"] = result.after_raw_pdu_hex

    if spec.mutation == "message-type":
        new_value = _parse_byte_value(spec.value, "message-type")
        nas["message_type_code"] = f"0x{new_value:02x}"
        nas["message_type"] = _KNOWN_5GMM_MESSAGE_TYPES.get(
            new_value,
            f"Unknown / mutated (0x{new_value:02x})",
        )

    elif spec.mutation == "registration-type-and-ngksi":
        new_value = _parse_byte_value(spec.value, "registration-type-and-ngksi")
        nas["registration_type_and_ngksi"] = f"0x{new_value:02x}"

    elif spec.mutation == "security-header":
        new_value = _parse_byte_value(spec.value, "security-header", max_value=0x0F)
        nas["security_header_type_code"] = str(new_value)
        nas["security_header_type"] = _KNOWN_SECURITY_HEADERS.get(
            new_value,
            f"Mutated / unknown security header ({new_value})",
        )
    elif spec.mutation == "mobile-identity-invalid-bcd-tail":
        new_value = _parse_byte_value(spec.value, "mobile-identity-invalid-bcd-tail")
        nas["mobile_identity_tail_octet"] = f"0x{new_value:02x}"


def simulate_initial_nas_proxy(
    trace: ProcedureTrace,
    spec: InitialNasMutationSpec,
    config: ProxyExecutionConfig | None = None,
) -> ProxySimulationResult:
    cfg = config or ProxyExecutionConfig()
    cloned = ProcedureTrace.from_dict(trace.to_dict())
    events: list[ProxyMutationEvent] = []

    for index, message in enumerate(cloned.messages, start=1):
        if message.direction != cfg.target_direction:
            continue
        if message.message_type != cfg.target_message_type:
            continue
        if message.nas is None:
            raise ProxyMutationError(
                f"Target message {index} does not carry NAS, cannot run proxy mutation."
            )

        raw_pdu_hex = message.nas.get("raw_pdu_hex")
        if not isinstance(raw_pdu_hex, str) or not raw_pdu_hex:
            raise ProxyMutationError(
                f"Target message {index} does not contain raw_pdu_hex, cannot run proxy mutation."
            )

        mutation_result = apply_initial_registration_mutation(raw_pdu_hex, spec)
        _apply_message_annotations(message.nas, spec, mutation_result)
        message.metadata["proxy_mutation_note"] = (
            f"proxy simulated {spec.mutation} on {cfg.target_message_type}"
        )

        events.append(
            ProxyMutationEvent(
                message_index=index,
                direction=message.direction,
                message_type=message.message_type,
                before_raw_pdu_hex=mutation_result.before_raw_pdu_hex,
                after_raw_pdu_hex=mutation_result.after_raw_pdu_hex,
                notes=list(mutation_result.notes),
            )
        )

        if cfg.match_once:
            break

    if not events:
        raise ProxyMutationError(
            f"No {cfg.target_direction} {cfg.target_message_type} with NAS raw_pdu_hex was found."
        )

    cloned.mutation_history.append(
        {
            "mutation": "proxy-simulated-initial-nas",
            "target_direction": cfg.target_direction,
            "target_message_type": cfg.target_message_type,
            "policy": spec.mutation,
            "value": spec.value,
            "matches": len(events),
        }
    )
    return ProxySimulationResult(trace=cloned, events=events)


def simulate_nested_registration_request_optional_ie_mutation(
    trace: ProcedureTrace,
    *,
    message_index: int,
    hit_index: int,
    field_name: str,
    action: str,
    length_value: str | None = None,
) -> ProxySimulationResult:
    cloned = ProcedureTrace.from_dict(trace.to_dict())
    try:
        message = cloned.messages[message_index - 1]
    except IndexError as exc:
        raise ProxyMutationError(
            f"Message index {message_index} is outside the trace length {len(cloned.messages)}."
        ) from exc

    if message.nas is None:
        raise ProxyMutationError(
            f"Target message {message_index} does not carry NAS, cannot mutate nested Registration Request."
        )

    outer_raw_pdu_hex = message.nas.get("raw_pdu_hex")
    if not isinstance(outer_raw_pdu_hex, str) or not outer_raw_pdu_hex:
        raise ProxyMutationError(
            f"Target message {message_index} does not contain raw_pdu_hex, cannot mutate nested Registration Request."
        )

    scan = scan_for_nested_registration_requests(outer_raw_pdu_hex)
    if hit_index < 1 or hit_index > len(scan.hits):
        raise ProxyMutationError(
            f"Nested hit index {hit_index} is outside the detected count {len(scan.hits)}."
        )

    nested_before = scan.hits[hit_index - 1].raw_pdu_hex
    nested_result = apply_registration_request_optional_ie_mutation(
        nested_before,
        field_name=field_name,
        action=action,
        length_value=length_value,
    )
    final_preview = preview_nested_registration_request_mutation(
        outer_raw_pdu_hex,
        hit_index=hit_index,
        after_nested_raw_pdu_hex=nested_result.after_raw_pdu_hex,
    )

    message.nas["raw_pdu_hex"] = final_preview.after_outer_raw_pdu_hex
    message.metadata["proxy_mutation_note"] = (
        f"proxy simulated nested Registration Request optional IE {field_name} {action}"
    )
    if message.nas.get("message_type"):
        message.nas["message_type"] = f"{message.nas['message_type']} [nested RR mutated]"

    event = ProxyMutationEvent(
        message_index=message_index,
        direction=message.direction,
        message_type=message.message_type,
        before_raw_pdu_hex=final_preview.before_outer_raw_pdu_hex,
        after_raw_pdu_hex=final_preview.after_outer_raw_pdu_hex,
        notes=[
            f"nested hit {hit_index} at offset {final_preview.start_offset}",
            *nested_result.notes,
        ],
    )

    cloned.mutation_history.append(
        {
            "mutation": "proxy-simulated-nested-registration-request-optional-ie",
            "target_message_index": message_index,
            "nested_hit_index": hit_index,
            "field_name": field_name,
            "action": action,
            "length_value": length_value,
        }
    )
    return ProxySimulationResult(trace=cloned, events=[event])
