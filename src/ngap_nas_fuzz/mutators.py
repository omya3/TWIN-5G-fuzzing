from __future__ import annotations

import copy
from typing import Any

from .models import ProcedureTrace


class MutationError(ValueError):
    """Raised when a requested mutation cannot be applied."""


def _get_message(trace: ProcedureTrace, index_1_based: int):
    if index_1_based < 1 or index_1_based > len(trace.messages):
        raise MutationError(
            f"Message index {index_1_based} is outside the trace length {len(trace.messages)}."
        )
    return trace.messages[index_1_based - 1]


def _renumber_messages(trace: ProcedureTrace) -> None:
    for offset, msg in enumerate(trace.messages, start=1):
        msg.id = offset


def _record(trace: ProcedureTrace, mutation: str, details: dict[str, Any]) -> None:
    trace.mutation_history.append({"mutation": mutation, **details})


def slice_trace(
    trace: ProcedureTrace,
    start_index_1_based: int,
    end_index_1_based: int,
) -> ProcedureTrace:
    if start_index_1_based < 1 or end_index_1_based > len(trace.messages):
        raise MutationError(
            f"Slice range [{start_index_1_based}, {end_index_1_based}] is outside the trace length {len(trace.messages)}."
        )
    if start_index_1_based > end_index_1_based:
        raise MutationError("Slice start index must be <= end index.")

    cloned = copy.deepcopy(trace)
    cloned.messages = cloned.messages[start_index_1_based - 1 : end_index_1_based]
    _renumber_messages(cloned)
    _record(
        cloned,
        "slice-trace",
        {"start_index": start_index_1_based, "end_index": end_index_1_based},
    )
    return cloned


def duplicate_message(trace: ProcedureTrace, index_1_based: int) -> ProcedureTrace:
    cloned = copy.deepcopy(trace)
    message = copy.deepcopy(_get_message(cloned, index_1_based))
    message.metadata["mutation_note"] = "duplicated message"
    cloned.messages.insert(index_1_based, message)
    _renumber_messages(cloned)
    _record(cloned, "duplicate-message", {"index": index_1_based})
    return cloned


def drop_message(trace: ProcedureTrace, index_1_based: int) -> ProcedureTrace:
    cloned = copy.deepcopy(trace)
    _get_message(cloned, index_1_based)
    del cloned.messages[index_1_based - 1]
    _renumber_messages(cloned)
    _record(cloned, "drop-message", {"index": index_1_based})
    return cloned


def reorder_messages(
    trace: ProcedureTrace, first_index_1_based: int, second_index_1_based: int
) -> ProcedureTrace:
    cloned = copy.deepcopy(trace)
    _get_message(cloned, first_index_1_based)
    _get_message(cloned, second_index_1_based)
    a = first_index_1_based - 1
    b = second_index_1_based - 1
    cloned.messages[a], cloned.messages[b] = cloned.messages[b], cloned.messages[a]
    _renumber_messages(cloned)
    _record(
        cloned,
        "reorder-messages",
        {"first_index": first_index_1_based, "second_index": second_index_1_based},
    )
    return cloned


def stale_id(
    trace: ProcedureTrace,
    index_1_based: int,
    field_name: str,
    source_index_1_based: int,
) -> ProcedureTrace:
    cloned = copy.deepcopy(trace)
    target = _get_message(cloned, index_1_based)
    source = _get_message(cloned, source_index_1_based)
    if field_name not in source.ngap_fields:
        raise MutationError(f"Source message does not contain NGAP field '{field_name}'.")
    target.ngap_fields[field_name] = source.ngap_fields[field_name]
    target.metadata["mutation_note"] = f"stale {field_name} copied from message {source_index_1_based}"
    _record(
        cloned,
        "stale-id",
        {
            "index": index_1_based,
            "field_name": field_name,
            "source_index": source_index_1_based,
        },
    )
    return cloned


def set_ngap_field(
    trace: ProcedureTrace,
    index_1_based: int,
    field_name: str,
    new_value: str,
) -> ProcedureTrace:
    cloned = copy.deepcopy(trace)
    target = _get_message(cloned, index_1_based)
    target.ngap_fields[field_name] = new_value
    target.metadata["mutation_note"] = f"set {field_name} to {new_value}"
    _record(
        cloned,
        "set-ngap-field",
        {"index": index_1_based, "field_name": field_name, "new_value": new_value},
    )
    return cloned


def patch_plain_nas_message_type(
    trace: ProcedureTrace,
    index_1_based: int,
    new_message_type_code: str,
    new_message_type_label: str | None = None,
) -> ProcedureTrace:
    cloned = copy.deepcopy(trace)
    message = _get_message(cloned, index_1_based)
    if message.nas is None:
        raise MutationError("Target message does not carry NAS payload.")

    raw_hex = message.nas.get("raw_pdu_hex")
    if not raw_hex:
        raise MutationError("Target NAS payload does not contain raw_pdu_hex.")

    security_header_code = str(message.nas.get("security_header_type_code", ""))
    if security_header_code != "0":
        raise MutationError(
            "Raw NAS message-type patching is currently supported only for plain NAS messages (security header type code 0)."
        )

    octets = raw_hex.split(":")
    if len(octets) < 3:
        raise MutationError("raw_pdu_hex is too short to patch a NAS message type.")

    normalized = new_message_type_code.lower().strip()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if len(normalized) != 2:
        raise MutationError("new_message_type_code must be a single byte like 0x5c or 5c.")

    octets[2] = normalized
    message.nas["raw_pdu_hex"] = ":".join(octets)
    message.nas["message_type_code"] = f"0x{normalized}"
    if new_message_type_label is not None:
        message.nas["message_type"] = new_message_type_label
    message.metadata["mutation_note"] = f"patched plain NAS message type to 0x{normalized}"
    _record(
        cloned,
        "patch-plain-nas-message-type",
        {
            "index": index_1_based,
            "new_message_type_code": f"0x{normalized}",
            "new_message_type_label": new_message_type_label,
        },
    )
    return cloned


def nas_message_type(
    trace: ProcedureTrace, index_1_based: int, new_message_type: str
) -> ProcedureTrace:
    cloned = copy.deepcopy(trace)
    message = _get_message(cloned, index_1_based)
    if message.nas is None:
        raise MutationError("Target message does not carry NAS payload.")
    message.nas["message_type"] = new_message_type
    message.metadata["mutation_note"] = "mutated NAS message type"
    _record(
        cloned,
        "nas-message-type",
        {"index": index_1_based, "new_message_type": new_message_type},
    )
    return cloned


def nas_security_header(
    trace: ProcedureTrace, index_1_based: int, new_security_header_type: str
) -> ProcedureTrace:
    cloned = copy.deepcopy(trace)
    message = _get_message(cloned, index_1_based)
    if message.nas is None:
        raise MutationError("Target message does not carry NAS payload.")
    message.nas["security_header_type"] = new_security_header_type
    message.metadata["mutation_note"] = "mutated NAS security header type"
    _record(
        cloned,
        "nas-security-header",
        {"index": index_1_based, "new_security_header_type": new_security_header_type},
    )
    return cloned


def toggle_optional_ie(
    trace: ProcedureTrace, index_1_based: int, ie_name: str
) -> ProcedureTrace:
    cloned = copy.deepcopy(trace)
    message = _get_message(cloned, index_1_based)
    if message.nas is None:
        raise MutationError("Target message does not carry NAS payload.")
    fields = message.nas.setdefault("fields", {})
    optional_ies = list(fields.get("optional_ies", []))
    if ie_name in optional_ies:
        optional_ies.remove(ie_name)
        note = f"removed optional IE '{ie_name}'"
    else:
        optional_ies.append(ie_name)
        note = f"added optional IE '{ie_name}'"
    fields["optional_ies"] = optional_ies
    message.metadata["mutation_note"] = note
    _record(cloned, "toggle-optional-ie", {"index": index_1_based, "ie_name": ie_name})
    return cloned
