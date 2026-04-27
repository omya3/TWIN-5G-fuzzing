from __future__ import annotations

from dataclasses import dataclass, field

from .nas_field_locator import inspect_nas_message_fields
from .nas_schema import get_nas_message_schema


@dataclass(frozen=True)
class NestedRegistrationRequestHit:
    start_offset: int
    raw_pdu_hex: str
    optional_fields_present: tuple[str, ...]


@dataclass(frozen=True)
class NestedRegistrationRequestScan:
    outer_raw_pdu_hex: str
    hits: tuple[NestedRegistrationRequestHit, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class NestedRegistrationRequestMutationPreview:
    hit_index: int
    start_offset: int
    before_outer_raw_pdu_hex: str
    after_outer_raw_pdu_hex: str
    before_nested_raw_pdu_hex: str
    after_nested_raw_pdu_hex: str


def _parse_raw_pdu_hex(raw_pdu_hex: str) -> list[int]:
    octets = [part.strip().lower() for part in raw_pdu_hex.split(":") if part.strip()]
    parsed: list[int] = []
    for octet in octets:
        if len(octet) != 2:
            raise ValueError(f"Invalid octet '{octet}' in raw_pdu_hex.")
        parsed.append(int(octet, 16))
    return parsed


def _format_octets(octets: list[int]) -> str:
    return ":".join(f"{octet:02x}" for octet in octets)


def scan_for_nested_registration_requests(raw_pdu_hex: str) -> NestedRegistrationRequestScan:
    return scan_for_nested_plain_nas_messages(
        raw_pdu_hex,
        message_name="Registration Request",
    )


def scan_for_nested_plain_nas_messages(
    raw_pdu_hex: str,
    *,
    message_name: str,
) -> NestedRegistrationRequestScan:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    hits: list[NestedRegistrationRequestHit] = []
    warnings: list[str] = []
    schema = get_nas_message_schema(message_name)

    try:
        expected_message_type = int(schema.message_type_code, 16)
    except ValueError as exc:
        raise ValueError(
            f"NAS message '{message_name}' does not expose a plain 5GMM message type code."
        ) from exc

    for start in range(0, max(0, len(octets) - 2)):
        if octets[start : start + 3] != [0x7E, 0x00, expected_message_type]:
            continue

        candidate = octets[start:]
        candidate_hex = _format_octets(candidate)
        try:
            report = inspect_nas_message_fields(candidate_hex, message_name=message_name)
        except ValueError:
            continue

        present_optional = tuple(
            field.name
            for field in report.fields
            if field.kind in {"optional_tlv", "tlv_payload"} and field.present
        )
        hits.append(
            NestedRegistrationRequestHit(
                start_offset=start,
                raw_pdu_hex=candidate_hex,
                optional_fields_present=present_optional,
            )
        )
        warnings.extend(report.warnings)

    return NestedRegistrationRequestScan(
        outer_raw_pdu_hex=raw_pdu_hex,
        hits=tuple(hits),
        warnings=tuple(warnings),
    )


def preview_nested_registration_request_mutation(
    outer_raw_pdu_hex: str,
    *,
    hit_index: int,
    after_nested_raw_pdu_hex: str,
) -> NestedRegistrationRequestMutationPreview:
    return preview_nested_plain_nas_message_mutation(
        outer_raw_pdu_hex,
        message_name="Registration Request",
        hit_index=hit_index,
        after_nested_raw_pdu_hex=after_nested_raw_pdu_hex,
    )


def preview_nested_plain_nas_message_mutation(
    outer_raw_pdu_hex: str,
    *,
    message_name: str,
    hit_index: int,
    after_nested_raw_pdu_hex: str,
) -> NestedRegistrationRequestMutationPreview:
    scan = scan_for_nested_plain_nas_messages(
        outer_raw_pdu_hex,
        message_name=message_name,
    )
    if hit_index < 1 or hit_index > len(scan.hits):
        raise ValueError(
            f"hit_index {hit_index} is outside the detected nested {message_name} count {len(scan.hits)}."
        )

    hit = scan.hits[hit_index - 1]
    outer_octets = _parse_raw_pdu_hex(outer_raw_pdu_hex)
    replacement_octets = _parse_raw_pdu_hex(after_nested_raw_pdu_hex)

    start = hit.start_offset
    before_nested_octets = _parse_raw_pdu_hex(hit.raw_pdu_hex)
    end = start + len(before_nested_octets)
    outer_octets[start:end] = replacement_octets

    return NestedRegistrationRequestMutationPreview(
        hit_index=hit_index,
        start_offset=start,
        before_outer_raw_pdu_hex=outer_raw_pdu_hex,
        after_outer_raw_pdu_hex=_format_octets(outer_octets),
        before_nested_raw_pdu_hex=hit.raw_pdu_hex,
        after_nested_raw_pdu_hex=after_nested_raw_pdu_hex,
    )
