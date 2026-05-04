from __future__ import annotations

from dataclasses import dataclass, field

from .nas_schema import NasFieldSchema, get_nas_message_schema
from .nas_tlv import ParsedTlv, find_tlv_by_tag, format_octets as format_tlv_octets, parse_tlv_sequence


@dataclass(frozen=True)
class LocatedField:
    name: str
    kind: str
    present: bool
    start_offset: int | None = None
    length: int | None = None
    value_hex: str = ""
    details: str = ""


@dataclass(frozen=True)
class LocatedTlv:
    tag: str
    start_offset: int
    length_octets: int
    value_offset: int
    value_length: int
    value_hex: str
    mapped_field_name: str | None = None


@dataclass
class RegistrationRequestFieldReport:
    raw_pdu_hex: str
    total_octets: int
    message_name: str = ""
    fields: list[LocatedField] = field(default_factory=list)
    tlvs: list[LocatedTlv] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


_PLAIN_5GMM_MESSAGE_TYPES = {
    0x41: "Registration Request",
    0x57: "Authentication Response",
    0x5C: "Identity Response",
    0x5E: "Security Mode Complete",
}

_UL_NAS_TRANSPORT_MESSAGE_TYPE = 0x67


def _message_field_schema(message_name: str, field_name: str) -> NasFieldSchema:
    return get_nas_message_schema(message_name).get_field(field_name)


def _optional_ie_field_schemas(message_name: str) -> tuple[NasFieldSchema, ...]:
    schema = get_nas_message_schema(message_name)
    return tuple(field for field in schema.fields if field.iei_tag)


def _optional_iei_tag_map(message_name: str) -> dict[int, str]:
    tag_map: dict[int, str] = {}
    for field in _optional_ie_field_schemas(message_name):
        tag_map[int(field.iei_tag, 16)] = field.field_name
    return tag_map


def _parse_raw_pdu_hex(raw_pdu_hex: str) -> list[int]:
    octets = [part.strip().lower() for part in raw_pdu_hex.split(":") if part.strip()]
    if not octets:
        raise ValueError("raw_pdu_hex is empty.")

    parsed: list[int] = []
    for octet in octets:
        if len(octet) != 2:
            raise ValueError(f"Invalid octet '{octet}' in raw_pdu_hex.")
        try:
            parsed.append(int(octet, 16))
        except ValueError as exc:
            raise ValueError(f"Invalid hex octet '{octet}' in raw_pdu_hex.") from exc
    return parsed


def _format_octets(octets: list[int]) -> str:
    return format_tlv_octets(octets)


def _slice_hex(octets: list[int], start: int, length: int) -> str:
    return _format_octets(octets[start : start + length])


def _format_field_value(octets: list[int], *, field_kind: str) -> str:
    if not octets:
        return ""
    if len(octets) == 1 and field_kind in {"enum", "bitfield"}:
        return f"0x{octets[0]:02x}"
    if len(octets) == 2 and field_kind == "length":
        return f"0x{((octets[0] << 8) | octets[1]):04x}"
    return _format_octets(octets)


def _read_length_from_field(octets: list[int], field: LocatedField) -> int:
    if (
        not field.present
        or field.start_offset is None
        or field.length is None
        or field.length <= 0
        or len(octets) < field.start_offset + field.length
    ):
        raise ValueError(f"Could not read a valid length from field '{field.name}'.")
    if field.length == 1:
        return octets[field.start_offset]
    if field.length == 2:
        return (octets[field.start_offset] << 8) | octets[field.start_offset + 1]
    raise ValueError(
        f"Length-bearing field '{field.name}' uses unsupported width {field.length}."
    )


def _locate_field_from_schema(
    octets: list[int],
    field_schema: NasFieldSchema,
    *,
    prior_fields: dict[str, LocatedField],
    warnings: list[str],
) -> LocatedField | None:
    locator = field_schema.locator
    if locator is None:
        return None

    if locator.strategy == "fixed-offset":
        if locator.offset is None or locator.length is None:
            raise ValueError(
                f"Field '{field_schema.field_name}' is missing fixed-offset locator details."
            )
        if len(octets) < locator.offset + locator.length:
            end_offset = locator.offset + locator.length - 1
            return LocatedField(
                name=field_schema.field_name,
                kind=field_schema.kind,
                present=False,
                details=f"raw PDU ended before offsets {locator.offset}-{end_offset}",
            )
        value_octets = octets[locator.offset : locator.offset + locator.length]
        return LocatedField(
            name=field_schema.field_name,
            kind=field_schema.kind,
            present=True,
            start_offset=locator.offset,
            length=locator.length,
            value_hex=_format_field_value(value_octets, field_kind=field_schema.kind),
        )

    if locator.strategy == "length-prefixed-payload":
        if locator.offset is None or not locator.length_from_field:
            raise ValueError(
                f"Field '{field_schema.field_name}' is missing length-prefixed locator details."
            )
        length_field = prior_fields.get(locator.length_from_field)
        if length_field is None:
            return LocatedField(
                name=field_schema.field_name,
                kind=field_schema.kind,
                present=False,
                details=f"length source field '{locator.length_from_field}' was not located first",
            )
        try:
            payload_length = _read_length_from_field(octets, length_field)
        except ValueError as exc:
            return LocatedField(
                name=field_schema.field_name,
                kind=field_schema.kind,
                present=False,
                details=str(exc),
            )

        end_offset = locator.offset + payload_length
        if len(octets) >= end_offset:
            return LocatedField(
                name=field_schema.field_name,
                kind=field_schema.kind,
                present=True,
                start_offset=locator.offset,
                length=payload_length,
                value_hex=_slice_hex(octets, locator.offset, payload_length),
            )

        warnings.append(
            f"{field_schema.field_name} is truncated relative to its declared length"
        )
        available_length = max(0, len(octets) - locator.offset)
        return LocatedField(
            name=field_schema.field_name,
            kind=field_schema.kind,
            present=False,
            start_offset=locator.offset,
            length=available_length,
            value_hex=_slice_hex(octets, locator.offset, available_length) if available_length else "",
            details=(
                f"declared {field_schema.field_name} length is 0x{payload_length:04x}, "
                f"but packet ends at octet {len(octets) - 1}"
            ),
        )

    if locator.strategy == "payload-remainder":
        if locator.offset is None:
            raise ValueError(
                f"Field '{field_schema.field_name}' is missing payload-remainder locator details."
            )
        payload_length = max(0, len(octets) - locator.offset)
        return LocatedField(
            name=field_schema.field_name,
            kind=field_schema.kind,
            present=payload_length > 0,
            start_offset=locator.offset,
            length=payload_length,
            value_hex=_slice_hex(octets, locator.offset, payload_length) if payload_length else "",
            details="all remaining octets after the plain 5GS NAS header",
        )

    raise ValueError(
        f"Unsupported locator strategy '{locator.strategy}' for field '{field_schema.field_name}'."
    )


def _field_end_offset_from_schema(
    octets: list[int],
    field_schema: NasFieldSchema,
    located_fields: dict[str, LocatedField],
) -> int:
    locator = field_schema.locator
    if locator is None:
        raise ValueError(f"Field '{field_schema.field_name}' does not define a locator.")
    if locator.strategy == "fixed-offset":
        if locator.offset is None or locator.length is None:
            raise ValueError(
                f"Field '{field_schema.field_name}' is missing fixed-offset locator details."
            )
        return min(locator.offset + locator.length, len(octets))
    if locator.strategy == "length-prefixed-payload":
        if locator.offset is None or not locator.length_from_field:
            raise ValueError(
                f"Field '{field_schema.field_name}' is missing length-prefixed locator details."
            )
        length_field = located_fields.get(locator.length_from_field)
        if length_field is None:
            raise ValueError(
                f"Length source field '{locator.length_from_field}' for '{field_schema.field_name}' is unavailable."
            )
        payload_length = _read_length_from_field(octets, length_field)
        return min(locator.offset + payload_length, len(octets))
    raise ValueError(
        f"Unsupported locator strategy '{locator.strategy}' for field '{field_schema.field_name}'."
    )


def parse_raw_pdu_hex(raw_pdu_hex: str) -> list[int]:
    return _parse_raw_pdu_hex(raw_pdu_hex)


def format_octets(octets: list[int]) -> str:
    return _format_octets(octets)


def inspect_registration_request_fields(raw_pdu_hex: str) -> RegistrationRequestFieldReport:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    schema = get_nas_message_schema("Registration Request")
    report = RegistrationRequestFieldReport(
        raw_pdu_hex=raw_pdu_hex,
        total_octets=len(octets),
        message_name="Registration Request",
    )

    if len(octets) < 3:
        raise ValueError("Registration Request raw_pdu_hex is too short.")
    if octets[0] != 0x7E:
        raise ValueError(f"Expected EPD 0x7e, found 0x{octets[0]:02x}.")
    if octets[2] != 0x41:
        raise ValueError(f"Expected 5GMM message type 0x41, found 0x{octets[2]:02x}.")

    located_fields: dict[str, LocatedField] = {}
    for field_schema in schema.fields:
        if field_schema.iei_tag:
            continue
        located = _locate_field_from_schema(
            octets,
            field_schema,
            prior_fields=located_fields,
            warnings=report.warnings,
        )
        if located is None:
            continue
        report.fields.append(located)
        located_fields[field_schema.field_name] = located

    mobile_identity_schema = schema.get_field("mobile_identity_value")
    tlv_start_offset = _field_end_offset_from_schema(
        octets,
        mobile_identity_schema,
        located_fields,
    )
    tlv_sequence = parse_tlv_sequence(octets, start_offset=tlv_start_offset)
    report.warnings.extend(tlv_sequence.warnings)
    for tlv in tlv_sequence.tlvs:
        report.tlvs.append(_located_tlv_from_parsed("Registration Request", tlv))

    mapped_tlvs = {tlv.mapped_field_name: tlv for tlv in report.tlvs if tlv.mapped_field_name}
    for field_schema in _optional_ie_field_schemas("Registration Request"):
        tlv = mapped_tlvs.get(field_schema.field_name)
        if tlv is None:
            report.fields.append(
                LocatedField(
                    name=field_schema.field_name,
                    kind=field_schema.kind,
                    present=False,
                    details="not detected in trailing TLV scan",
                )
            )
        else:
            report.fields.append(
                LocatedField(
                    name=field_schema.field_name,
                    kind=field_schema.kind,
                    present=True,
                    start_offset=tlv.start_offset,
                    length=2 + tlv.value_length,
                    value_hex=f"{tlv.tag}:{tlv.value_hex}",
                    details=f"tag {tlv.tag}, length {tlv.value_length}",
                )
            )

    return report


def detect_plain_5gmm_message_name(raw_pdu_hex: str) -> str:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    if len(octets) < 3:
        raise ValueError("raw_pdu_hex is too short to detect a plain 5GS NAS message.")
    if octets[0] != 0x7E:
        raise ValueError(f"Expected EPD 0x7e, found 0x{octets[0]:02x}.")
    message_name = _PLAIN_5GMM_MESSAGE_TYPES.get(octets[2])
    if message_name is None:
        raise ValueError(f"Unsupported plain 5GS NAS message type 0x{octets[2]:02x}.")
    return message_name


def _find_nested_plain_message_start(
    octets: list[int],
    *,
    message_type: int,
) -> int | None:
    if len(octets) >= 3 and octets[0] == 0x7E and octets[1] == 0x00 and octets[2] == message_type:
        return 0

    if len(octets) < 10:
        return None

    for index in range(0, len(octets) - 9):
        if octets[index] != 0x7E:
            continue
        if octets[index + 7] != 0x7E or octets[index + 8] != 0x00:
            continue
        if octets[index + 9] != message_type:
            continue
        return index + 7

    return None


def _pdu_session_tlv_start_offset(
    raw_pdu_hex: str,
    octets: list[int] | None = None,
) -> tuple[int, int]:
    parsed_octets = octets or _parse_raw_pdu_hex(raw_pdu_hex)
    inner_start = _find_nested_plain_message_start(
        parsed_octets,
        message_type=_UL_NAS_TRANSPORT_MESSAGE_TYPE,
    )
    if inner_start is None:
        raise ValueError(
            "Could not locate a plain UL NAS Transport container for the PDU Session Establishment Request baseline."
        )
    if len(parsed_octets) < inner_start + 6:
        raise ValueError("PDU Session Establishment Request baseline is too short for the UL NAS Transport header.")

    payload_container_length = (
        (parsed_octets[inner_start + 4] << 8) | parsed_octets[inner_start + 5]
    )
    tlv_start_offset = inner_start + 6 + payload_container_length
    if tlv_start_offset > len(parsed_octets):
        raise ValueError(
            "PDU Session Establishment Request payload container length points beyond the available packet bytes."
        )
    return inner_start, tlv_start_offset


def _inspect_schema_defined_plain_message(
    raw_pdu_hex: str,
    *,
    message_name: str,
) -> RegistrationRequestFieldReport:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    schema = get_nas_message_schema(message_name)
    report = RegistrationRequestFieldReport(
        raw_pdu_hex=raw_pdu_hex,
        total_octets=len(octets),
        message_name=message_name,
    )

    if len(octets) < 3:
        raise ValueError(f"{message_name} raw_pdu_hex is too short.")
    if octets[0] != 0x7E:
        raise ValueError(f"Expected EPD 0x7e, found 0x{octets[0]:02x}.")
    expected_message_type = int(schema.message_type_code, 16)
    if octets[2] != expected_message_type:
        raise ValueError(
            f"Expected 5GMM message type 0x{expected_message_type:02x}, found 0x{octets[2]:02x}."
        )

    located_fields: dict[str, LocatedField] = {}
    for field_schema in schema.fields:
        if field_schema.iei_tag:
            continue
        located = _locate_field_from_schema(
            octets,
            field_schema,
            prior_fields=located_fields,
            warnings=report.warnings,
        )
        if located is None:
            continue
        report.fields.append(located)
        located_fields[field_schema.field_name] = located
    return report


def _inspect_schema_defined_protected_message(
    raw_pdu_hex: str,
    *,
    message_name: str,
) -> RegistrationRequestFieldReport:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    schema = get_nas_message_schema(message_name)
    report = RegistrationRequestFieldReport(
        raw_pdu_hex=raw_pdu_hex,
        total_octets=len(octets),
        message_name=message_name,
    )

    if len(octets) < 10:
        raise ValueError(f"{message_name} raw_pdu_hex is too short for the protected wrapper.")
    if octets[0] != 0x7E:
        raise ValueError(f"Expected outer EPD 0x7e, found 0x{octets[0]:02x}.")
    if octets[7] != 0x7E:
        raise ValueError(f"Expected inner plain EPD 0x7e at offset 7, found 0x{octets[7]:02x}.")

    expected_message_type = int(schema.message_type_code, 16)
    if octets[9] != expected_message_type:
        raise ValueError(
            f"Expected inner 5GMM message type 0x{expected_message_type:02x}, found 0x{octets[9]:02x}."
        )

    located_fields: dict[str, LocatedField] = {}
    for field_schema in schema.fields:
        if field_schema.iei_tag:
            continue
        located = _locate_field_from_schema(
            octets,
            field_schema,
            prior_fields=located_fields,
            warnings=report.warnings,
        )
        if located is None:
            continue
        report.fields.append(located)
        located_fields[field_schema.field_name] = located
    return report


def _inspect_pdu_session_establishment_request_fields(
    raw_pdu_hex: str,
) -> RegistrationRequestFieldReport:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    report = RegistrationRequestFieldReport(
        raw_pdu_hex=raw_pdu_hex,
        total_octets=len(octets),
        message_name="PDU Session Establishment Request",
    )
    _, tlv_start_offset = _pdu_session_tlv_start_offset(raw_pdu_hex, octets)

    tlv_sequence = parse_tlv_sequence(octets, start_offset=tlv_start_offset)
    report.warnings.extend(tlv_sequence.warnings)
    for tlv in tlv_sequence.tlvs:
        report.tlvs.append(
            _located_tlv_from_parsed("PDU Session Establishment Request", tlv)
        )

    mapped_tlvs = {tlv.mapped_field_name: tlv for tlv in report.tlvs if tlv.mapped_field_name}
    for field_schema in _optional_ie_field_schemas("PDU Session Establishment Request"):
        tlv = mapped_tlvs.get(field_schema.field_name)
        if tlv is None:
            report.fields.append(
                LocatedField(
                    name=field_schema.field_name,
                    kind=field_schema.kind,
                    present=False,
                    details="not detected in trailing TLV scan",
                )
            )
        else:
            report.fields.append(
                LocatedField(
                    name=field_schema.field_name,
                    kind=field_schema.kind,
                    present=True,
                    start_offset=tlv.start_offset,
                    length=2 + tlv.value_length,
                    value_hex=f"{tlv.tag}:{tlv.value_hex}",
                    details=f"tag {tlv.tag}, length {tlv.value_length}",
                )
            )

    return report


def inspect_nas_message_fields(
    raw_pdu_hex: str,
    *,
    message_name: str | None = None,
) -> RegistrationRequestFieldReport:
    resolved_message_name = message_name or detect_plain_5gmm_message_name(raw_pdu_hex)
    if resolved_message_name == "Registration Request":
        return inspect_registration_request_fields(raw_pdu_hex)
    if resolved_message_name == "Identity Response":
        return _inspect_schema_defined_plain_message(
            raw_pdu_hex,
            message_name=resolved_message_name,
        )
    if resolved_message_name == "Authentication Response":
        return _inspect_schema_defined_plain_message(
            raw_pdu_hex,
            message_name=resolved_message_name,
        )
    if resolved_message_name == "Security Mode Complete":
        return _inspect_schema_defined_protected_message(
            raw_pdu_hex,
            message_name=resolved_message_name,
        )
    if resolved_message_name == "PDU Session Establishment Request":
        return _inspect_pdu_session_establishment_request_fields(raw_pdu_hex)
    raise ValueError(
        f"Field inspection is not implemented yet for NAS message '{resolved_message_name}'."
    )


def _located_tlv_from_parsed(message_name: str, tlv: ParsedTlv) -> LocatedTlv:
    return LocatedTlv(
        tag=f"0x{tlv.tag:02x}",
        start_offset=tlv.start_offset,
        length_octets=tlv.length_octets,
        value_offset=tlv.value_offset,
        value_length=tlv.value_length,
        value_hex=format_tlv_octets(tlv.value_octets),
        mapped_field_name=_optional_iei_tag_map(message_name).get(tlv.tag),
    )


def locate_registration_request_field(
    raw_pdu_hex: str,
    field_name: str,
) -> LocatedField:
    report = inspect_registration_request_fields(raw_pdu_hex)
    for field in report.fields:
        if field.name == field_name:
            return field
    raise KeyError(f"Unknown Registration Request field '{field_name}'.")


def locate_registration_request_tlv_by_tag(
    raw_pdu_hex: str,
    tag: int,
) -> LocatedTlv | None:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    start_offset = _registration_request_tlv_start_offset(raw_pdu_hex, octets)
    tlv = find_tlv_by_tag(octets, start_offset=start_offset, tag=tag)
    if tlv is None:
        return None
    return _located_tlv_from_parsed("Registration Request", tlv)


def locate_nas_field(
    raw_pdu_hex: str,
    field_name: str,
    *,
    message_name: str | None = None,
) -> LocatedField:
    report = inspect_nas_message_fields(raw_pdu_hex, message_name=message_name)
    for field in report.fields:
        if field.name == field_name:
            return field
    label = message_name or report.message_name or "unknown NAS message"
    raise KeyError(f"Unknown field '{field_name}' for {label}.")


def locate_optional_nas_ie(
    raw_pdu_hex: str,
    *,
    message_name: str,
    field_name: str,
    tlv_start_offset: int,
) -> LocatedTlv | None:
    field_schema = _message_field_schema(message_name, field_name)
    if not field_schema.iei_tag:
        raise KeyError(
            f"Field '{field_name}' for NAS message '{message_name}' does not define an IEI tag."
        )
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    tlv = find_tlv_by_tag(
        octets,
        start_offset=tlv_start_offset,
        tag=int(field_schema.iei_tag, 16),
    )
    if tlv is None:
        return None
    return _located_tlv_from_parsed(message_name, tlv)


def _optional_ie_start_offset_from_anchor_field(
    raw_pdu_hex: str,
    *,
    message_name: str,
    anchor_field_name: str,
    octets: list[int] | None = None,
) -> int:
    parsed_octets = octets or _parse_raw_pdu_hex(raw_pdu_hex)
    schema = get_nas_message_schema(message_name)
    anchor_schema = schema.get_field(anchor_field_name)
    located_fields: dict[str, LocatedField] = {}
    warnings: list[str] = []
    anchor_field: LocatedField | None = None
    for field_schema in schema.fields:
        if field_schema.iei_tag:
            continue
        located = _locate_field_from_schema(
            parsed_octets,
            field_schema,
            prior_fields=located_fields,
            warnings=warnings,
        )
        if located is None:
            continue
        located_fields[field_schema.field_name] = located
        if field_schema.field_name == anchor_field_name:
            anchor_field = located
            break

    if anchor_field is None:
        raise ValueError(
            f"Could not locate anchor field '{anchor_field_name}' for NAS message '{message_name}'."
        )
    return _field_end_offset_from_schema(
        parsed_octets,
        anchor_schema,
        located_fields,
    )


def _registration_request_tlv_start_offset(
    raw_pdu_hex: str,
    octets: list[int] | None = None,
) -> int:
    return _optional_ie_start_offset_from_anchor_field(
        raw_pdu_hex,
        message_name="Registration Request",
        anchor_field_name="mobile_identity_value",
        octets=octets,
    )


def locate_registration_request_optional_ie(
    raw_pdu_hex: str,
    field_name: str,
) -> LocatedTlv | None:
    return locate_message_optional_ie(
        raw_pdu_hex,
        message_name="Registration Request",
        field_name=field_name,
    )


def locate_message_optional_ie(
    raw_pdu_hex: str,
    *,
    message_name: str,
    field_name: str,
) -> LocatedTlv | None:
    field_schema = _message_field_schema(message_name, field_name)
    locator = field_schema.locator
    if locator is None:
        raise ValueError(
            f"Optional IE location is not implemented yet for field '{field_name}' in NAS message '{message_name}'."
        )

    if locator.strategy == "nested-optional-tlv":
        if not locator.nested_message_name:
            raise ValueError(
                f"Field '{field_name}' for NAS message '{message_name}' is missing nested-message locator metadata."
            )
        from .nas_nested_inspector import scan_for_nested_plain_nas_messages

        scan = scan_for_nested_plain_nas_messages(
            raw_pdu_hex,
            message_name=locator.nested_message_name,
        )
        for hit in scan.hits:
            nested_located = locate_message_optional_ie(
                hit.raw_pdu_hex,
                message_name=locator.nested_message_name,
                field_name=field_name,
            )
            if nested_located is None:
                continue
            return LocatedTlv(
                tag=nested_located.tag,
                start_offset=hit.start_offset + nested_located.start_offset,
                length_octets=nested_located.length_octets,
                value_offset=hit.start_offset + nested_located.value_offset,
                value_length=nested_located.value_length,
                value_hex=nested_located.value_hex,
                mapped_field_name=nested_located.mapped_field_name,
            )
        return None

    if locator.strategy == "nested-5gsm-optional-tlv":
        octets = _parse_raw_pdu_hex(raw_pdu_hex)
        _, start_offset = _pdu_session_tlv_start_offset(raw_pdu_hex, octets)
        return locate_optional_nas_ie(
            raw_pdu_hex,
            message_name=message_name,
            field_name=field_name,
            tlv_start_offset=start_offset,
        )

    if locator.strategy != "optional-tlv-after-field" or not locator.anchor_field:
        raise ValueError(
            f"Optional IE location is not implemented yet for NAS message '{message_name}'."
        )

    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    start_offset = _optional_ie_start_offset_from_anchor_field(
        raw_pdu_hex,
        message_name=message_name,
        anchor_field_name=locator.anchor_field,
        octets=octets,
    )
    return locate_optional_nas_ie(
        raw_pdu_hex,
        message_name=message_name,
        field_name=field_name,
        tlv_start_offset=start_offset,
    )
