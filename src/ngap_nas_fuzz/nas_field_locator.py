from __future__ import annotations

from dataclasses import dataclass, field

from .nas_catalog import get_nas_field_definition, get_optional_iei_tag_map
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
}


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


def parse_raw_pdu_hex(raw_pdu_hex: str) -> list[int]:
    return _parse_raw_pdu_hex(raw_pdu_hex)


def format_octets(octets: list[int]) -> str:
    return _format_octets(octets)


def inspect_registration_request_fields(raw_pdu_hex: str) -> RegistrationRequestFieldReport:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
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

    report.fields.append(
        LocatedField(
            name="security_header",
            kind="enum",
            present=True,
            start_offset=1,
            length=1,
            value_hex=f"0x{octets[1]:02x}",
        )
    )
    report.fields.append(
        LocatedField(
            name="message_type",
            kind="enum",
            present=True,
            start_offset=2,
            length=1,
            value_hex=f"0x{octets[2]:02x}",
        )
    )

    if len(octets) >= 4:
        report.fields.append(
            LocatedField(
                name="registration_type_and_ngksi",
                kind="bitfield",
                present=True,
                start_offset=3,
                length=1,
                value_hex=f"0x{octets[3]:02x}",
            )
        )
    else:
        report.fields.append(
            LocatedField(
                name="registration_type_and_ngksi",
                kind="bitfield",
                present=False,
                details="raw PDU ended before offset 3",
            )
        )

    mobile_identity_length = None
    if len(octets) >= 6:
        mobile_identity_length = (octets[4] << 8) | octets[5]
        report.fields.append(
            LocatedField(
                name="mobile_identity_length",
                kind="length",
                present=True,
                start_offset=4,
                length=2,
                value_hex=f"0x{mobile_identity_length:04x}",
            )
        )
    else:
        report.fields.append(
            LocatedField(
                name="mobile_identity_length",
                kind="length",
                present=False,
                details="raw PDU ended before offsets 4-5",
            )
        )

    mobile_identity_end = 6
    if mobile_identity_length is not None:
        mobile_identity_end = 6 + mobile_identity_length
        if len(octets) >= mobile_identity_end:
            report.fields.append(
                LocatedField(
                    name="mobile_identity_value",
                    kind="identity",
                    present=True,
                    start_offset=6,
                    length=mobile_identity_length,
                    value_hex=_slice_hex(octets, 6, mobile_identity_length),
                )
            )
        else:
            report.fields.append(
                LocatedField(
                    name="mobile_identity_value",
                    kind="identity",
                    present=False,
                    start_offset=6,
                    length=max(0, len(octets) - 6),
                    value_hex=_slice_hex(octets, 6, max(0, len(octets) - 6)) if len(octets) > 6 else "",
                    details=(
                        f"declared mobile identity length is 0x{mobile_identity_length:04x}, "
                        f"but packet ends at octet {len(octets) - 1}"
                    ),
                )
            )
            report.warnings.append("mobile_identity_value is truncated relative to its declared length")

    tlv_sequence = parse_tlv_sequence(octets, start_offset=min(mobile_identity_end, len(octets)))
    report.warnings.extend(tlv_sequence.warnings)
    for tlv in tlv_sequence.tlvs:
        report.tlvs.append(_located_tlv_from_parsed("Registration Request", tlv))

    mapped_tlvs = {tlv.mapped_field_name: tlv for tlv in report.tlvs if tlv.mapped_field_name}
    for field_name, field_kind in (
        ("requested_nssai", "optional_tlv"),
        ("fivegmm_capability", "tlv_payload"),
    ):
        tlv = mapped_tlvs.get(field_name)
        if tlv is None:
            report.fields.append(
                LocatedField(
                    name=field_name,
                    kind=field_kind,
                    present=False,
                    details="not detected in trailing TLV scan",
                )
            )
        else:
            report.fields.append(
                LocatedField(
                    name=field_name,
                    kind=field_kind,
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


def _inspect_simple_plain_message(
    raw_pdu_hex: str,
    *,
    message_name: str,
    expected_message_type: int,
    payload_field_name: str,
    payload_field_kind: str,
) -> RegistrationRequestFieldReport:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    report = RegistrationRequestFieldReport(
        raw_pdu_hex=raw_pdu_hex,
        total_octets=len(octets),
        message_name=message_name,
    )

    if len(octets) < 3:
        raise ValueError(f"{message_name} raw_pdu_hex is too short.")
    if octets[0] != 0x7E:
        raise ValueError(f"Expected EPD 0x7e, found 0x{octets[0]:02x}.")
    if octets[2] != expected_message_type:
        raise ValueError(
            f"Expected 5GMM message type 0x{expected_message_type:02x}, found 0x{octets[2]:02x}."
        )

    report.fields.append(
        LocatedField(
            name="security_header",
            kind="enum",
            present=True,
            start_offset=1,
            length=1,
            value_hex=f"0x{octets[1]:02x}",
        )
    )
    report.fields.append(
        LocatedField(
            name="message_type",
            kind="enum",
            present=True,
            start_offset=2,
            length=1,
            value_hex=f"0x{octets[2]:02x}",
        )
    )

    payload_offset = 3
    payload_length = max(0, len(octets) - payload_offset)
    report.fields.append(
        LocatedField(
            name=payload_field_name,
            kind=payload_field_kind,
            present=payload_length > 0,
            start_offset=payload_offset,
            length=payload_length,
            value_hex=_slice_hex(octets, payload_offset, payload_length) if payload_length else "",
            details="all remaining octets after the plain 5GS NAS header",
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
        return _inspect_simple_plain_message(
            raw_pdu_hex,
            message_name=resolved_message_name,
            expected_message_type=0x5C,
            payload_field_name="identity_payload",
            payload_field_kind="payload",
        )
    if resolved_message_name == "Authentication Response":
        return _inspect_simple_plain_message(
            raw_pdu_hex,
            message_name=resolved_message_name,
            expected_message_type=0x57,
            payload_field_name="authentication_response_parameter",
            payload_field_kind="payload",
        )
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
        mapped_field_name=get_optional_iei_tag_map(message_name).get(tlv.tag),
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
    field_def = get_nas_field_definition(message_name, field_name)
    if not field_def.iei_tag:
        raise KeyError(
            f"Field '{field_name}' for NAS message '{message_name}' does not define an IEI tag."
        )
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    tlv = find_tlv_by_tag(
        octets,
        start_offset=tlv_start_offset,
        tag=int(field_def.iei_tag, 16),
    )
    if tlv is None:
        return None
    return _located_tlv_from_parsed(message_name, tlv)


def _registration_request_tlv_start_offset(
    raw_pdu_hex: str,
    octets: list[int] | None = None,
) -> int:
    parsed_octets = octets or _parse_raw_pdu_hex(raw_pdu_hex)
    mobile_identity_length_field = locate_registration_request_field(raw_pdu_hex, "mobile_identity_length")
    if (
        not mobile_identity_length_field.present
        or mobile_identity_length_field.start_offset is None
        or mobile_identity_length_field.length != 2
    ):
        raise ValueError("Could not locate mobile_identity_length to derive the trailing TLV start offset.")
    mobile_identity_length = (parsed_octets[4] << 8) | parsed_octets[5]
    return min(6 + mobile_identity_length, len(parsed_octets))


def locate_registration_request_optional_ie(
    raw_pdu_hex: str,
    field_name: str,
) -> LocatedTlv | None:
    octets = _parse_raw_pdu_hex(raw_pdu_hex)
    start_offset = _registration_request_tlv_start_offset(raw_pdu_hex, octets)
    return locate_optional_nas_ie(
        raw_pdu_hex,
        message_name="Registration Request",
        field_name=field_name,
        tlv_start_offset=start_offset,
    )
