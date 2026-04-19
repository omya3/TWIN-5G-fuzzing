from __future__ import annotations

from dataclasses import dataclass, field

from .nas_field_locator import (
    format_octets,
    locate_nas_field,
    locate_registration_request_optional_ie,
    locate_registration_request_tlv_by_tag,
    parse_raw_pdu_hex,
)
from .nas_patch_templates import (
    NasPatchTemplateError,
    duplicate_span,
    patch_byte,
    patch_word_be,
    remove_span,
    replace_span,
    tlv_total_length,
)


class ProxyMutationError(ValueError):
    """Raised when a proxy-side mutation cannot be applied safely."""


@dataclass(frozen=True)
class InitialNasMutationSpec:
    mutation: str
    value: str | None = None


@dataclass
class InitialNasMutationResult:
    before_raw_pdu_hex: str
    after_raw_pdu_hex: str
    notes: list[str] = field(default_factory=list)

def _parse_byte_value(raw_value: str | None, env_name: str, max_value: int = 0xFF) -> int:
    if raw_value is None or raw_value == "":
        raise ProxyMutationError(f"{env_name} requires a byte value like 0x57.")

    try:
        parsed = int(raw_value, 0)
    except ValueError as exc:
        raise ProxyMutationError(
            f"{env_name} value '{raw_value}' is not a valid integer or hex byte."
        ) from exc

    if parsed < 0 or parsed > max_value:
        raise ProxyMutationError(
            f"{env_name} value '{raw_value}' is outside the allowed range 0..{max_value}."
        )
    return parsed


def apply_registration_request_optional_ie_mutation(
    raw_pdu_hex: str,
    *,
    field_name: str,
    action: str,
    length_value: str | None = None,
) -> InitialNasMutationResult:
    try:
        octets = parse_raw_pdu_hex(raw_pdu_hex)
    except ValueError as exc:
        raise ProxyMutationError(str(exc)) from exc

    located = locate_registration_request_optional_ie(raw_pdu_hex, field_name)
    if located is None:
        raise ProxyMutationError(
            f"Optional IE '{field_name}' is not present in this Registration Request."
        )

    total_length = tlv_total_length(located.length_octets, located.value_length)
    result = InitialNasMutationResult(
        before_raw_pdu_hex=raw_pdu_hex,
        after_raw_pdu_hex=raw_pdu_hex,
    )

    try:
        if action == "omit":
            removed = remove_span(octets, located.start_offset, total_length)
            result.notes.append(
                f"removed optional IE {field_name} ({located.tag}) total_length={len(removed)} at offset {located.start_offset}"
            )
        elif action == "duplicate":
            duplicated = duplicate_span(octets, located.start_offset, total_length)
            result.notes.append(
                f"duplicated optional IE {field_name} ({located.tag}) total_length={len(duplicated)} at offset {located.start_offset}"
            )
        elif action == "bad-length":
            new_length = _parse_byte_value(length_value, f"{field_name} bad-length")
            old_length = patch_byte(octets, located.start_offset + 1, new_length)
            result.notes.append(
                f"patched optional IE {field_name} ({located.tag}) length 0x{old_length:02x} -> 0x{new_length:02x}"
            )
        elif action == "unsupported-sst-sd":
            if field_name != "requested_nssai":
                raise ProxyMutationError(
                    f"Action '{action}' is only supported for requested_nssai."
                )
            if located.value_length < 2:
                raise ProxyMutationError(
                    "requested_nssai payload is too short to patch into an unsupported SST/SD combination."
                )
            old_span = replace_span(octets, located.value_offset, [0xFF, 0xFF])
            result.notes.append(
                "patched requested_nssai payload "
                f"{format_octets(old_span)} -> ff:ff for an unsupported SST/SD combination"
            )
        elif action == "duplicate-payload-entries":
            if field_name != "requested_nssai":
                raise ProxyMutationError(
                    f"Action '{action}' is only supported for requested_nssai."
                )
            if located.length_octets != 1:
                raise ProxyMutationError(
                    "duplicate-payload-entries currently requires a 1-octet IE length field."
                )
            if located.value_length <= 0:
                raise ProxyMutationError(
                    "requested_nssai payload is empty and cannot be duplicated."
                )
            duplicated = duplicate_span(
                octets,
                located.value_offset,
                located.value_length,
                insert_offset=located.value_offset + located.value_length,
            )
            new_length = located.value_length + len(duplicated)
            if new_length > 0xFF:
                raise ProxyMutationError(
                    f"Duplicated requested_nssai payload would exceed 1-octet length: {new_length}."
                )
            old_length = patch_byte(octets, located.start_offset + 1, new_length)
            result.notes.append(
                "duplicated requested_nssai payload entries "
                f"{format_octets(duplicated)} and length 0x{old_length:02x} -> 0x{new_length:02x}"
            )
        elif action == "set-reserved-bits":
            if field_name != "fivegmm_capability":
                raise ProxyMutationError(
                    f"Action '{action}' is only supported for fivegmm_capability."
                )
            if located.value_length < 1:
                raise ProxyMutationError(
                    "fivegmm_capability payload is empty and cannot have reserved bits set."
                )
            old_value = patch_byte(octets, located.value_offset, 0xFF)
            result.notes.append(
                f"patched fivegmm_capability payload byte 0x{old_value:02x} -> 0xff to set reserved bits"
            )
        elif action == "truncate-payload":
            if field_name != "fivegmm_capability":
                raise ProxyMutationError(
                    f"Action '{action}' is only supported for fivegmm_capability."
                )
            if located.length_octets != 1:
                raise ProxyMutationError(
                    "truncate-payload currently requires a 1-octet IE length field."
                )
            if located.value_length < 1:
                raise ProxyMutationError(
                    "fivegmm_capability payload is already empty and cannot be truncated."
                )
            removed = remove_span(
                octets,
                located.value_offset + located.value_length - 1,
                1,
            )
            new_length = located.value_length - len(removed)
            old_length = patch_byte(octets, located.start_offset + 1, new_length)
            result.notes.append(
                "truncated fivegmm_capability payload by removing "
                f"{format_octets(removed)} and length 0x{old_length:02x} -> 0x{new_length:02x}"
            )
        else:
            raise ProxyMutationError(f"Unsupported optional IE mutation action '{action}'.")
    except NasPatchTemplateError as exc:
        raise ProxyMutationError(str(exc)) from exc

    result.after_raw_pdu_hex = format_octets(octets)
    return result


def apply_initial_registration_mutation(
    raw_pdu_hex: str, spec: InitialNasMutationSpec
) -> InitialNasMutationResult:
    try:
        octets = parse_raw_pdu_hex(raw_pdu_hex)
    except ValueError as exc:
        raise ProxyMutationError(str(exc)) from exc
    if len(octets) < 3:
        raise ProxyMutationError("Initial NAS PDU is too short to mutate.")

    result = InitialNasMutationResult(
        before_raw_pdu_hex=raw_pdu_hex,
        after_raw_pdu_hex=raw_pdu_hex,
    )

    if octets[0] != 0x7E:
        raise ProxyMutationError(
            f"Expected first octet 0x7e for 5GS NAS, found 0x{octets[0]:02x}."
        )

    try:
        if spec.mutation == "message-type":
            field = locate_nas_field(raw_pdu_hex, "message_type", message_name="Registration Request")
            new_value = _parse_byte_value(spec.value, "message-type")
            if not field.present or field.start_offset is None:
                raise ProxyMutationError("message_type is not present in the Registration Request.")
            old_value = patch_byte(octets, field.start_offset, new_value)
            result.notes.append(f"patched message type 0x{old_value:02x} -> 0x{new_value:02x}")

        elif spec.mutation == "registration-type-and-ngksi":
            field = locate_nas_field(
                raw_pdu_hex,
                "registration_type_and_ngksi",
                message_name="Registration Request",
            )
            new_value = _parse_byte_value(spec.value, "registration-type-and-ngksi")
            if not field.present or field.start_offset is None:
                raise ProxyMutationError(
                    "registration_type_and_ngksi is not present in the Registration Request."
                )
            old_value = patch_byte(octets, field.start_offset, new_value)
            result.notes.append(
                f"patched registration type / ngKSI 0x{old_value:02x} -> 0x{new_value:02x}"
            )

        elif spec.mutation == "security-header":
            field = locate_nas_field(raw_pdu_hex, "security_header", message_name="Registration Request")
            new_value = _parse_byte_value(spec.value, "security-header", max_value=0x0F)
            if not field.present or field.start_offset is None:
                raise ProxyMutationError("security_header is not present in the Registration Request.")
            old_value = patch_byte(octets, field.start_offset, new_value)
            result.notes.append(
                f"patched security header type 0x{old_value:02x} -> 0x{new_value:02x}"
            )

        elif spec.mutation == "mobile-identity-length-zero":
            field = locate_nas_field(
                raw_pdu_hex,
                "mobile_identity_length",
                message_name="Registration Request",
            )
            if not field.present or field.start_offset is None or field.length != 2:
                raise ProxyMutationError("mobile_identity_length is not present as a 2-byte field.")
            old_value = patch_word_be(octets, field.start_offset, 0x0000)
            result.notes.append(
                f"corrupted mobile-identity length 0x{old_value:04x} -> 0x0000"
            )

        elif spec.mutation == "mobile-identity-invalid-bcd-tail":
            tlv = locate_registration_request_tlv_by_tag(raw_pdu_hex, 0x2E)
            if tlv is None:
                raise ProxyMutationError(
                    "Could not locate the legacy trailing TLV tag 0x2e used by the mobile-identity-invalid-bcd-tail mutation."
                )
            new_value = _parse_byte_value(spec.value, "mobile-identity-invalid-bcd-tail")
            old_value = patch_byte(octets, tlv.start_offset, new_value)
            result.notes.append(
                f"corrupted legacy trailing TLV tag byte 0x{old_value:02x} -> 0x{new_value:02x} at offset {tlv.start_offset}"
            )

        elif spec.mutation == "mobile-identity-toggle-type-bits":
            field = locate_nas_field(
                raw_pdu_hex,
                "mobile_identity_value",
                message_name="Registration Request",
            )
            if not field.present or field.start_offset is None or field.length is None or field.length < 1:
                raise ProxyMutationError(
                    "mobile_identity_value is not present with enough bytes to toggle identity type bits."
                )
            old_value = patch_byte(octets, field.start_offset, 0x06)
            result.notes.append(
                f"toggled mobile identity type bits inconsistently 0x{old_value:02x} -> 0x06"
            )

        else:
            raise ProxyMutationError(f"Unsupported initial NAS mutation '{spec.mutation}'.")
    except ValueError as exc:
        raise ProxyMutationError(str(exc)) from exc
    except NasPatchTemplateError as exc:
        raise ProxyMutationError(str(exc)) from exc

    result.after_raw_pdu_hex = format_octets(octets)
    return result
