from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .nas_field_locator import (
    format_octets,
    locate_nas_field,
    locate_registration_request_optional_ie,
    locate_registration_request_tlv_by_tag,
    parse_raw_pdu_hex,
)
from .nas_schema import (
    NasFieldSchema,
    NasMutationPlan,
    build_nested_optional_ie_mutation_plan,
    build_plain_field_mutation_plan,
    get_nas_message_schema,
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


@dataclass(frozen=True)
class _PlainFieldMutationRule:
    field_name: str
    action: str
    env_name: str
    note_builder: Callable[[int, int], str]
    max_value: int = 0xFF
    fixed_value: int | None = None


def _note_patched_message_type(old_value: int, new_value: int) -> str:
    return f"patched message type 0x{old_value:02x} -> 0x{new_value:02x}"


def _note_patched_registration_type(old_value: int, new_value: int) -> str:
    return f"patched registration type / ngKSI 0x{old_value:02x} -> 0x{new_value:02x}"


def _note_patched_security_header(old_value: int, new_value: int) -> str:
    return f"patched security header type 0x{old_value:02x} -> 0x{new_value:02x}"


def _note_corrupted_mobile_identity_length(old_value: int, new_value: int) -> str:
    return f"corrupted mobile-identity length 0x{old_value:04x} -> 0x{new_value:04x}"


def _note_toggled_mobile_identity_type_bits(old_value: int, new_value: int) -> str:
    return (
        f"toggled mobile identity type bits inconsistently 0x{old_value:02x} -> 0x{new_value:02x}"
    )


_INITIAL_REGISTRATION_FIELD_MUTATIONS: dict[str, _PlainFieldMutationRule] = {
    "message-type": _PlainFieldMutationRule(
        field_name="message_type",
        action="replace-byte",
        env_name="message-type",
        note_builder=_note_patched_message_type,
    ),
    "registration-type-and-ngksi": _PlainFieldMutationRule(
        field_name="registration_type_and_ngksi",
        action="replace-byte",
        env_name="registration-type-and-ngksi",
        note_builder=_note_patched_registration_type,
    ),
    "security-header": _PlainFieldMutationRule(
        field_name="security_header",
        action="replace-byte",
        env_name="security-header",
        max_value=0x0F,
        note_builder=_note_patched_security_header,
    ),
    "mobile-identity-length-zero": _PlainFieldMutationRule(
        field_name="mobile_identity_length",
        action="replace-word-be",
        env_name="mobile-identity-length-zero",
        fixed_value=0x0000,
        note_builder=_note_corrupted_mobile_identity_length,
    ),
    "mobile-identity-toggle-type-bits": _PlainFieldMutationRule(
        field_name="mobile_identity_value",
        action="replace-first-byte",
        env_name="mobile-identity-toggle-type-bits",
        fixed_value=0x06,
        note_builder=_note_toggled_mobile_identity_type_bits,
    ),
}


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


def _resolve_plain_field_mutation_value(
    rule: _PlainFieldMutationRule,
    spec: InitialNasMutationSpec,
) -> int:
    if rule.fixed_value is not None:
        return rule.fixed_value
    return _parse_byte_value(spec.value, rule.env_name, max_value=rule.max_value)


def _format_plain_field_plan_value(action: str, value: int) -> str:
    if action == "replace-word-be":
        return f"0x{value:04x}"
    return f"0x{value:02x}"


def _build_initial_registration_mutation_plan(
    spec: InitialNasMutationSpec,
) -> NasMutationPlan | None:
    rule = _INITIAL_REGISTRATION_FIELD_MUTATIONS.get(spec.mutation)
    if rule is None:
        return None

    value = _resolve_plain_field_mutation_value(rule, spec)
    return build_plain_field_mutation_plan(
        message_name="Registration Request",
        field_name=rule.field_name,
        action=rule.action,
        value=_format_plain_field_plan_value(rule.action, value),
    )


def _message_field_schema_for_plan(plan: NasMutationPlan) -> NasFieldSchema:
    try:
        schema = get_nas_message_schema(plan.selector.message_name)
    except KeyError as exc:
        raise ProxyMutationError(str(exc)) from exc

    try:
        return schema.get_field(plan.field_name)
    except KeyError as exc:
        raise ProxyMutationError(str(exc)) from exc


def _plain_field_schema_for_plan(plan: NasMutationPlan) -> NasFieldSchema:
    field_schema = _message_field_schema_for_plan(plan)
    if field_schema.locator is None:
        raise ProxyMutationError(
            f"Field '{plan.field_name}' for NAS message '{plan.selector.message_name}' does not define a locator."
        )
    if field_schema.iei_tag:
        raise ProxyMutationError(
            f"Field '{plan.field_name}' for NAS message '{plan.selector.message_name}' is modeled as an optional IE and must use an optional-IE mutation path."
        )
    return field_schema


def _note_builder_for_plain_plan(
    plan: NasMutationPlan,
) -> Callable[[int, int], str] | None:
    if plan.selector.message_name != "Registration Request":
        return None
    for rule in _INITIAL_REGISTRATION_FIELD_MUTATIONS.values():
        if rule.field_name == plan.field_name and rule.action == plan.action:
            return rule.note_builder
    return None


def _parse_plain_field_plan_value(plan: NasMutationPlan) -> int:
    if plan.action in {"replace-byte", "replace-first-byte"}:
        max_value = 0x0F if plan.field_name == "security_header" else 0xFF
        return _parse_byte_value(
            plan.value,
            f"{plan.field_name} {plan.action}",
            max_value=max_value,
        )
    if plan.action == "replace-word-be":
        return _parse_byte_value(
            plan.value,
            f"{plan.field_name} {plan.action}",
            max_value=0xFFFF,
        )
    if plan.action == "truncate-payload":
        raise ProxyMutationError(
            f"{plan.action} does not accept a numeric value for field '{plan.field_name}'."
        )
    raise ProxyMutationError(f"Unsupported plain field mutation action '{plan.action}'.")


def _apply_plain_field_mutation_plan(
    octets: list[int],
    *,
    raw_pdu_hex: str,
    plan: NasMutationPlan,
    result: InitialNasMutationResult,
) -> None:
    _plain_field_schema_for_plan(plan)
    field = locate_nas_field(
        raw_pdu_hex,
        plan.field_name,
        message_name=plan.selector.message_name,
    )
    if not field.present or field.start_offset is None:
        raise ProxyMutationError(
            f"{plan.field_name} is not present in the {plan.selector.message_name}."
        )

    if plan.action == "replace-byte":
        new_value = _parse_plain_field_plan_value(plan)
        if field.length != 1:
            raise ProxyMutationError(
                f"{plan.field_name} is not present as a 1-byte field in the {plan.selector.message_name}."
            )
        old_value = patch_byte(octets, field.start_offset, new_value)
    elif plan.action == "replace-word-be":
        new_value = _parse_plain_field_plan_value(plan)
        if field.length != 2:
            raise ProxyMutationError(
                f"{plan.field_name} is not present as a 2-byte field in the {plan.selector.message_name}."
            )
        old_value = patch_word_be(octets, field.start_offset, new_value)
    elif plan.action == "replace-first-byte":
        new_value = _parse_plain_field_plan_value(plan)
        if field.length is None or field.length < 1:
            raise ProxyMutationError(
                f"{plan.field_name} is not present with enough bytes to patch in the {plan.selector.message_name}."
            )
        old_value = patch_byte(octets, field.start_offset, new_value)
    elif plan.action == "truncate-payload":
        if field.length is None or field.length < 1:
            raise ProxyMutationError(
                f"{plan.field_name} is not present with enough bytes to truncate in the {plan.selector.message_name}."
            )
        removed = remove_span(
            octets,
            field.start_offset + field.length - 1,
            1,
        )
        result.notes.append(
            f"truncated field {plan.field_name} by removing {format_octets(removed)} from offset {field.start_offset + field.length - 1}"
        )
        return
    else:
        raise ProxyMutationError(
            f"Unsupported plain field mutation action '{plan.action}'."
        )

    note_builder = _note_builder_for_plain_plan(plan)
    if note_builder is not None:
        result.notes.append(note_builder(old_value, new_value))
        return

    if plan.action == "replace-word-be":
        result.notes.append(
            f"patched field {plan.field_name} 0x{old_value:04x} -> 0x{new_value:04x}"
        )
    else:
        result.notes.append(
            f"patched field {plan.field_name} 0x{old_value:02x} -> 0x{new_value:02x}"
        )


def build_nested_registration_request_optional_ie_plan(
    *,
    field_name: str,
    action: str,
    value: str | None = None,
) -> NasMutationPlan:
    return build_nested_optional_ie_mutation_plan(
        field_name=field_name,
        action=action,
        value=value,
    )


def _action_supported_by_schema(field_schema: NasFieldSchema, action: str) -> bool:
    normalized_action = action.lower()
    supported = {kind.lower() for kind in field_schema.action_kinds}
    if normalized_action in supported:
        return True

    aliases = {
        "duplicate": "duplicate-ie",
    }
    alias = aliases.get(normalized_action)
    if alias is not None and alias in supported:
        return True
    return False


def _field_schema_for_plan(plan: NasMutationPlan) -> NasFieldSchema:
    field_schema = _message_field_schema_for_plan(plan)
    if not field_schema.iei_tag:
        raise ProxyMutationError(
            f"Field '{plan.field_name}' for NAS message '{plan.selector.message_name}' is not modeled as an optional IE."
        )
    if not _action_supported_by_schema(field_schema, plan.action):
        raise ProxyMutationError(
            f"Action '{plan.action}' is not modeled for field '{plan.field_name}' in NAS message '{plan.selector.message_name}'."
        )
    return field_schema


def _apply_nested_registration_request_optional_ie_plan(
    octets: list[int],
    *,
    located: object,
    field_name: str,
    action: str,
    value: str | None,
    result: InitialNasMutationResult,
) -> None:
    if action == "omit":
        removed = remove_span(octets, located.start_offset, tlv_total_length(located.length_octets, located.value_length))
        result.notes.append(
            f"removed optional IE {field_name} ({located.tag}) total_length={len(removed)} at offset {located.start_offset}"
        )
        return

    if action == "duplicate":
        duplicated = duplicate_span(
            octets,
            located.start_offset,
            tlv_total_length(located.length_octets, located.value_length),
        )
        result.notes.append(
            f"duplicated optional IE {field_name} ({located.tag}) total_length={len(duplicated)} at offset {located.start_offset}"
        )
        return

    if action == "bad-length":
        new_length = _parse_byte_value(value, f"{field_name} bad-length")
        old_length = patch_byte(octets, located.start_offset + 1, new_length)
        result.notes.append(
            f"patched optional IE {field_name} ({located.tag}) length 0x{old_length:02x} -> 0x{new_length:02x}"
        )
        return

    if action == "unsupported-sst-sd":
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
        return

    if action == "duplicate-payload-entries":
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
        return

    if action == "set-reserved-bits":
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
        return

    if action == "truncate-payload":
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
        return

    raise ProxyMutationError(f"Unsupported optional IE mutation action '{action}'.")


def apply_nas_mutation_plan(
    raw_pdu_hex: str,
    plan: NasMutationPlan,
) -> InitialNasMutationResult:
    try:
        octets = parse_raw_pdu_hex(raw_pdu_hex)
    except ValueError as exc:
        raise ProxyMutationError(str(exc)) from exc

    result = InitialNasMutationResult(
        before_raw_pdu_hex=raw_pdu_hex,
        after_raw_pdu_hex=raw_pdu_hex,
    )

    try:
        if plan.selector.container_type == "plain-nas-message":
            _apply_plain_field_mutation_plan(
                octets,
                raw_pdu_hex=raw_pdu_hex,
                plan=plan,
                result=result,
            )
        elif plan.selector.container_type == "nested-registration-request":
            if plan.selector.message_name != "Registration Request":
                raise ProxyMutationError(
                    "Nested NAS mutation execution is only implemented for "
                    f"Registration Request, not '{plan.selector.message_name}'."
                )

            _field_schema_for_plan(plan)

            located = locate_registration_request_optional_ie(raw_pdu_hex, plan.field_name)
            if located is None:
                raise ProxyMutationError(
                    f"Optional IE '{plan.field_name}' is not present in this Registration Request."
                )

            _apply_nested_registration_request_optional_ie_plan(
                octets,
                located=located,
                field_name=plan.field_name,
                action=plan.action,
                value=plan.value,
                result=result,
            )
        else:
            raise ProxyMutationError(
                f"Container type '{plan.selector.container_type}' is not supported yet by the proxy mutation executor."
            )
    except NasPatchTemplateError as exc:
        raise ProxyMutationError(str(exc)) from exc

    result.after_raw_pdu_hex = format_octets(octets)
    return result


def apply_registration_request_optional_ie_mutation(
    raw_pdu_hex: str,
    *,
    field_name: str,
    action: str,
    length_value: str | None = None,
) -> InitialNasMutationResult:
    plan = build_nested_registration_request_optional_ie_plan(
        field_name=field_name,
        action=action,
        value=length_value,
    )
    return apply_nas_mutation_plan(raw_pdu_hex, plan)


def apply_initial_registration_mutation(
    raw_pdu_hex: str, spec: InitialNasMutationSpec
) -> InitialNasMutationResult:
    plan = _build_initial_registration_mutation_plan(spec)
    if plan is not None:
        return apply_nas_mutation_plan(raw_pdu_hex, plan)

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
        if spec.mutation == "mobile-identity-invalid-bcd-tail":
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
        else:
            raise ProxyMutationError(f"Unsupported initial NAS mutation '{spec.mutation}'.")
    except ValueError as exc:
        raise ProxyMutationError(str(exc)) from exc
    except NasPatchTemplateError as exc:
        raise ProxyMutationError(str(exc)) from exc

    result.after_raw_pdu_hex = format_octets(octets)
    return result
