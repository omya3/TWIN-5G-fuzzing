from __future__ import annotations

from dataclasses import dataclass, field
import re

from .nas_catalog import NasFieldDefinition, NasMessageProfile, get_nas_message_profiles
from .nas_field_rules import NasFieldGenerationRule, generate_mutation_operators


def _dedupe_preserve_order(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


def _named_operator_action_kinds(operators: tuple[str, ...]) -> tuple[str, ...]:
    action_kinds: list[str] = []
    for operator in operators:
        normalized = operator.lower()
        if normalized == "toggle identity type bits inconsistently":
            action_kinds.append("toggle-identity-type-bits")
        elif normalized == "unsupported sst/sd combination":
            action_kinds.append("unsupported-sst-sd")
        elif normalized == "duplicate nssai entries":
            action_kinds.append("duplicate-payload-entries")
        elif normalized == "reserved bits set":
            action_kinds.append("set-reserved-bits")
        elif normalized == "truncation":
            action_kinds.append("truncate-payload")
        elif normalized == "truncate response parameter":
            action_kinds.append("truncate-payload")
        elif normalized == "oversized length":
            action_kinds.append("set-leading-length-byte")
        elif normalized == "all-zero response value":
            action_kinds.append("zero-payload-value")
        elif normalized == "append extra bytes":
            action_kinds.append("append-bytes")
        elif normalized == "leave inconsistent length metadata":
            action_kinds.append("increment-leading-length-byte")
        else:
            action_kinds.append("named-operator")
    return tuple(action_kinds)


def _rule_action_kinds(field_def: NasFieldDefinition) -> tuple[str, ...]:
    action_kinds: list[str] = []
    for rule in field_def.generation_rules:
        if rule.strategy in {"enum-substitution", "bitfield-substitution"}:
            action_kinds.append("substitute-value")
        elif rule.strategy == "length-boundary":
            action_kinds.append("boundary-length")
        elif rule.strategy == "identity-tail-bcd-substitution":
            action_kinds.append("replace-tail-bcd")
        elif rule.strategy == "optional-ie-omit":
            action_kinds.append("omit")
        elif rule.strategy == "optional-ie-duplicate":
            action_kinds.append("duplicate-ie")
        elif rule.strategy == "optional-ie-bad-length":
            action_kinds.append("bad-length")
        elif rule.strategy == "payload-truncation":
            action_kinds.append("truncate-payload")
        elif rule.strategy == "bitfield-reserved-bits":
            action_kinds.append("set-reserved-bits")
        elif rule.strategy == "named-operators":
            action_kinds.extend(_named_operator_action_kinds(rule.operators))
        else:
            action_kinds.append(rule.strategy)
    return _dedupe_preserve_order(tuple(action_kinds))


def _field_operator_labels(field_def: NasFieldDefinition) -> tuple[str, ...]:
    operators: list[str] = []
    for rule in field_def.generation_rules:
        operators.extend(
            generate_mutation_operators(
                field_name=field_def.name,
                field_kind=field_def.kind,
                baseline_value=field_def.baseline_value,
                rule=rule,
            )
        )
    return _dedupe_preserve_order(tuple(operators))


@dataclass(frozen=True)
class PacketSelector:
    direction: str
    container_type: str
    message_name: str
    occurrence: str = "first"


@dataclass(frozen=True)
class NasMutationPlan:
    selector: PacketSelector
    field_name: str
    action: str
    value: str | None = None


@dataclass(frozen=True)
class NasFieldLocatorSpec:
    strategy: str
    offset: int | None = None
    length: int | None = None
    length_from_field: str = ""


@dataclass(frozen=True)
class NasRuleSchema:
    family_name: str
    strategy: str
    priority: str
    rationale: str
    target: str = ""
    candidate_values: tuple[str, ...] = field(default_factory=tuple)
    named_operators: tuple[str, ...] = field(default_factory=tuple)
    operator_labels: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class NasFieldSchema:
    message_name: str
    field_name: str
    kind: str
    mandatory: bool
    baseline_value: str
    location_hint: str
    notes: str
    iei_tag: str = ""
    action_kinds: tuple[str, ...] = field(default_factory=tuple)
    operator_labels: tuple[str, ...] = field(default_factory=tuple)
    generation_strategies: tuple[str, ...] = field(default_factory=tuple)
    rules: tuple[NasRuleSchema, ...] = field(default_factory=tuple)
    locator: NasFieldLocatorSpec | None = None


@dataclass(frozen=True)
class NasMessageSchema:
    message_name: str
    message_type_code: str
    direction: str
    procedure_phase: str
    expected_precondition: str
    baseline_signature: str = ""
    fields: tuple[NasFieldSchema, ...] = field(default_factory=tuple)

    def field_map(self) -> dict[str, NasFieldSchema]:
        return {field.field_name: field for field in self.fields}

    def get_field(self, field_name: str) -> NasFieldSchema:
        try:
            return self.field_map()[field_name]
        except KeyError as exc:
            raise KeyError(
                f"Unknown field '{field_name}' for NAS message schema '{self.message_name}'."
            ) from exc


def build_nested_registration_request_selector(
    *,
    message_name: str = "Registration Request",
    occurrence: str = "later",
) -> PacketSelector:
    return PacketSelector(
        direction="uplink",
        container_type="nested-registration-request",
        message_name=message_name,
        occurrence=occurrence,
    )


def build_plain_nas_selector(
    *,
    message_name: str,
    occurrence: str = "first",
    direction: str = "uplink",
) -> PacketSelector:
    return PacketSelector(
        direction=direction,
        container_type="plain-nas-message",
        message_name=message_name,
        occurrence=occurrence,
    )


def build_plain_field_mutation_plan(
    *,
    message_name: str,
    field_name: str,
    action: str,
    value: str | None = None,
    occurrence: str = "first",
    direction: str = "uplink",
) -> NasMutationPlan:
    return NasMutationPlan(
        selector=build_plain_nas_selector(
            message_name=message_name,
            occurrence=occurrence,
            direction=direction,
        ),
        field_name=field_name,
        action=action,
        value=value,
    )


def build_nested_optional_ie_mutation_plan(
    *,
    field_name: str,
    action: str,
    value: str | None = None,
    message_name: str = "Registration Request",
    occurrence: str = "later",
) -> NasMutationPlan:
    return NasMutationPlan(
        selector=build_nested_registration_request_selector(
            message_name=message_name,
            occurrence=occurrence,
        ),
        field_name=field_name,
        action=action,
        value=value,
    )


def serialize_mutation_plan_value(
    plan: NasMutationPlan,
    *,
    include_field: bool = True,
) -> str:
    parts: list[str] = []
    if include_field:
        parts.append(f"field:{plan.field_name}")
    parts.append(f"action:{plan.action}")
    if plan.value is not None:
        value_key = "length" if plan.action == "bad-length" else "value"
        parts.append(f"{value_key}:{plan.value}")
    return ",".join(parts)


def deserialize_mutation_plan_value(
    raw_value: str | None,
    *,
    selector: PacketSelector,
    default_field_name: str | None = None,
) -> NasMutationPlan:
    field_name = default_field_name or ""
    action = ""
    value = None

    if raw_value:
        for part in raw_value.split(","):
            if ":" not in part:
                continue
            key, raw_part_value = part.split(":", 1)
            if key == "field":
                field_name = raw_part_value
            elif key == "action":
                action = raw_part_value
            elif key in {"length", "value"}:
                value = raw_part_value

    if not field_name:
        raise ValueError(f"Could not decode field name from mutation plan value '{raw_value}'.")
    if not action:
        raise ValueError(f"Could not decode action from mutation plan value '{raw_value}'.")

    return NasMutationPlan(
        selector=selector,
        field_name=field_name,
        action=action,
        value=value,
    )


def build_field_schema(
    message_name: str,
    field_def: NasFieldDefinition,
) -> NasFieldSchema:
    return NasFieldSchema(
        message_name=message_name,
        field_name=field_def.name,
        kind=field_def.kind,
        mandatory=field_def.mandatory,
        baseline_value=field_def.baseline_value,
        location_hint=field_def.location_hint,
        notes=field_def.notes,
        iei_tag=field_def.iei_tag,
        action_kinds=_rule_action_kinds(field_def),
        operator_labels=_field_operator_labels(field_def),
        generation_strategies=_dedupe_preserve_order(
            tuple(rule.strategy for rule in field_def.generation_rules)
        ),
        rules=tuple(build_rule_schema(field_def, rule) for rule in field_def.generation_rules),
        locator=_field_locator_spec(message_name, field_def),
    )


def _field_locator_spec(
    message_name: str,
    field_def: NasFieldDefinition,
) -> NasFieldLocatorSpec | None:
    if message_name == "Registration Request":
        if field_def.name == "security_header":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=1, length=1)
        if field_def.name == "message_type":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=2, length=1)
        if field_def.name == "registration_type_and_ngksi":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=3, length=1)
        if field_def.name == "mobile_identity_length":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=4, length=2)
        if field_def.name == "mobile_identity_value":
            return NasFieldLocatorSpec(
                strategy="length-prefixed-payload",
                offset=6,
                length_from_field="mobile_identity_length",
            )
    if message_name == "Identity Response":
        if field_def.name == "security_header":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=1, length=1)
        if field_def.name == "message_type":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=2, length=1)
        if field_def.name == "identity_payload":
            return NasFieldLocatorSpec(strategy="payload-remainder", offset=3)
    if message_name == "Authentication Response":
        if field_def.name == "security_header":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=1, length=1)
        if field_def.name == "message_type":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=2, length=1)
        if field_def.name == "authentication_response_parameter":
            return NasFieldLocatorSpec(strategy="payload-remainder", offset=3)
    if message_name == "Security Mode Complete":
        if field_def.name == "protected_security_header":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=1, length=1)
        if field_def.name == "message_type":
            return NasFieldLocatorSpec(strategy="fixed-offset", offset=9, length=1)
    return None


def build_rule_schema(
    field_def: NasFieldDefinition,
    rule: NasFieldGenerationRule,
) -> NasRuleSchema:
    return NasRuleSchema(
        family_name=rule.family_name,
        strategy=rule.strategy,
        priority=rule.priority,
        rationale=rule.rationale,
        target=rule.target,
        candidate_values=rule.candidate_values,
        named_operators=rule.operators,
        operator_labels=generate_mutation_operators(
            field_name=field_def.name,
            field_kind=field_def.kind,
            baseline_value=field_def.baseline_value,
            rule=rule,
        ),
    )


def build_message_schema(profile: NasMessageProfile) -> NasMessageSchema:
    return NasMessageSchema(
        message_name=profile.message_name,
        message_type_code=profile.message_type_code,
        direction=profile.direction,
        procedure_phase=profile.procedure_phase,
        expected_precondition=profile.expected_precondition,
        baseline_signature=profile.baseline_signature,
        fields=tuple(
            build_field_schema(profile.message_name, field_def)
            for field_def in profile.field_definitions
        ),
    )


def get_nas_message_schemas() -> tuple[NasMessageSchema, ...]:
    return tuple(build_message_schema(profile) for profile in get_nas_message_profiles())


def get_nas_message_schema(message_name: str) -> NasMessageSchema:
    for schema in get_nas_message_schemas():
        if schema.message_name == message_name:
            return schema
    raise KeyError(f"Unknown NAS message schema '{message_name}'.")


def _nested_optional_ie_action_from_rule(
    *,
    rule: NasRuleSchema,
    operator: str,
) -> tuple[str, str | None] | None:
    normalized_operator = operator.lower()

    if rule.strategy == "optional-ie-omit":
        return ("omit", None)
    if rule.strategy == "optional-ie-duplicate":
        return ("duplicate", None)
    if rule.strategy == "optional-ie-bad-length":
        return ("bad-length", "0xff")
    if rule.strategy == "payload-truncation":
        return ("truncate-payload", None)
    if rule.strategy == "bitfield-reserved-bits":
        return ("set-reserved-bits", None)
    if rule.strategy == "named-operators":
        if normalized_operator == "unsupported sst/sd combination":
            return ("unsupported-sst-sd", None)
        if normalized_operator == "duplicate nssai entries":
            return ("duplicate-payload-entries", None)
    return None


def resolve_nested_optional_ie_plan(
    *,
    message_name: str,
    family_name: str,
    operator: str,
) -> NasMutationPlan | None:
    schema = get_nas_message_schema(message_name)
    normalized_family = family_name.lower()
    normalized_operator = operator.lower()

    for field in schema.fields:
        if field.kind not in {"optional_tlv", "tlv_payload"}:
            continue
        for rule in field.rules:
            if rule.family_name.lower() != normalized_family:
                continue
            if normalized_operator not in {label.lower() for label in rule.operator_labels}:
                continue
            resolved = _nested_optional_ie_action_from_rule(rule=rule, operator=operator)
            if resolved is None:
                continue
            action, value = resolved
            return NasMutationPlan(
                selector=build_nested_registration_request_selector(
                    message_name=message_name,
                    occurrence="later",
                ),
                field_name=field.field_name,
                action=action,
                value=value,
            )

    return None


def _last_operator_hex_value(operator: str) -> str | None:
    matches = re.findall(r"0x[0-9a-fA-F]+", operator)
    if not matches:
        return None
    return matches[-1].lower()


def _plain_field_action_from_rule(
    *,
    field: NasFieldSchema,
    rule: NasRuleSchema,
    operator: str,
) -> tuple[str, str | None] | None:
    if rule.strategy in {"enum-substitution", "bitfield-substitution"}:
        resolved = _last_operator_hex_value(operator)
        if resolved is None:
            return None
        return ("replace-byte", resolved)

    if rule.strategy == "length-boundary":
        resolved = _last_operator_hex_value(operator)
        if resolved is None:
            return None
        locator = field.locator
        if locator is not None and locator.length == 1:
            return ("replace-byte", resolved)
        return ("replace-word-be", resolved)

    if rule.strategy == "payload-truncation":
        if field.kind not in {"payload", "identity"}:
            return None
        return ("truncate-payload", None)

    if rule.strategy == "named-operators":
        normalized_operator = operator.lower()
        if normalized_operator == "toggle identity type bits inconsistently":
            return ("replace-first-byte", "0x06")
        if field.field_name == "authentication_response_parameter":
            if normalized_operator == "truncate response parameter":
                return ("truncate-payload", None)
            if normalized_operator == "oversized length":
                return ("set-leading-length-byte", "0xff")
            if normalized_operator == "all-zero response value":
                return ("zero-payload-value", None)
            if normalized_operator == "append extra bytes":
                return ("append-bytes", "0x0000")
            if normalized_operator == "leave inconsistent length metadata":
                return ("increment-leading-length-byte", None)

    return None


def resolve_plain_field_mutation_plan(
    *,
    message_name: str,
    family_name: str,
    operator: str,
) -> NasMutationPlan | None:
    schema = get_nas_message_schema(message_name)
    normalized_family = family_name.lower()
    normalized_operator = operator.lower()

    for field in schema.fields:
        if field.iei_tag:
            continue
        if field.locator is None:
            continue
        for rule in field.rules:
            if rule.family_name.lower() != normalized_family:
                continue
            if normalized_operator not in {label.lower() for label in rule.operator_labels}:
                continue
            resolved = _plain_field_action_from_rule(
                field=field,
                rule=rule,
                operator=operator,
            )
            if resolved is None:
                continue
            action, value = resolved
            return build_plain_field_mutation_plan(
                message_name=message_name,
                field_name=field.field_name,
                action=action,
                value=value,
            )

    return None
