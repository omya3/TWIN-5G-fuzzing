from __future__ import annotations

from dataclasses import dataclass
import re

from .nas_schema import (
    build_nested_optional_ie_mutation_plan,
    build_nested_registration_request_selector,
    deserialize_mutation_plan_value,
    resolve_plain_field_mutation_plan,
    resolve_nested_optional_ie_plan,
    serialize_mutation_plan_value,
)

LIVE_NESTED_OPTIONAL_IE_MUTATION = "nested-registration-request-optional-ie-live"
PLAIN_FIELD_SIMULATION_MUTATION = "plain-nas-field-simulation"
IDENTITY_RESPONSE_MESSAGE_TYPE_MUTATION = "identity-response-message-type"
IDENTITY_RESPONSE_SECURITY_HEADER_MUTATION = "identity-response-security-header"
AUTHENTICATION_RESPONSE_MESSAGE_TYPE_MUTATION = "authentication-response-message-type"
AUTHENTICATION_RESPONSE_SECURITY_HEADER_MUTATION = "authentication-response-security-header"
AUTHENTICATION_RESPONSE_ZERO_RESPONSE_VALUE_MUTATION = "authentication-response-zero-response-value"
AUTHENTICATION_RESPONSE_PARAMETER_LENGTH_MUTATION = "authentication-response-parameter-length"
AUTHENTICATION_RESPONSE_PARAMETER_LENGTH_DEFAULT = "0xff"
SECURITY_MODE_COMPLETE_MESSAGE_TYPE_MUTATION = "security-mode-complete-message-type"
SECURITY_MODE_COMPLETE_SECURITY_HEADER_MUTATION = "security-mode-complete-security-header"


@dataclass(frozen=True)
class NasExecutionBridge:
    message_name: str
    family_name: str
    proxy_mutation: str
    execution_mode: str
    operator_pattern: str


_EXECUTION_BRIDGES: tuple[NasExecutionBridge, ...] = (
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="message-type substitution",
        proxy_mutation="message-type",
        execution_mode="proxy",
        operator_pattern=r"replace 0x41 with (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="registration-type-and-ngksi mutation",
        proxy_mutation="registration-type-and-ngksi",
        execution_mode="proxy",
        operator_pattern=r"replace 0x79 with (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="security-header mutation",
        proxy_mutation="security-header",
        execution_mode="proxy",
        operator_pattern=r"0x00 -> (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="mobile-identity length corruption",
        proxy_mutation="mobile-identity-length",
        execution_mode="proxy",
        operator_pattern=r"0x000d -> (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="mobile-identity value corruption",
        proxy_mutation="mobile-identity-invalid-bcd-tail",
        execution_mode="proxy",
        operator_pattern=r"0x2e -> (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="mobile-identity value corruption",
        proxy_mutation="mobile-identity-toggle-type-bits",
        execution_mode="proxy",
        operator_pattern=r"^toggle identity type bits inconsistently$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="requested NSSAI corruption",
        proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^omit ie entirely$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="requested NSSAI corruption",
        proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^invalid length$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="requested NSSAI corruption",
        proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^duplicate ie$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="requested NSSAI corruption",
        proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^unsupported sst/sd combination$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="requested NSSAI corruption",
        proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^duplicate nssai entries$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="5GMM capability corruption",
        proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^omit ie entirely$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="5GMM capability corruption",
        proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^oversized length$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="5GMM capability corruption",
        proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^reserved bits set$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="5GMM capability corruption",
        proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^truncation$",
    ),
    NasExecutionBridge(
        message_name="Identity Response",
        family_name="message-type substitution",
        proxy_mutation=IDENTITY_RESPONSE_MESSAGE_TYPE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"replace 0x5c with (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Identity Response",
        family_name="security-header mutation",
        proxy_mutation=IDENTITY_RESPONSE_SECURITY_HEADER_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"0x00 -> (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Authentication Response",
        family_name="message-type substitution",
        proxy_mutation=AUTHENTICATION_RESPONSE_MESSAGE_TYPE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"replace 0x57 with (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Authentication Response",
        family_name="security-header mutation",
        proxy_mutation=AUTHENTICATION_RESPONSE_SECURITY_HEADER_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"0x00 -> (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Authentication Response",
        family_name="authentication parameter corruption",
        proxy_mutation=AUTHENTICATION_RESPONSE_ZERO_RESPONSE_VALUE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^all-zero response value$",
    ),
    NasExecutionBridge(
        message_name="Authentication Response",
        family_name="authentication parameter corruption",
        proxy_mutation=AUTHENTICATION_RESPONSE_PARAMETER_LENGTH_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"^oversized length$",
    ),
    NasExecutionBridge(
        message_name="Security Mode Complete",
        family_name="message-type substitution",
        proxy_mutation=SECURITY_MODE_COMPLETE_MESSAGE_TYPE_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"replace 0x5e with (0x[0-9a-f]+)",
    ),
    NasExecutionBridge(
        message_name="Security Mode Complete",
        family_name="security-header inconsistency",
        proxy_mutation=SECURITY_MODE_COMPLETE_SECURITY_HEADER_MUTATION,
        execution_mode="proxy",
        operator_pattern=r"0x04 -> (0x[0-9a-f]+)",
    ),
)


def _matching_bridge(message_name: str, family_name: str, operator: str) -> NasExecutionBridge | None:
    for bridge in _EXECUTION_BRIDGES:
        if (
            bridge.message_name == message_name
            and bridge.family_name == family_name
            and re.search(bridge.operator_pattern, operator.lower()) is not None
        ):
            return bridge
    return None


def _live_nested_optional_ie_value(
    *,
    message_name: str,
    family_name: str,
    operator: str,
) -> str:
    plan = resolve_nested_optional_ie_plan(
        message_name=message_name,
        family_name=family_name,
        operator=operator,
    )
    if plan is None:
        raise ValueError(
            f"Unsupported live nested optional-IE operator '{operator}' for family '{family_name}'."
        )
    return serialize_mutation_plan_value(plan, include_field=True)


def _normalize_legacy_proxy_runtime(
    proxy_mutation: str,
    proxy_value: str | None,
) -> tuple[str, str | None]:
    if proxy_mutation == "nested-requested-nssai-omit":
        plan = build_nested_optional_ie_mutation_plan(
            field_name="requested_nssai",
            action="omit",
        )
        return (
            LIVE_NESTED_OPTIONAL_IE_MUTATION,
            serialize_mutation_plan_value(plan, include_field=True),
        )
    if proxy_mutation == "nested-requested-nssai-bad-length":
        plan = build_nested_optional_ie_mutation_plan(
            field_name="requested_nssai",
            action="bad-length",
            value=proxy_value or "0xff",
        )
        return (
            LIVE_NESTED_OPTIONAL_IE_MUTATION,
            serialize_mutation_plan_value(plan, include_field=True),
        )
    if proxy_mutation == "nested-fivegmm-capability-omit":
        plan = build_nested_optional_ie_mutation_plan(
            field_name="fivegmm_capability",
            action="omit",
        )
        return (
            LIVE_NESTED_OPTIONAL_IE_MUTATION,
            serialize_mutation_plan_value(plan, include_field=True),
        )
    if proxy_mutation == "nested-fivegmm-capability-bad-length":
        plan = build_nested_optional_ie_mutation_plan(
            field_name="fivegmm_capability",
            action="bad-length",
            value=proxy_value or "0xff",
        )
        return (
            LIVE_NESTED_OPTIONAL_IE_MUTATION,
            serialize_mutation_plan_value(plan, include_field=True),
        )
    if proxy_mutation == LIVE_NESTED_OPTIONAL_IE_MUTATION:
        plan = deserialize_mutation_plan_value(
            proxy_value,
            selector=build_nested_registration_request_selector(),
        )
        return (
            LIVE_NESTED_OPTIONAL_IE_MUTATION,
            serialize_mutation_plan_value(plan, include_field=True),
        )
    return (proxy_mutation, proxy_value)


def resolve_operator_execution(
    *,
    message_name: str,
    family_name: str,
    operator: str,
) -> tuple[bool, str, str | None, str | None]:
    bridge = _matching_bridge(message_name, family_name, operator)
    if bridge is not None:
        match = re.search(bridge.operator_pattern, operator.lower())

        if bridge.execution_mode == "nested-simulation":
            plan = resolve_nested_optional_ie_plan(
                message_name=message_name,
                family_name=family_name,
                operator=operator,
            )
            proxy_value = (
                serialize_mutation_plan_value(plan, include_field=False)
                if plan is not None
                else None
            )
        else:
            if bridge.proxy_mutation == LIVE_NESTED_OPTIONAL_IE_MUTATION:
                proxy_value = _live_nested_optional_ie_value(
                    message_name=message_name,
                    family_name=family_name,
                    operator=operator,
                )
            elif bridge.proxy_mutation == AUTHENTICATION_RESPONSE_PARAMETER_LENGTH_MUTATION:
                proxy_value = (
                    match.group(1)
                    if match is not None and match.groups()
                    else AUTHENTICATION_RESPONSE_PARAMETER_LENGTH_DEFAULT
                )
            else:
                proxy_value = match.group(1) if match.groups() else None
        return (True, bridge.execution_mode, bridge.proxy_mutation, proxy_value)

    plain_plan = resolve_plain_field_mutation_plan(
        message_name=message_name,
        family_name=family_name,
        operator=operator,
    )
    if plain_plan is not None:
        return (
            True,
            "plain-simulation",
            PLAIN_FIELD_SIMULATION_MUTATION,
            serialize_mutation_plan_value(plain_plan, include_field=True),
        )

    return (False, "planned", None, None)


def observation_runtime_key(
    *,
    message_name: str,
    family_name: str,
    operator: str,
    proxy_mutation: str | None,
    proxy_value: str | None,
) -> tuple[str, str, str | None, str | None] | None:
    if proxy_mutation is not None:
        normalized_mutation, normalized_value = _normalize_legacy_proxy_runtime(
            proxy_mutation,
            proxy_value,
        )
        return (message_name, family_name, normalized_mutation, normalized_value)

    executable_now, _, resolved_mutation, resolved_value = resolve_operator_execution(
        message_name=message_name,
        family_name=family_name,
        operator=operator,
    )
    if not executable_now:
        return None
    return (message_name, family_name, resolved_mutation, resolved_value)


def render_operator_for_value(base_operator: str, proxy_mutation: str, value: str | None) -> str:
    if value is None:
        return base_operator
    if proxy_mutation == "message-type":
        return f"replace 0x41 with {value}"
    if proxy_mutation == IDENTITY_RESPONSE_MESSAGE_TYPE_MUTATION:
        return f"replace 0x5c with {value}"
    if proxy_mutation == AUTHENTICATION_RESPONSE_MESSAGE_TYPE_MUTATION:
        return f"replace 0x57 with {value}"
    if proxy_mutation == SECURITY_MODE_COMPLETE_MESSAGE_TYPE_MUTATION:
        return f"replace 0x5e with {value}"
    if proxy_mutation == "registration-type-and-ngksi":
        return f"replace 0x79 with {value}"
    if proxy_mutation == "security-header":
        return f"set security header 0x00 -> {value}"
    if proxy_mutation == IDENTITY_RESPONSE_SECURITY_HEADER_MUTATION:
        return f"set security header 0x00 -> {value}"
    if proxy_mutation == AUTHENTICATION_RESPONSE_SECURITY_HEADER_MUTATION:
        return f"set security header 0x00 -> {value}"
    if proxy_mutation == SECURITY_MODE_COMPLETE_SECURITY_HEADER_MUTATION:
        return f"set security header 0x04 -> {value}"
    if proxy_mutation == "mobile-identity-length":
        return f"set mobile identity length 0x000d -> {value}"
    if proxy_mutation == "mobile-identity-invalid-bcd-tail":
        return f"inject invalid BCD digit in tail octet 0x2e -> {value}"
    return base_operator


def render_proxy_command_flag(proxy_mutation: str, value: str | None) -> str:
    if proxy_mutation == "mobile-identity-toggle-type-bits":
        return " --mutate-mobile-identity-type-bits"
    if proxy_mutation == AUTHENTICATION_RESPONSE_ZERO_RESPONSE_VALUE_MUTATION:
        return " --mutate-authentication-response-zero-response-value"
    if proxy_mutation == AUTHENTICATION_RESPONSE_PARAMETER_LENGTH_MUTATION:
        return (
            " --mutate-authentication-response-parameter-length "
            f"{value or AUTHENTICATION_RESPONSE_PARAMETER_LENGTH_DEFAULT}"
        )
    if proxy_mutation == SECURITY_MODE_COMPLETE_MESSAGE_TYPE_MUTATION:
        return f" --mutate-security-mode-complete-msgtype {value}"
    if proxy_mutation == SECURITY_MODE_COMPLETE_SECURITY_HEADER_MUTATION:
        return f" --mutate-security-mode-complete-security-header {value}"
    if proxy_mutation == LIVE_NESTED_OPTIONAL_IE_MUTATION:
        plan = deserialize_mutation_plan_value(
            value,
            selector=build_nested_registration_request_selector(),
        )
        normalized_value = serialize_mutation_plan_value(plan, include_field=True)
        return f" --mutate-nested-optional-ie {normalized_value}"
    if proxy_mutation == "nested-requested-nssai-omit":
        return " --mutate-nested-requested-nssai-omit"
    if proxy_mutation == "nested-requested-nssai-bad-length":
        return f" --mutate-nested-requested-nssai-bad-length {value or '0xff'}"
    if proxy_mutation == "nested-fivegmm-capability-omit":
        return " --mutate-nested-fivegmm-capability-omit"
    if proxy_mutation == "nested-fivegmm-capability-bad-length":
        return f" --mutate-nested-fivegmm-capability-bad-length {value or '0xff'}"
    if value is None:
        return ""
    if proxy_mutation == "message-type":
        return f" --mutate-initial-nas-msgtype {value}"
    if proxy_mutation == IDENTITY_RESPONSE_MESSAGE_TYPE_MUTATION:
        return f" --mutate-identity-response-msgtype {value}"
    if proxy_mutation == AUTHENTICATION_RESPONSE_MESSAGE_TYPE_MUTATION:
        return f" --mutate-authentication-response-msgtype {value}"
    if proxy_mutation == "registration-type-and-ngksi":
        return f" --mutate-registration-type-and-ngksi {value}"
    if proxy_mutation == "mobile-identity-length":
        return f" --mutate-mobile-identity-length {value}"
    if proxy_mutation == "mobile-identity-invalid-bcd-tail":
        return f" --mutate-mobile-identity-tail-bcd {value}"
    if proxy_mutation == "mobile-identity-toggle-type-bits":
        return " --mutate-mobile-identity-type-bits"
    if proxy_mutation == "security-header":
        return f" --mutate-initial-nas-security-header {value}"
    if proxy_mutation == IDENTITY_RESPONSE_SECURITY_HEADER_MUTATION:
        return f" --mutate-identity-response-security-header {value}"
    if proxy_mutation == AUTHENTICATION_RESPONSE_SECURITY_HEADER_MUTATION:
        return f" --mutate-authentication-response-security-header {value}"
    return ""
