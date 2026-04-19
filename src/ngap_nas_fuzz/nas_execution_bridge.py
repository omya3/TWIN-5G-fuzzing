from __future__ import annotations

from dataclasses import dataclass
import re


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
        proxy_mutation="nested-registration-request-optional-ie",
        execution_mode="nested-simulation",
        operator_pattern=r"^(omit ie entirely|duplicate ie|invalid length|unsupported sst/sd combination|duplicate nssai entries)$",
    ),
    NasExecutionBridge(
        message_name="Registration Request",
        family_name="5GMM capability corruption",
        proxy_mutation="nested-registration-request-optional-ie",
        execution_mode="nested-simulation",
        operator_pattern=r"^(omit ie entirely|oversized length|reserved bits set|truncation)$",
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


def resolve_operator_execution(
    *,
    message_name: str,
    family_name: str,
    operator: str,
) -> tuple[bool, str, str | None, str | None]:
    bridge = _matching_bridge(message_name, family_name, operator)
    if bridge is None:
        return (False, "planned", None, None)
    match = re.search(bridge.operator_pattern, operator.lower())

    if bridge.execution_mode == "nested-simulation":
        normalized = operator.lower()
        if normalized == "omit ie entirely":
            proxy_value = "action:omit"
        elif normalized == "duplicate ie":
            proxy_value = "action:duplicate"
        elif normalized in {"invalid length", "oversized length"}:
            proxy_value = "action:bad-length,length:0xff"
        elif normalized == "unsupported sst/sd combination":
            proxy_value = "action:unsupported-sst-sd"
        elif normalized == "duplicate nssai entries":
            proxy_value = "action:duplicate-payload-entries"
        elif normalized == "reserved bits set":
            proxy_value = "action:set-reserved-bits"
        elif normalized == "truncation":
            proxy_value = "action:truncate-payload"
        else:
            proxy_value = None
    else:
        proxy_value = match.group(1) if match.groups() else None
    return (True, bridge.execution_mode, bridge.proxy_mutation, proxy_value)


def observation_runtime_key(
    *,
    message_name: str,
    family_name: str,
    operator: str,
    proxy_mutation: str | None,
    proxy_value: str | None,
) -> tuple[str, str, str | None, str | None] | None:
    if proxy_mutation is not None:
        return (message_name, family_name, proxy_mutation, proxy_value)

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
    if proxy_mutation == "registration-type-and-ngksi":
        return f"replace 0x79 with {value}"
    if proxy_mutation == "security-header":
        return f"set security header 0x00 -> {value}"
    if proxy_mutation == "mobile-identity-length":
        return f"set mobile identity length 0x000d -> {value}"
    if proxy_mutation == "mobile-identity-invalid-bcd-tail":
        return f"inject invalid BCD digit in tail octet 0x2e -> {value}"
    return base_operator


def render_proxy_command_flag(proxy_mutation: str, value: str | None) -> str:
    if proxy_mutation == "mobile-identity-toggle-type-bits":
        return " --mutate-mobile-identity-type-bits"
    if value is None:
        return ""
    if proxy_mutation == "message-type":
        return f" --mutate-initial-nas-msgtype {value}"
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
    return ""
