from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .logs import LogEvent, UeransimLogEvent, parse_amf_log, parse_ueransim_log
from .nas_scheduler import (
    RESULT_AMF_CRASH,
    RESULT_DEEP_DECODER_FAILURE,
    RESULT_EARLY_SEMANTIC_REJECT,
    RESULT_PROXY_CRASH,
    RESULT_TIMEOUT_RETRY,
    RESULT_UNEXPECTED_ACCEPT,
)


_CRASH_PATTERNS = (
    re.compile(r"segmentation fault", re.IGNORECASE),
    re.compile(r"core dumped", re.IGNORECASE),
    re.compile(r"\bfatal\b", re.IGNORECASE),
    re.compile(r"\baborted\b", re.IGNORECASE),
    re.compile(r"assert", re.IGNORECASE),
)

_DEEP_DECODER_PATTERNS = (
    re.compile(r"ogs_nas_5gs_decode_.*failed"),
    re.compile(r"ogs_pkbuf_pull\(\) failed"),
    re.compile(r"Unknown type\(0x[0-9a-f]+\) or not implemented", re.IGNORECASE),
    re.compile(r"decode_5gs_mobile_identity", re.IGNORECASE),
    re.compile(r"Failed to decode ASN-PDU", re.IGNORECASE),
    re.compile(r"Failed to decode NGAP-PDU", re.IGNORECASE),
    re.compile(r"Cannot decode NGAP message", re.IGNORECASE),
    re.compile(r"abstract-syntax-error-falsely-constructed-message", re.IGNORECASE),
)

_EARLY_REJECT_PATTERNS = (
    re.compile(r"Invalid 5GMM message type"),
    re.compile(r"Invalid extended_protocol_discriminator"),
    re.compile(r"Not implemented\(security header type:0x[0-9a-f]+\)", re.IGNORECASE),
    re.compile(r"Unknown reg_type\[\d+\]", re.IGNORECASE),
    re.compile(r"Registration reject \[\d+\]", re.IGNORECASE),
    re.compile(r"Non cleartext IEs is included", re.IGNORECASE),
    re.compile(r"Expectation `OGS_OK == ngap_send_to_nas"),
    re.compile(r"Invalid .*"),
)

_UE_TIMER_RETRY_PATTERNS = (
    re.compile(r"NAS timer\[3510\] expired"),
    re.compile(r"NAS timer\[3511\] expired"),
)

_UE_SUCCESS_PATTERNS = (
    re.compile(r"Initial Registration is successful"),
    re.compile(r"PDU Session establishment is successful"),
)

_UE_PDU_SESSION_SUCCESS_PATTERNS = (
    re.compile(r"PDU Session establishment is successful"),
    re.compile(r"PDU Session Establishment Accept received"),
)


def _success_patterns_for_message(
    message_name: str | None,
) -> tuple[re.Pattern[str], ...]:
    if message_name == "PDU Session Establishment Request":
        return _UE_PDU_SESSION_SUCCESS_PATTERNS
    return _UE_SUCCESS_PATTERNS


@dataclass
class ProxyNasResultSuggestion:
    result_class: str
    note: str
    confidence: str
    evidence: list[str] = field(default_factory=list)


def _first_attempt_amf_window(events: list[LogEvent]) -> list[LogEvent]:
    indices = [idx for idx, event in enumerate(events) if "InitialUEMessage" in event.message]
    if not indices:
        return events
    start = indices[0]
    end = indices[1] if len(indices) > 1 else len(events)
    return events[start:end]


def _first_attempt_ue_window(events: list[UeransimLogEvent]) -> list[UeransimLogEvent]:
    indices = [
        idx
        for idx, event in enumerate(events)
        if "Sending Initial Registration" in event.message
    ]
    if not indices:
        return events
    start = indices[0]
    end = indices[1] if len(indices) > 1 else len(events)
    return events[start:end]


def _first_attempt_gnb_window(events: list[UeransimLogEvent]) -> list[UeransimLogEvent]:
    indices = [
        idx
        for idx, event in enumerate(events)
        if "Initial NAS message received" in event.message
    ]
    if not indices:
        return events
    start = indices[0]
    end = indices[1] if len(indices) > 1 else len(events)
    return events[start:end]


def _matching_event_message(
    messages: list[str],
    patterns: tuple[re.Pattern[str], ...],
) -> str | None:
    for pattern in patterns:
        for message in messages:
            if pattern.search(message):
                return message
    return None


def _matching_text_line(
    text: str,
    patterns: tuple[re.Pattern[str], ...],
) -> str | None:
    for pattern in patterns:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and pattern.search(stripped):
                return stripped
    return None


def _clean_note(prefix: str, message: str) -> str:
    cleaned = re.sub(r"\s+\([^)]*\)\s*$", "", message).strip()
    return f"{prefix} {cleaned}"


def _gnb_first_attempt_success_message(events: list[UeransimLogEvent]) -> str | None:
    return next(
        (
            event.message
            for event in events
            if "PDU session resource(s) setup" in event.message
            or "Initial Context Setup Request received" in event.message
        ),
        None,
    )


def classify_proxy_nas_result_texts(
    *,
    amf_text: str = "",
    ue_text: str = "",
    gnb_text: str = "",
    proxy_text: str = "",
    message_name: str | None = None,
) -> ProxyNasResultSuggestion:
    proxy_lines = [line.strip() for line in proxy_text.splitlines() if line.strip()]
    amf_events = parse_amf_log(amf_text)
    ue_events = parse_ueransim_log(ue_text)
    gnb_events = parse_ueransim_log(gnb_text)

    proxy_messages = proxy_lines
    amf_first_window = _first_attempt_amf_window(amf_events)
    ue_first_window = _first_attempt_ue_window(ue_events)
    gnb_first_window = _first_attempt_gnb_window(gnb_events)

    amf_first_messages = [event.message for event in amf_first_window]
    amf_first_error_messages = [
        event.message for event in amf_first_window if event.level in {"ERROR", "FATAL"}
    ]
    ue_first_messages = [event.message for event in ue_first_window]
    gnb_success_message = _gnb_first_attempt_success_message(gnb_first_window)
    amf_first_text = "\n".join(amf_first_messages)
    ue_first_text = "\n".join(ue_first_messages)

    crash_message = _matching_event_message(proxy_messages, _CRASH_PATTERNS)
    if crash_message is not None:
        return ProxyNasResultSuggestion(
            result_class=RESULT_PROXY_CRASH,
            note=_clean_note("Proxy log shows", crash_message),
            confidence="high",
            evidence=[f"proxy: {crash_message}"],
        )

    crash_message = _matching_event_message(amf_first_messages, _CRASH_PATTERNS)
    if crash_message is not None:
        return ProxyNasResultSuggestion(
            result_class=RESULT_AMF_CRASH,
            note=_clean_note("AMF log shows", crash_message),
            confidence="high",
            evidence=[f"amf: {crash_message}"],
        )

    success_message = _matching_event_message(
        ue_first_messages,
        _success_patterns_for_message(message_name),
    )

    deep_message = _matching_event_message(amf_first_error_messages, _DEEP_DECODER_PATTERNS)
    if deep_message is None:
        deep_message = _matching_text_line(amf_first_text, _DEEP_DECODER_PATTERNS)
    if deep_message is not None and success_message is not None:
        evidence = [f"amf: {deep_message}", f"ue: {success_message}"]
        if gnb_success_message is not None:
            evidence.append(f"gnb: {gnb_success_message}")
        return ProxyNasResultSuggestion(
            result_class=RESULT_UNEXPECTED_ACCEPT,
            note=_clean_note("UE log shows", success_message),
            confidence="high",
            evidence=evidence,
        )
    if deep_message is not None:
        evidence = [f"amf: {deep_message}"]
        timer_message = _matching_event_message(ue_first_messages, _UE_TIMER_RETRY_PATTERNS)
        if timer_message is None:
            timer_message = _matching_text_line(ue_first_text, _UE_TIMER_RETRY_PATTERNS)
        if timer_message is not None:
            evidence.append(f"ue: {timer_message}")
        return ProxyNasResultSuggestion(
            result_class=RESULT_DEEP_DECODER_FAILURE,
            note=_clean_note("AMF log shows", deep_message),
            confidence="high",
            evidence=evidence,
        )

    early_message = _matching_event_message(amf_first_error_messages, _EARLY_REJECT_PATTERNS)
    if early_message is None:
        early_message = _matching_text_line(amf_first_text, _EARLY_REJECT_PATTERNS)
    if early_message is not None and success_message is not None:
        evidence = [f"amf: {early_message}", f"ue: {success_message}"]
        if gnb_success_message is not None:
            evidence.append(f"gnb: {gnb_success_message}")
        return ProxyNasResultSuggestion(
            result_class=RESULT_UNEXPECTED_ACCEPT,
            note=_clean_note("UE log shows", success_message),
            confidence="high",
            evidence=evidence,
        )
    if early_message is not None:
        evidence = [f"amf: {early_message}"]
        timer_message = _matching_event_message(ue_first_messages, _UE_TIMER_RETRY_PATTERNS)
        if timer_message is None:
            timer_message = _matching_text_line(ue_first_text, _UE_TIMER_RETRY_PATTERNS)
        if timer_message is not None:
            evidence.append(f"ue: {timer_message}")
        return ProxyNasResultSuggestion(
            result_class=RESULT_EARLY_SEMANTIC_REJECT,
            note=_clean_note("AMF log shows", early_message),
            confidence="high",
            evidence=evidence,
        )

    if success_message is not None:
        evidence = [f"ue: {success_message}"]
        if gnb_success_message is not None:
            evidence.append(f"gnb: {gnb_success_message}")
        return ProxyNasResultSuggestion(
            result_class=RESULT_UNEXPECTED_ACCEPT,
            note=_clean_note("UE log shows", success_message),
            confidence="medium",
            evidence=evidence,
        )

    timer_message = _matching_event_message(ue_first_messages, _UE_TIMER_RETRY_PATTERNS)
    if timer_message is None:
        timer_message = _matching_text_line(ue_first_text, _UE_TIMER_RETRY_PATTERNS)
    if timer_message is not None:
        evidence = [f"ue: {timer_message}"]
        if amf_first_error_messages:
            evidence.append(f"amf: {amf_first_error_messages[0]}")
        return ProxyNasResultSuggestion(
            result_class=RESULT_TIMEOUT_RETRY,
            note=_clean_note("UE log shows", timer_message),
            confidence="medium",
            evidence=evidence,
        )

    if amf_first_error_messages:
        fallback_error = amf_first_error_messages[0]
        return ProxyNasResultSuggestion(
            result_class=RESULT_EARLY_SEMANTIC_REJECT,
            note=_clean_note("AMF log shows", fallback_error),
            confidence="low",
            evidence=[f"amf: {fallback_error}"],
        )

    return ProxyNasResultSuggestion(
        result_class=RESULT_TIMEOUT_RETRY,
        note="No decisive AMF decode error was found; result may be a timeout or retry case",
        confidence="low",
        evidence=[],
    )


def classify_proxy_nas_result_logs(
    logs_dir: Path,
    *,
    message_name: str | None = None,
) -> ProxyNasResultSuggestion:
    proxy_path = logs_dir / "proxy.log"
    amf_path = logs_dir / "amf.log"
    gnb_path = logs_dir / "gnb.log"
    ue_path = logs_dir / "ue.log"

    return classify_proxy_nas_result_texts(
        proxy_text=proxy_path.read_text() if proxy_path.exists() else "",
        amf_text=amf_path.read_text() if amf_path.exists() else "",
        gnb_text=gnb_path.read_text() if gnb_path.exists() else "",
        ue_text=ue_path.read_text() if ue_path.exists() else "",
        message_name=message_name,
    )
