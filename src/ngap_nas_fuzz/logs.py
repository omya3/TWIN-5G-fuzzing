from __future__ import annotations

import re
from dataclasses import dataclass


LOG_RE = re.compile(
    r"^(?P<sys_ts>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>\S+)\[(?P<pid>\d+)\]:\s+"
    r"(?P<ogs_ts>\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}):\s+"
    r"\[(?P<component>[^\]]+)\]\s+"
    r"(?P<level>[A-Z]+):\s+"
    r"(?P<message>.*)$"
)

UERANSIM_LOG_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<component>[^\]]+)\]\s+\[(?P<level>[^\]]+)\]\s+(?P<message>.*)$"
)


@dataclass
class LogEvent:
    line_number: int
    system_timestamp: str
    open5gs_timestamp: str
    component: str
    level: str
    message: str


@dataclass
class UeransimLogEvent:
    line_number: int
    timestamp: str
    component: str
    level: str
    message: str


KEY_PATTERNS = {
    "gnb_connected": re.compile(r"gNB-N2 accepted"),
    "initial_ue_message": re.compile(r"InitialUEMessage"),
    "registration_request": re.compile(r"Registration request"),
    "authentication": re.compile(r"Authentication"),
    "security_mode": re.compile(r"Security mode"),
    "registration_complete": re.compile(r"Registration complete"),
    "pdu_session": re.compile(r"PDU|/nsmf-pdusession"),
    "warning_or_error": re.compile(r".*"),
}

UERANSIM_KEY_PATTERNS = {
    "sctp_connected": re.compile(r"SCTP connection established"),
    "ng_setup_success": re.compile(r"NG Setup procedure is successful"),
    "initial_nas_from_ue": re.compile(r"Initial NAS message received from UE"),
    "initial_registration_sent": re.compile(r"Sending Initial Registration"),
    "authentication_request": re.compile(r"Authentication Request received"),
    "security_mode_command": re.compile(r"Security Mode Command received"),
    "registration_accept": re.compile(r"Registration accept received"),
    "registration_success": re.compile(r"Initial Registration is successful"),
    "initial_context_setup_request": re.compile(r"Initial Context Setup Request received"),
    "pdu_session_success": re.compile(
        r"PDU session resource\(s\) setup|PDU Session establishment is successful"
    ),
    "radio_link_failure": re.compile(r"Radio link failure detected"),
    "signal_lost": re.compile(r"Signal lost"),
    "warning_or_error": re.compile(r".*"),
}


def parse_amf_log(text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        match = LOG_RE.match(line)
        if not match:
            continue
        events.append(
            LogEvent(
                line_number=idx,
                system_timestamp=match.group("sys_ts"),
                open5gs_timestamp=match.group("ogs_ts"),
                component=match.group("component"),
                level=match.group("level"),
                message=match.group("message"),
            )
        )
    return events


def summarize_amf_log(text: str) -> dict:
    events = parse_amf_log(text)
    summary = {
        "total_events": len(events),
        "by_level": {},
        "key_events": {name: [] for name in KEY_PATTERNS.keys()},
    }

    for event in events:
        summary["by_level"][event.level] = summary["by_level"].get(event.level, 0) + 1
        for name, pattern in KEY_PATTERNS.items():
            if name == "warning_or_error":
                if event.level in {"WARNING", "ERROR", "FATAL"}:
                    summary["key_events"][name].append(event)
            elif pattern.search(event.message):
                summary["key_events"][name].append(event)

    return summary


def parse_ueransim_log(text: str) -> list[UeransimLogEvent]:
    events: list[UeransimLogEvent] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        match = UERANSIM_LOG_RE.match(line)
        if not match:
            continue
        events.append(
            UeransimLogEvent(
                line_number=idx,
                timestamp=match.group("ts"),
                component=match.group("component"),
                level=match.group("level").upper(),
                message=match.group("message"),
            )
        )
    return events


def summarize_ueransim_log(text: str) -> dict:
    events = parse_ueransim_log(text)
    summary = {
        "total_events": len(events),
        "by_level": {},
        "key_events": {name: [] for name in UERANSIM_KEY_PATTERNS.keys()},
    }

    for event in events:
        summary["by_level"][event.level] = summary["by_level"].get(event.level, 0) + 1
        for name, pattern in UERANSIM_KEY_PATTERNS.items():
            if name == "warning_or_error":
                if event.level in {"WARNING", "ERROR", "FATAL"}:
                    summary["key_events"][name].append(event)
            elif pattern.search(event.message):
                summary["key_events"][name].append(event)

    return summary
