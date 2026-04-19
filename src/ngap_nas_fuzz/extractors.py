from __future__ import annotations

import re
from typing import Iterable
import json

from .models import Message, ProcedureTrace

_FRAME_HEADER_RE = re.compile(r"^Frame\s+\d+:")
_FRAME_NUMBER_RE = re.compile(r"^Frame\s+(\d+):")
_IP_LINE_RE = re.compile(r"Internet Protocol Version 4, Src:\s*([^,]+), Dst:\s*([^\s]+)")
_NGAP_TYPE_RE = re.compile(r"NG Application Protocol \(([^)]+)\)")
_AMF_UE_ID_RE = re.compile(r"AMF[- ]UE[- ]NGAP[- ]ID:\s*([^\s,]+)", re.IGNORECASE)
_RAN_UE_ID_RE = re.compile(r"RAN[- ]UE[- ]NGAP[- ]ID:\s*([^\s,]+)", re.IGNORECASE)
_TAC_RE = re.compile(r"tAC:\s*([^\s,]+)")
_NAS_MM_RE = re.compile(
    r"NAS 5GS Mobility Management Message Type:\s*([^\(\n]+?)(?:\s+\(0x[0-9a-fA-F]+\))?$"
)
_NAS_SM_RE = re.compile(
    r"NAS 5GS Session Management Message Type:\s*([^\(\n]+?)(?:\s+\(0x[0-9a-fA-F]+\))?$"
)
_NAS_GENERIC_MSG_RE = re.compile(
    r"Message type:\s*([^\(\n]+?)(?:\s+\(0x[0-9a-fA-F]+\))?$"
)
_SEC_HDR_RE = re.compile(r"Security header type:\s*(.+)")


def _split_frames(lines: Iterable[str]) -> list[list[str]]:
    frames: list[list[str]] = []
    current: list[str] = []
    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if _FRAME_HEADER_RE.match(line):
            if current:
                frames.append(current)
            current = [line]
        else:
            if current:
                current.append(line)
    if current:
        frames.append(current)
    return frames


def _first_match(pattern: re.Pattern[str], lines: list[str]) -> str | None:
    for line in lines:
        match = pattern.search(line)
        if match:
            return match.group(1).strip()
    return None


def _frame_number(frame_lines: list[str]) -> str | None:
    if not frame_lines:
        return None
    match = _FRAME_NUMBER_RE.match(frame_lines[0])
    if match:
        return match.group(1)
    return None


def _determine_direction(frame_lines: list[str], amf_ip: str) -> str:
    for line in frame_lines:
        match = _IP_LINE_RE.search(line)
        if match:
            src, dst = match.group(1), match.group(2)
            if dst == amf_ip:
                return "gNB->AMF"
            if src == amf_ip:
                return "AMF->gNB"
            return f"{src}->{dst}"
    return "unknown"


def extract_trace_from_tshark_text(
    text: str,
    *,
    procedure_name: str = "Captured NGAP Trace",
    description: str = "",
    amf_ip: str = "127.0.0.5",
) -> ProcedureTrace:
    frames = _split_frames(text.splitlines())
    messages: list[Message] = []

    for frame in frames:
        ngap_type = _first_match(_NGAP_TYPE_RE, frame)
        if not ngap_type:
            continue

        ngap_fields = {}
        amf_ue = _first_match(_AMF_UE_ID_RE, frame)
        ran_ue = _first_match(_RAN_UE_ID_RE, frame)
        tac = _first_match(_TAC_RE, frame)
        if amf_ue:
            ngap_fields["AMF_UE_NGAP_ID"] = amf_ue
        if ran_ue:
            ngap_fields["RAN_UE_NGAP_ID"] = ran_ue
        if tac:
            ngap_fields["TAC"] = tac

        nas_message_type = (
            _first_match(_NAS_MM_RE, frame)
            or _first_match(_NAS_SM_RE, frame)
            or _first_match(_NAS_GENERIC_MSG_RE, frame)
        )
        security_header_type = _first_match(_SEC_HDR_RE, frame)
        nas = None
        if nas_message_type or security_header_type:
            nas = {"fields": {}}
            if nas_message_type:
                nas["message_type"] = nas_message_type
            if security_header_type:
                nas["security_header_type"] = security_header_type

        messages.append(
            Message(
                id=len(messages) + 1,
                direction=_determine_direction(frame, amf_ip),
                protocol="NGAP",
                message_type=ngap_type,
                ngap_fields=ngap_fields,
                nas=nas,
                metadata={
                    "source": "tshark-text",
                    "frame_number": _frame_number(frame),
                },
            )
        )

    return ProcedureTrace(
        procedure=procedure_name,
        description=description or "Extracted from tshark -V NGAP decode output.",
        messages=messages,
    )


def _walk_key_values(obj, key: str, out: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, str):
                out.append(v)
            _walk_key_values(v, key, out)
    elif isinstance(obj, list):
        for item in obj:
            _walk_key_values(item, key, out)


def augment_trace_with_tshark_json(
    trace: ProcedureTrace,
    tshark_json_text: str,
) -> ProcedureTrace:
    data = json.loads(tshark_json_text)

    ngap_frames = []
    for frame in data:
        layers = frame.get("_source", {}).get("layers", {})
        if "ngap" not in layers:
            continue

        frame_numbers: list[str] = []
        nas_pdu: list[str] = []
        pdu_session_nas_pdu: list[str] = []
        mm_message_type: list[str] = []
        security_header_type: list[str] = []

        _walk_key_values(layers, "frame.number", frame_numbers)
        _walk_key_values(layers, "ngap.NAS_PDU", nas_pdu)
        _walk_key_values(layers, "ngap.pDUSessionNAS_PDU", pdu_session_nas_pdu)
        _walk_key_values(layers, "nas-5gs.mm.message_type", mm_message_type)
        _walk_key_values(layers, "nas-5gs.security_header_type", security_header_type)

        ngap_frames.append(
            {
                "frame_number": frame_numbers[0] if frame_numbers else None,
                "nas_pdu_hex": nas_pdu[0] if nas_pdu else None,
                "pdu_session_nas_pdu_hex": pdu_session_nas_pdu[0] if pdu_session_nas_pdu else None,
                "nas_message_type_code": mm_message_type[0] if mm_message_type else None,
                "nas_security_header_code": security_header_type[0] if security_header_type else None,
            }
        )

    frame_map = {frame["frame_number"]: frame for frame in ngap_frames if frame["frame_number"]}

    cloned = ProcedureTrace.from_dict(trace.to_dict())
    augmented = 0
    for i, message in enumerate(cloned.messages):
        frame = None
        frame_number = message.metadata.get("frame_number")
        if frame_number and frame_number in frame_map:
            frame = frame_map[frame_number]
        elif i < len(ngap_frames):
            frame = ngap_frames[i]

        if frame is None:
            continue

        if frame.get("frame_number"):
            message.metadata["frame_number"] = frame["frame_number"]
        if frame["nas_pdu_hex"] or frame["pdu_session_nas_pdu_hex"]:
            if message.nas is None:
                message.nas = {"fields": {}}
            if frame["nas_pdu_hex"]:
                message.nas["raw_pdu_hex"] = frame["nas_pdu_hex"]
            if frame["pdu_session_nas_pdu_hex"]:
                message.nas["raw_pdu_hex"] = frame["pdu_session_nas_pdu_hex"]
            if frame["nas_message_type_code"]:
                message.nas["message_type_code"] = frame["nas_message_type_code"]
            if frame["nas_security_header_code"]:
                message.nas["security_header_type_code"] = frame["nas_security_header_code"]
        augmented += 1

    cloned.mutation_history.append(
        {
            "mutation": "augment-with-tshark-json",
            "frames_seen": len(ngap_frames),
            "messages_augmented": augmented,
        }
    )
    return cloned
