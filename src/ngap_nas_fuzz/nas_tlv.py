from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedTlv:
    tag: int
    start_offset: int
    length_octets: int
    value_offset: int
    value_length: int
    value_octets: tuple[int, ...]


@dataclass(frozen=True)
class ParsedTlvSequence:
    tlvs: tuple[ParsedTlv, ...]
    warnings: tuple[str, ...]


def format_octets(octets: list[int] | tuple[int, ...]) -> str:
    return ":".join(f"{octet:02x}" for octet in octets)


def parse_tlv_sequence(
    octets: list[int],
    *,
    start_offset: int,
) -> ParsedTlvSequence:
    if start_offset < 0:
        raise ValueError(f"start_offset {start_offset} cannot be negative.")
    if start_offset > len(octets):
        raise ValueError(
            f"start_offset {start_offset} is outside octet length {len(octets)}."
        )

    tlvs: list[ParsedTlv] = []
    warnings: list[str] = []
    cursor = start_offset

    while cursor < len(octets):
        if cursor + 1 >= len(octets):
            warnings.append(
                f"trailing TLV at offset {cursor} is truncated before its length octet"
            )
            break

        tag = octets[cursor]
        value_length = octets[cursor + 1]
        value_offset = cursor + 2
        end_offset = value_offset + value_length
        if end_offset > len(octets):
            warnings.append(
                f"trailing TLV tag 0x{tag:02x} at offset {cursor} is truncated "
                f"(declared length {value_length}, only {len(octets) - value_offset} octets remain)"
            )
            break

        tlvs.append(
            ParsedTlv(
                tag=tag,
                start_offset=cursor,
                length_octets=1,
                value_offset=value_offset,
                value_length=value_length,
                value_octets=tuple(octets[value_offset:end_offset]),
            )
        )
        cursor = end_offset

    return ParsedTlvSequence(tlvs=tuple(tlvs), warnings=tuple(warnings))


def find_tlv_by_tag(
    octets: list[int],
    *,
    start_offset: int,
    tag: int,
) -> ParsedTlv | None:
    sequence = parse_tlv_sequence(octets, start_offset=start_offset)
    for tlv in sequence.tlvs:
        if tlv.tag == tag:
            return tlv
    return None
