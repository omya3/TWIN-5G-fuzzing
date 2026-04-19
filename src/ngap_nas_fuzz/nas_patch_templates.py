from __future__ import annotations


class NasPatchTemplateError(ValueError):
    """Raised when a generic NAS patch template cannot be applied safely."""


def _validate_offset(octets: list[int], offset: int, width: int) -> None:
    if offset < 0:
        raise NasPatchTemplateError(f"Offset {offset} cannot be negative.")
    if width < 0:
        raise NasPatchTemplateError(f"Width {width} cannot be negative.")
    if offset + width > len(octets):
        raise NasPatchTemplateError(
            f"Patch range offset={offset} width={width} exceeds octet length {len(octets)}."
        )


def patch_byte(octets: list[int], offset: int, new_value: int) -> int:
    _validate_offset(octets, offset, 1)
    if new_value < 0 or new_value > 0xFF:
        raise NasPatchTemplateError(f"Byte value 0x{new_value:x} is outside 0x00..0xff.")
    old_value = octets[offset]
    octets[offset] = new_value
    return old_value


def patch_word_be(octets: list[int], offset: int, new_value: int) -> int:
    _validate_offset(octets, offset, 2)
    if new_value < 0 or new_value > 0xFFFF:
        raise NasPatchTemplateError(f"Word value 0x{new_value:x} is outside 0x0000..0xffff.")
    old_value = (octets[offset] << 8) | octets[offset + 1]
    octets[offset] = (new_value >> 8) & 0xFF
    octets[offset + 1] = new_value & 0xFF
    return old_value


def replace_span(octets: list[int], offset: int, replacement: list[int]) -> list[int]:
    _validate_offset(octets, offset, len(replacement))
    old_span = list(octets[offset : offset + len(replacement)])
    octets[offset : offset + len(replacement)] = replacement
    return old_span


def remove_span(octets: list[int], offset: int, length: int) -> list[int]:
    _validate_offset(octets, offset, length)
    removed = list(octets[offset : offset + length])
    del octets[offset : offset + length]
    return removed


def duplicate_span(octets: list[int], offset: int, length: int, *, insert_offset: int | None = None) -> list[int]:
    _validate_offset(octets, offset, length)
    span = list(octets[offset : offset + length])
    destination = offset + length if insert_offset is None else insert_offset
    if destination < 0 or destination > len(octets):
        raise NasPatchTemplateError(
            f"Insert offset {destination} is outside the allowed range 0..{len(octets)}."
        )
    octets[destination:destination] = span
    return span


def tlv_total_length(length_octets: int, value_length: int) -> int:
    if length_octets < 0 or value_length < 0:
        raise NasPatchTemplateError("TLV length fields cannot be negative.")
    return 1 + length_octets + value_length
