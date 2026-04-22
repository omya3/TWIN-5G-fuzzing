from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class NasFieldGenerationRule:
    family_name: str
    strategy: str
    priority: str
    rationale: str
    target: str = ""
    candidate_values: tuple[str, ...] = field(default_factory=tuple)
    operators: tuple[str, ...] = field(default_factory=tuple)
    baseline_anchor: str = ""


def generate_mutation_operators(
    *,
    field_name: str,
    field_kind: str,
    baseline_value: str,
    rule: NasFieldGenerationRule,
) -> tuple[str, ...]:
    if rule.strategy == "enum-substitution":
        if field_kind != "enum":
            raise ValueError(
                f"Field '{field_name}' uses enum-substitution but has kind '{field_kind}'."
            )
        if field_name == "message_type":
            return tuple(
                f"replace {baseline_value} with {value}" for value in rule.candidate_values
            )
        return tuple(
            f"set {field_name.replace('_', ' ')} {baseline_value} -> {value}"
            for value in rule.candidate_values
        )

    if rule.strategy == "length-boundary":
        if field_kind != "length":
            raise ValueError(
                f"Field '{field_name}' uses length-boundary but has kind '{field_kind}'."
            )
        return tuple(
            f"set length {baseline_value} -> {value}" for value in rule.candidate_values
        )

    if rule.strategy == "identity-tail-bcd-substitution":
        if field_kind != "identity":
            raise ValueError(
                f"Field '{field_name}' uses identity-tail-bcd-substitution but has kind '{field_kind}'."
            )
        anchor = rule.baseline_anchor or baseline_value
        return tuple(
            f"inject invalid BCD digit in tail octet {anchor} -> {value}"
            for value in rule.candidate_values
        )

    if rule.strategy == "bitfield-substitution":
        if field_kind != "bitfield":
            raise ValueError(
                f"Field '{field_name}' uses bitfield-substitution but has kind '{field_kind}'."
            )
        return tuple(f"replace {baseline_value} with {value}" for value in rule.candidate_values)

    if rule.strategy == "named-operators":
        return rule.operators

    if rule.strategy == "optional-ie-omit":
        if field_kind not in {"optional_tlv", "tlv_payload"}:
            raise ValueError(
                f"Field '{field_name}' uses optional-ie-omit but has kind '{field_kind}'."
            )
        return ("omit IE entirely",)

    if rule.strategy == "optional-ie-duplicate":
        if field_kind not in {"optional_tlv", "tlv_payload"}:
            raise ValueError(
                f"Field '{field_name}' uses optional-ie-duplicate but has kind '{field_kind}'."
            )
        return ("duplicate IE",)

    if rule.strategy == "optional-ie-bad-length":
        if field_kind not in {"optional_tlv", "tlv_payload"}:
            raise ValueError(
                f"Field '{field_name}' uses optional-ie-bad-length but has kind '{field_kind}'."
            )
        labels = rule.candidate_values or ("invalid",)
        return tuple(f"{label} length" for label in labels)

    if rule.strategy == "payload-truncation":
        if field_kind not in {"optional_tlv", "tlv_payload", "identity", "payload"}:
            raise ValueError(
                f"Field '{field_name}' uses payload-truncation but has kind '{field_kind}'."
            )
        return ("truncation",)

    if rule.strategy == "bitfield-reserved-bits":
        if field_kind not in {"bitfield", "tlv_payload"}:
            raise ValueError(
                f"Field '{field_name}' uses bitfield-reserved-bits but has kind '{field_kind}'."
            )
        return ("reserved bits set",)

    raise ValueError(f"Unsupported field-generation strategy '{rule.strategy}'.")
