from __future__ import annotations

from dataclasses import dataclass, field, replace

from .nas_field_rules import NasFieldGenerationRule, generate_mutation_operators


@dataclass(frozen=True)
class NasMutationFamily:
    name: str
    target: str
    mutation_operators: tuple[str, ...]
    priority: str
    rationale: str


@dataclass(frozen=True)
class NasFieldDefinition:
    name: str
    kind: str
    mandatory: bool
    baseline_value: str
    location_hint: str
    notes: str
    iei_tag: str = ""
    generation_rules: tuple[NasFieldGenerationRule, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class NasMessageProfile:
    message_name: str
    message_type_code: str
    direction: str
    procedure_phase: str
    expected_precondition: str
    baseline_signature: str = ""
    field_definitions: tuple[NasFieldDefinition, ...] = field(default_factory=tuple)
    mutation_families: tuple[NasMutationFamily, ...] = field(default_factory=tuple)


REGISTRATION_REQUEST = NasMessageProfile(
    message_name="Registration Request",
    message_type_code="0x41",
    direction="UE -> AMF",
    procedure_phase="initial registration entry point",
    expected_precondition="first uplink NAS message in normal registration",
    baseline_signature="7e 00 41 79 00 0d ...",
    field_definitions=(
        NasFieldDefinition(
            name="security_header",
            kind="enum",
            mandatory=True,
            baseline_value="0x00",
            location_hint="byte 1 in plain NAS header after EPD 0x7e",
            notes="plain 5GS mobility-management NAS header in the baseline Registration Request",
            generation_rules=(
                NasFieldGenerationRule(
                    family_name="security-header mutation",
                    strategy="enum-substitution",
                    target="plain NAS security header field",
                    priority="high",
                    rationale="tests whether Open5GS rejects invalid protection context assumptions early",
                    candidate_values=("0x01", "0x02", "0x03", "0x04", "0x0f"),
                ),
            ),
        ),
        NasFieldDefinition(
            name="message_type",
            kind="enum",
            mandatory=True,
            baseline_value="0x41",
            location_hint="byte 2 in baseline signature 7e 00 41",
            notes="identifies the message as Registration Request and is ideal for early semantic substitution tests",
            generation_rules=(
                NasFieldGenerationRule(
                    family_name="message-type substitution",
                    strategy="enum-substitution",
                    target="5GMM message type octet",
                    priority="high",
                    rationale="tests whether the AMF safely rejects a wrong first NAS semantic type",
                    candidate_values=("0x5c", "0x56", "0x57", "0x5d", "0x5e", "0x00"),
                ),
            ),
        ),
        NasFieldDefinition(
            name="registration_type_and_ngksi",
            kind="bitfield",
            mandatory=True,
            baseline_value="0x79",
            location_hint="byte 3 in baseline signature 7e 00 41 79",
            notes="combined half-octet semantics make it useful later for state and encoding mutations",
            generation_rules=(
                NasFieldGenerationRule(
                    family_name="registration-type-and-ngksi mutation",
                    strategy="bitfield-substitution",
                    target="registration type / ngKSI combined octet",
                    priority="high",
                    rationale="tests whether Open5GS safely handles inconsistent registration-type and ngKSI combinations inside an otherwise valid Registration Request",
                    candidate_values=("0x00", "0x71", "0x7f", "0xf9"),
                ),
            ),
        ),
        NasFieldDefinition(
            name="mobile_identity_length",
            kind="length",
            mandatory=True,
            baseline_value="0x000d",
            location_hint="bytes 4-5 in baseline signature 7e 00 41 79 00 0d",
            notes="two-byte length for 5GS mobile identity and the strongest current deep-decoder target",
            generation_rules=(
                NasFieldGenerationRule(
                    family_name="mobile-identity length corruption",
                    strategy="length-boundary",
                    target="5GS mobile identity length field",
                    priority="high",
                    rationale="drives decoding deeper into Registration Request before failing on a mandatory IE",
                    candidate_values=("0x0000", "0x0001", "0x000c", "0x00ff"),
                ),
            ),
        ),
        NasFieldDefinition(
            name="mobile_identity_value",
            kind="identity",
            mandatory=True,
            baseline_value="SUCI payload body",
            location_hint="immediately follows mobile_identity_length",
            notes="contains UE identity encoding and is suited for truncation, bad digits, and type-bit corruption",
            generation_rules=(
                NasFieldGenerationRule(
                    family_name="mobile-identity value corruption",
                    strategy="identity-tail-bcd-substitution",
                    target="SUCI / mobile identity contents",
                    priority="high",
                    rationale="tests parser behavior for malformed identity encoding without changing the outer message type",
                    baseline_anchor="0x2e",
                    candidate_values=("0x2a", "0x2b", "0x2c", "0x2d"),
                ),
                NasFieldGenerationRule(
                    family_name="mobile-identity value corruption",
                    strategy="named-operators",
                    target="SUCI / mobile identity contents",
                    priority="high",
                    rationale="tests parser behavior for malformed identity encoding without changing the outer message type",
                    operators=("toggle identity type bits inconsistently",),
                ),
            ),
        ),
        NasFieldDefinition(
            name="requested_nssai",
            kind="optional_tlv",
            mandatory=False,
            baseline_value="optional Requested NSSAI IE when present",
            location_hint="later optional TLV region in Registration Request body",
            notes="good target for optional-IE length, value, and duplication mutations",
            iei_tag="0x2f",
            generation_rules=(
                NasFieldGenerationRule(
                    family_name="requested NSSAI corruption",
                    strategy="optional-ie-bad-length",
                    target="Requested NSSAI IE",
                    priority="medium",
                    rationale="tests optional IE parsing and policy handling inside registration setup",
                    candidate_values=("invalid",),
                ),
                NasFieldGenerationRule(
                    family_name="requested NSSAI corruption",
                    strategy="optional-ie-duplicate",
                    target="Requested NSSAI IE",
                    priority="medium",
                    rationale="tests duplicate optional IE handling inside registration setup",
                ),
                NasFieldGenerationRule(
                    family_name="requested NSSAI corruption",
                    strategy="optional-ie-omit",
                    target="Requested NSSAI IE",
                    priority="medium",
                    rationale="tests optional IE omission handling inside registration setup",
                ),
                NasFieldGenerationRule(
                    family_name="requested NSSAI corruption",
                    strategy="named-operators",
                    target="Requested NSSAI IE",
                    priority="medium",
                    rationale="tests optional IE parsing and policy handling inside registration setup",
                    operators=(
                        "unsupported SST/SD combination",
                    ),
                ),
            ),
        ),
        NasFieldDefinition(
            name="fivegmm_capability",
            kind="tlv_payload",
            mandatory=False,
            baseline_value="UE 5GMM capability IE when present",
            location_hint="later optional TLV region after core mandatory fields",
            notes="useful for deeper parser exploration after the outer Registration Request shell is accepted",
            iei_tag="0x10",
            generation_rules=(
                NasFieldGenerationRule(
                    family_name="5GMM capability corruption",
                    strategy="payload-truncation",
                    target="5GMM capability IE",
                    priority="medium",
                    rationale="targets deeper decoder logic after the core begins parsing a valid Registration Request shell",
                ),
                NasFieldGenerationRule(
                    family_name="5GMM capability corruption",
                    strategy="optional-ie-bad-length",
                    target="5GMM capability IE",
                    priority="medium",
                    rationale="targets deeper decoder logic after the core begins parsing a valid Registration Request shell",
                    candidate_values=("oversized",),
                ),
                NasFieldGenerationRule(
                    family_name="5GMM capability corruption",
                    strategy="bitfield-reserved-bits",
                    target="5GMM capability IE",
                    priority="medium",
                    rationale="targets deeper decoder logic after the core begins parsing a valid Registration Request shell",
                ),
                NasFieldGenerationRule(
                    family_name="5GMM capability corruption",
                    strategy="optional-ie-omit",
                    target="5GMM capability IE",
                    priority="medium",
                    rationale="tests optional IE omission handling after the Registration Request shell is accepted",
                ),
                NasFieldGenerationRule(
                    family_name="5GMM capability corruption",
                    strategy="named-operators",
                    target="5GMM capability IE",
                    priority="medium",
                    rationale="targets deeper decoder logic after the core begins parsing a valid Registration Request shell",
                    operators=(),
                ),
            ),
        ),
    ),
    mutation_families=(
        NasMutationFamily(
            name="message-type substitution",
            target="5GMM message type octet",
            mutation_operators=(
                "replace 0x41 with 0x5c",
                "replace 0x41 with 0x56",
                "replace 0x41 with 0x57",
                "replace 0x41 with 0x5d",
                "replace 0x41 with 0x00",
            ),
            priority="high",
            rationale="tests whether the AMF safely rejects a wrong first NAS semantic type",
        ),
        NasMutationFamily(
            name="security-header mutation",
            target="plain NAS security header field",
            mutation_operators=(
                "set security header 0x00 -> 0x01",
                "set security header 0x00 -> 0x02",
                "set security header 0x00 -> 0x03",
                "set security header 0x00 -> 0x04",
                "set security header 0x00 -> 0x0f",
            ),
            priority="high",
            rationale="tests whether Open5GS rejects invalid protection context assumptions early",
        ),
        NasMutationFamily(
            name="mobile-identity length corruption",
            target="5GS mobile identity length field",
            mutation_operators=(
                "set length 0x000d -> 0x0000",
                "set length 0x000d -> 0x0001",
                "set length 0x000d -> 0x000c",
                "set length 0x000d -> 0x00ff",
            ),
            priority="high",
            rationale="drives decoding deeper into Registration Request before failing on a mandatory IE",
        ),
        NasMutationFamily(
            name="mobile-identity value corruption",
            target="SUCI / mobile identity contents",
            mutation_operators=(
                "inject invalid BCD digit in tail octet 0x2e -> 0x2a",
                "toggle identity type bits inconsistently",
            ),
            priority="high",
            rationale="tests parser behavior for malformed identity encoding without changing the outer message type",
        ),
        NasMutationFamily(
            name="requested NSSAI corruption",
            target="Requested NSSAI IE",
            mutation_operators=(
                "invalid length",
                "unsupported SST/SD combination",
                "duplicate NSSAI entries",
            ),
            priority="medium",
            rationale="tests optional IE parsing and policy handling inside registration setup",
        ),
        NasMutationFamily(
            name="5GMM capability corruption",
            target="5GMM capability IE",
            mutation_operators=(
                "truncation",
                "oversized length",
                "reserved bits set",
            ),
            priority="medium",
            rationale="targets deeper decoder logic after the core begins parsing a valid Registration Request shell",
        ),
    ),
)

IDENTITY_RESPONSE = NasMessageProfile(
    message_name="Identity Response",
    message_type_code="0x5c",
    direction="UE -> AMF",
    procedure_phase="identity procedure",
    expected_precondition="should appear only after Identity Request from the AMF",
    baseline_signature="7e 00 5c ...",
    mutation_families=(
        NasMutationFamily(
            name="wrong-state delivery",
            target="message timing / procedure state",
            mutation_operators=(
                "send as first NAS message",
                "send after wrong downlink request",
            ),
            priority="high",
            rationale="tests whether the AMF rejects a response message that appears without a triggering request",
        ),
        NasMutationFamily(
            name="identity payload corruption",
            target="mobile identity value",
            mutation_operators=(
                "invalid BCD",
                "unsupported identity type",
                "truncated identity",
            ),
            priority="high",
            rationale="tests the identity-specific decoder path once the AMF expects an identity response",
        ),
        NasMutationFamily(
            name="length inconsistency",
            target="identity length field",
            mutation_operators=(
                "zero length",
                "shorter-than-body length",
                "longer-than-body length",
            ),
            priority="medium",
            rationale="checks whether length validation is robust in the identity-response parser",
        ),
    ),
)

AUTHENTICATION_RESPONSE = NasMessageProfile(
    message_name="Authentication Response",
    message_type_code="0x57",
    direction="UE -> AMF",
    procedure_phase="authentication procedure",
    expected_precondition="should appear only after Authentication Request",
    baseline_signature="7e 00 57 ...",
    mutation_families=(
        NasMutationFamily(
            name="wrong-state delivery",
            target="message timing / procedure state",
            mutation_operators=(
                "send as first NAS message",
                "send before Authentication Request",
            ),
            priority="high",
            rationale="tests whether the AMF safely rejects authentication completion outside the expected state",
        ),
        NasMutationFamily(
            name="authentication parameter corruption",
            target="RES*/authentication response parameter",
            mutation_operators=(
                "truncate response parameter",
                "oversized length",
                "all-zero response value",
            ),
            priority="medium",
            rationale="tests deeper NAS parsing and authentication-message validation",
        ),
        NasMutationFamily(
            name="extra trailing payload",
            target="message body length",
            mutation_operators=(
                "append extra bytes",
                "leave inconsistent length metadata",
            ),
            priority="medium",
            rationale="checks whether the AMF tolerates or safely rejects authentication responses with inconsistent body layout",
        ),
    ),
)

SECURITY_MODE_COMPLETE = NasMessageProfile(
    message_name="Security Mode Complete",
    message_type_code="0x5e",
    direction="UE -> AMF",
    procedure_phase="security mode completion",
    expected_precondition="should appear after Security Mode Command and usually under a protected NAS header",
    baseline_signature="protected-header ... 0x5e ...",
    mutation_families=(
        NasMutationFamily(
            name="wrong-state delivery",
            target="message timing / procedure state",
            mutation_operators=(
                "send as first NAS message",
                "send before Security Mode Command",
            ),
            priority="high",
            rationale="tests state tracking and safe rejection of security-completion messages in the wrong phase",
        ),
        NasMutationFamily(
            name="security-header inconsistency",
            target="security header vs message semantics",
            mutation_operators=(
                "send with plain header when protected header is expected",
                "send with mismatched protected header value",
            ),
            priority="high",
            rationale="targets the boundary between NAS protection handling and inner message decoding",
        ),
        NasMutationFamily(
            name="IMEISV/requested IE corruption",
            target="optional post-security IE payloads",
            mutation_operators=(
                "invalid optional IE length",
                "duplicate optional IE",
                "unknown optional IE tag",
            ),
            priority="medium",
            rationale="tests optional-IE parsing in a later protected message type",
        ),
    ),
)

PDU_SESSION_ESTABLISHMENT_REQUEST = NasMessageProfile(
    message_name="PDU Session Establishment Request",
    message_type_code="N/A (inside 5GSM payload)",
    direction="UE -> AMF/SMF path",
    procedure_phase="post-registration session setup",
    expected_precondition="should appear after successful registration and session initiation",
    baseline_signature="5GSM payload nested inside NAS transport",
    mutation_families=(
        NasMutationFamily(
            name="wrong-state delivery",
            target="message timing / procedure state",
            mutation_operators=(
                "send before registration completes",
                "send without valid session context",
            ),
            priority="medium",
            rationale="tests whether the core enforces session setup only after valid registration state exists",
        ),
        NasMutationFamily(
            name="session IE corruption",
            target="DNN / S-NSSAI / session type IEs",
            mutation_operators=(
                "truncate DNN",
                "invalid session type value",
                "bad S-NSSAI encoding",
            ),
            priority="medium",
            rationale="extends coverage beyond 5GMM into later NAS session-related content",
        ),
    ),
)


NAS_MESSAGE_PROFILES: tuple[NasMessageProfile, ...] = (
    REGISTRATION_REQUEST,
    IDENTITY_RESPONSE,
    AUTHENTICATION_RESPONSE,
    SECURITY_MODE_COMPLETE,
    PDU_SESSION_ESTABLISHMENT_REQUEST,
)


def _dedupe_operators(operators: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for operator in operators:
        if operator in seen:
            continue
        seen.add(operator)
        ordered.append(operator)
    return tuple(ordered)


def _family_from_generation_rule(
    field_def: NasFieldDefinition,
    rule: NasFieldGenerationRule,
) -> NasMutationFamily:
    operators = generate_mutation_operators(
        field_name=field_def.name,
        field_kind=field_def.kind,
        baseline_value=field_def.baseline_value,
        rule=rule,
    )
    return NasMutationFamily(
        name=rule.family_name,
        target=rule.target or field_def.name.replace("_", " "),
        mutation_operators=_dedupe_operators(operators),
        priority=rule.priority,
        rationale=rule.rationale,
    )


def _generated_mutation_families(profile: NasMessageProfile) -> tuple[NasMutationFamily, ...]:
    families: list[NasMutationFamily] = []
    for field_def in profile.field_definitions:
        for rule in field_def.generation_rules:
            family = _family_from_generation_rule(field_def, rule)
            if family.mutation_operators:
                families.append(family)
    return tuple(families)


def _merge_mutation_families(
    manual_families: tuple[NasMutationFamily, ...],
    generated_families: tuple[NasMutationFamily, ...],
) -> tuple[NasMutationFamily, ...]:
    merged: list[NasMutationFamily] = list(manual_families)
    index_by_name = {family.name: idx for idx, family in enumerate(merged)}

    for family in generated_families:
        existing_index = index_by_name.get(family.name)
        if existing_index is None:
            merged.append(
                replace(family, mutation_operators=_dedupe_operators(family.mutation_operators))
            )
            index_by_name[family.name] = len(merged) - 1
            continue

        existing = merged[existing_index]
        merged[existing_index] = replace(
            existing,
            mutation_operators=_dedupe_operators(
                existing.mutation_operators + family.mutation_operators
            ),
        )

    return tuple(merged)


def _expand_generated_families(profile: NasMessageProfile) -> NasMessageProfile:
    generated_families = _generated_mutation_families(profile)
    if not generated_families:
        return profile

    return replace(
        profile,
        mutation_families=_merge_mutation_families(profile.mutation_families, generated_families),
    )


def get_nas_message_profiles() -> tuple[NasMessageProfile, ...]:
    return tuple(_expand_generated_families(profile) for profile in NAS_MESSAGE_PROFILES)


def get_nas_message_profile(message_name: str) -> NasMessageProfile:
    for profile in get_nas_message_profiles():
        if profile.message_name == message_name:
            return profile
    raise KeyError(f"Unknown NAS message profile '{message_name}'.")


def get_nas_field_definition(message_name: str, field_name: str) -> NasFieldDefinition:
    profile = get_nas_message_profile(message_name)
    for field_def in profile.field_definitions:
        if field_def.name == field_name:
            return field_def
    raise KeyError(f"Unknown field '{field_name}' for NAS message '{message_name}'.")


def get_optional_iei_tag_map(message_name: str) -> dict[int, str]:
    profile = get_nas_message_profile(message_name)
    tag_map: dict[int, str] = {}
    for field_def in profile.field_definitions:
        if not field_def.iei_tag:
            continue
        tag_map[int(field_def.iei_tag, 16)] = field_def.name
    return tag_map
