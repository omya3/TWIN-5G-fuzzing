from __future__ import annotations

from dataclasses import dataclass, field

from .nas_catalog import NasMutationFamily, get_nas_message_profiles
from .nas_scheduler import (
    NasCampaignObservation,
    list_candidates_for_message,
    recommend_next_candidates,
    summarize_campaign_history,
)
from .nas_schema import NasFieldSchema, get_nas_message_schema


@dataclass(frozen=True)
class NasOperatorCapability:
    operator: str
    executable_now: bool
    execution_mode: str
    live_proxy_capable: bool
    proxy_mutation: str | None = None
    proxy_value: str | None = None


@dataclass(frozen=True)
class NasMutationDomain:
    message_name: str
    family_name: str
    domain_kind: str
    target: str
    priority: str
    rationale: str
    field_names: tuple[str, ...] = field(default_factory=tuple)
    field_kinds: tuple[str, ...] = field(default_factory=tuple)
    mandatory_fields: tuple[str, ...] = field(default_factory=tuple)
    location_hints: tuple[str, ...] = field(default_factory=tuple)
    locator_strategies: tuple[str, ...] = field(default_factory=tuple)
    generation_strategies: tuple[str, ...] = field(default_factory=tuple)
    action_kinds: tuple[str, ...] = field(default_factory=tuple)
    operators: tuple[NasOperatorCapability, ...] = field(default_factory=tuple)

    @property
    def operator_count(self) -> int:
        return len(self.operators)

    @property
    def reachable_operator_count(self) -> int:
        return sum(1 for operator in self.operators if operator.executable_now)

    @property
    def live_proxy_operator_count(self) -> int:
        return sum(1 for operator in self.operators if operator.live_proxy_capable)

    @property
    def execution_modes(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    operator.execution_mode
                    for operator in self.operators
                    if operator.executable_now
                }
            )
        )


@dataclass(frozen=True)
class NasDomainFrontier:
    message_name: str
    family_name: str
    operator: str
    score: int
    rationale: str
    execution_mode: str
    executable_now: bool
    live_proxy_capable: bool
    domain_kind: str
    field_names: tuple[str, ...]
    saturation: str
    total_known_operators: int
    tried_operators: int
    live_tried_operators: int
    recommendation_reasons: tuple[str, ...] = field(default_factory=tuple)
    proxy_mutation: str | None = None
    proxy_value: str | None = None


def _dedupe_preserve_order(values: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


def _matching_fields_for_family(
    *,
    message_name: str,
    family_name: str,
) -> tuple[NasFieldSchema, ...]:
    schema = get_nas_message_schema(message_name)
    normalized_family = family_name.lower()
    matches: list[NasFieldSchema] = []
    for field in schema.fields:
        if any(rule.family_name.lower() == normalized_family for rule in field.rules):
            matches.append(field)
    return tuple(matches)


def _domain_kind_for_family(
    family: NasMutationFamily,
    matching_fields: tuple[NasFieldSchema, ...],
) -> str:
    if matching_fields:
        return "field"
    if family.name == "wrong-state delivery":
        return "procedure-state"
    return "family-only"


def _domain_from_family(
    *,
    message_name: str,
    family: NasMutationFamily,
) -> NasMutationDomain:
    matching_fields = _matching_fields_for_family(
        message_name=message_name,
        family_name=family.name,
    )
    domain_kind = _domain_kind_for_family(family, matching_fields)
    mandatory_fields = tuple(
        field.field_name for field in matching_fields if field.mandatory
    )
    operators = []
    for candidate in list_candidates_for_message(message_name):
        if candidate.family_name != family.name:
            continue
        operators.append(
            NasOperatorCapability(
                operator=candidate.operator,
                executable_now=candidate.executable_now,
                execution_mode=candidate.execution_mode,
                live_proxy_capable=candidate.live_proxy_capable,
                proxy_mutation=candidate.proxy_mutation,
                proxy_value=candidate.proxy_value,
            )
        )

    return NasMutationDomain(
        message_name=message_name,
        family_name=family.name,
        domain_kind=domain_kind,
        target=family.target,
        priority=family.priority,
        rationale=family.rationale,
        field_names=tuple(field.field_name for field in matching_fields),
        field_kinds=_dedupe_preserve_order([field.kind for field in matching_fields]),
        mandatory_fields=mandatory_fields,
        location_hints=_dedupe_preserve_order([field.location_hint for field in matching_fields]),
        locator_strategies=_dedupe_preserve_order(
            [
                field.locator.strategy
                for field in matching_fields
                if field.locator is not None
            ]
        ),
        generation_strategies=_dedupe_preserve_order(
            [
                strategy
                for field in matching_fields
                for strategy in field.generation_strategies
                if any(rule.family_name == family.name for rule in field.rules)
            ]
        )
        if matching_fields
        else (
            ("procedure-state",)
            if domain_kind == "procedure-state"
            else tuple()
        ),
        action_kinds=_dedupe_preserve_order(
            [
                action
                for field in matching_fields
                for action in field.action_kinds
                if any(rule.family_name == family.name for rule in field.rules)
            ]
        )
        if matching_fields
        else (
            ("wrong-state-delivery",)
            if domain_kind == "procedure-state"
            else tuple()
        ),
        operators=tuple(operators),
    )


def explore_nas_mutation_domains(
    *,
    message_name: str | None = None,
    reachable_only: bool = False,
) -> list[NasMutationDomain]:
    profiles = [
        profile
        for profile in get_nas_message_profiles()
        if message_name is None or profile.message_name == message_name
    ]
    domains: list[NasMutationDomain] = []
    for profile in profiles:
        for family in profile.mutation_families:
            domain = _domain_from_family(message_name=profile.message_name, family=family)
            if reachable_only and domain.reachable_operator_count == 0:
                continue
            domains.append(domain)
    domains.sort(
        key=lambda item: (
            item.message_name,
            -item.live_proxy_operator_count,
            -item.reachable_operator_count,
            item.family_name,
        )
    )
    return domains


def recommend_nas_domain_frontiers(
    history: list[NasCampaignObservation] | None = None,
    *,
    message_name: str | None = None,
    limit: int = 10,
    executable_only: bool = True,
    fresh_only: bool = False,
) -> list[NasDomainFrontier]:
    history = history or []
    profiles = [
        profile
        for profile in get_nas_message_profiles()
        if message_name is None or profile.message_name == message_name
    ]
    summaries = summarize_campaign_history(history, message_name=message_name)
    summary_map = {
        (summary.message_name, summary.family_name): summary
        for summary in summaries
    }
    domain_map = {
        (domain.message_name, domain.family_name): domain
        for domain in explore_nas_mutation_domains(message_name=message_name)
    }

    recommendations = []
    for profile in profiles:
        message_candidates = list_candidates_for_message(profile.message_name)
        message_limit = max(len(message_candidates), limit)
        recommendations.extend(
            recommend_next_candidates(
                profile.message_name,
                history,
                limit=message_limit,
                executable_only=executable_only,
            )
        )

    if fresh_only:
        recommendations = [
            rec for rec in recommendations if "untried operator" in rec.reasons
        ]

    recommendations.sort(
        key=lambda item: (
            -item.score,
            not item.candidate.live_proxy_capable,
            not item.candidate.executable_now,
            item.candidate.message_name,
            item.candidate.family_name,
            item.candidate.operator,
        )
    )

    frontiers: list[NasDomainFrontier] = []
    for rec in recommendations[:limit]:
        candidate = rec.candidate
        summary = summary_map.get((candidate.message_name, candidate.family_name))
        domain = domain_map.get((candidate.message_name, candidate.family_name))
        frontiers.append(
            NasDomainFrontier(
                message_name=candidate.message_name,
                family_name=candidate.family_name,
                operator=candidate.operator,
                score=rec.score,
                rationale=candidate.rationale,
                execution_mode=candidate.execution_mode,
                executable_now=candidate.executable_now,
                live_proxy_capable=candidate.live_proxy_capable,
                domain_kind=domain.domain_kind if domain is not None else "unknown",
                field_names=domain.field_names if domain is not None else tuple(),
                saturation=summary.saturation if summary is not None else "unexplored",
                total_known_operators=(
                    summary.total_known_operators if summary is not None else 0
                ),
                tried_operators=summary.tried_operators if summary is not None else 0,
                live_tried_operators=summary.live_tried_operators if summary is not None else 0,
                recommendation_reasons=tuple(rec.reasons),
                proxy_mutation=candidate.proxy_mutation,
                proxy_value=candidate.proxy_value,
            )
        )
    return frontiers
