from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .nas_execution_bridge import observation_runtime_key, resolve_operator_execution
from .nas_catalog import NasMessageProfile, get_nas_message_profiles


class NasSchedulerError(ValueError):
    """Raised when a NAS scheduler request cannot be satisfied."""


RESULT_EARLY_SEMANTIC_REJECT = "early-semantic-reject"
RESULT_DEEP_DECODER_FAILURE = "deep-decoder-failure"
RESULT_TIMEOUT_RETRY = "timeout-retry"
RESULT_UNEXPECTED_ACCEPT = "unexpected-accept"
RESULT_AMF_CRASH = "amf-crash"
RESULT_PROXY_CRASH = "proxy-crash"
RESULT_SIMULATION_ARTIFACT = "simulation-artifact"

ALL_RESULT_CLASSES = (
    RESULT_EARLY_SEMANTIC_REJECT,
    RESULT_DEEP_DECODER_FAILURE,
    RESULT_TIMEOUT_RETRY,
    RESULT_UNEXPECTED_ACCEPT,
    RESULT_AMF_CRASH,
    RESULT_PROXY_CRASH,
    RESULT_SIMULATION_ARTIFACT,
)

PRIORITY_WEIGHT = {
    "high": 30,
    "medium": 20,
    "low": 10,
}

RESULT_WEIGHT = {
    RESULT_EARLY_SEMANTIC_REJECT: 0,
    RESULT_DEEP_DECODER_FAILURE: 15,
    RESULT_TIMEOUT_RETRY: 8,
    RESULT_UNEXPECTED_ACCEPT: 20,
    RESULT_AMF_CRASH: 25,
    RESULT_PROXY_CRASH: 12,
    RESULT_SIMULATION_ARTIFACT: 0,
}

FAMILY_CHARACTERIZATION_PENALTY_STEP = 4
FAMILY_CHARACTERIZATION_PENALTY_CAP = 16
FAMILY_DIVERSE_OUTCOME_REPEAT_PENALTY = 24
FAMILY_LIKELY_SATURATED_PENALTY = 18
FAMILY_DIVERSE_BEHAVIOR_BONUS = 6


@dataclass(frozen=True)
class NasMutationCandidate:
    message_name: str
    message_type_code: str
    family_name: str
    operator: str
    priority: str
    rationale: str
    executable_now: bool
    live_proxy_capable: bool
    execution_mode: str
    proxy_mutation: str | None = None
    proxy_value: str | None = None


@dataclass
class NasCampaignObservation:
    message_name: str
    family_name: str
    operator: str
    result_class: str
    notes: str = ""
    proxy_mutation: str | None = None
    proxy_value: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NasCampaignObservation":
        result_class = data["result_class"]
        if result_class not in ALL_RESULT_CLASSES:
            raise NasSchedulerError(
                f"Unknown result class '{result_class}'. Expected one of: {', '.join(ALL_RESULT_CLASSES)}"
            )
        return cls(
            message_name=data["message_name"],
            family_name=data["family_name"],
            operator=data["operator"],
            result_class=result_class,
            notes=data.get("notes", ""),
            proxy_mutation=data.get("proxy_mutation"),
            proxy_value=data.get("proxy_value"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NasSchedulerRecommendation:
    candidate: NasMutationCandidate
    score: int
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class NasFamilySummary:
    message_name: str
    family_name: str
    total_known_operators: int
    executable_known_operators: int
    tried_operators: int
    result_counts: dict[str, int]
    live_result_counts: dict[str, int]
    simulation_result_counts: dict[str, int]
    live_tried_operators: int
    simulation_tried_operators: int
    dominant_result_class: str | None
    unique_result_classes: tuple[str, ...]
    saturation: str


def _profile_by_name() -> dict[str, NasMessageProfile]:
    return {profile.message_name: profile for profile in get_nas_message_profiles()}


def _normalize_message_name(message_name: str) -> str:
    lookup = _profile_by_name()
    for known_name in lookup:
        if known_name.lower() == message_name.lower():
            return known_name
    raise NasSchedulerError(f"Unknown NAS message '{message_name}'.")


def _candidate_from_operator(
    profile: NasMessageProfile,
    family_name: str,
    priority: str,
    rationale: str,
    operator: str,
) -> NasMutationCandidate:
    executable_now, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
        message_name=profile.message_name,
        family_name=family_name,
        operator=operator,
    )

    return NasMutationCandidate(
        message_name=profile.message_name,
        message_type_code=profile.message_type_code,
        family_name=family_name,
        operator=operator,
        priority=priority,
        rationale=rationale,
        executable_now=executable_now,
        live_proxy_capable=execution_mode == "proxy" and executable_now,
        execution_mode=execution_mode,
        proxy_mutation=proxy_mutation,
        proxy_value=proxy_value,
    )


def list_candidates_for_message(message_name: str) -> list[NasMutationCandidate]:
    normalized = _normalize_message_name(message_name)
    profile = _profile_by_name()[normalized]
    candidates: list[NasMutationCandidate] = []
    for family in profile.mutation_families:
        for operator in family.mutation_operators:
            candidates.append(
                _candidate_from_operator(
                    profile,
                    family.name,
                    family.priority,
                    family.rationale,
                    operator,
                )
            )
    return candidates


def list_all_candidates() -> list[NasMutationCandidate]:
    candidates: list[NasMutationCandidate] = []
    for profile in get_nas_message_profiles():
        candidates.extend(list_candidates_for_message(profile.message_name))
    return candidates


def _candidate_key(candidate: NasMutationCandidate) -> tuple[str, str, str]:
    return (candidate.message_name, candidate.family_name, candidate.operator)


def _candidate_runtime_key(candidate: NasMutationCandidate) -> tuple[str, str, str | None, str | None]:
    return (
        candidate.message_name,
        candidate.family_name,
        candidate.proxy_mutation,
        candidate.proxy_value,
    )


def _observation_runtime_key(
    entry: NasCampaignObservation,
) -> tuple[str, str, str | None, str | None] | None:
    return observation_runtime_key(
        message_name=entry.message_name,
        family_name=entry.family_name,
        operator=entry.operator,
        proxy_mutation=entry.proxy_mutation,
        proxy_value=entry.proxy_value,
    )


def _observation_operator_key(entry: NasCampaignObservation) -> tuple[str, str, str]:
    return (entry.message_name, entry.family_name, entry.operator)


def _family_saturation_label(
    *,
    total_known_operators: int,
    tried_operators: int,
    unique_result_count: int,
    dominant_result_class: str | None,
) -> str:
    if tried_operators == 0:
        return "unexplored"
    if total_known_operators > 0 and tried_operators >= total_known_operators:
        if unique_result_count == 1:
            return f"likely saturated ({dominant_result_class})"
        return "fully explored with mixed outcomes"
    if tried_operators >= 3 and unique_result_count == 1:
        return f"likely saturated ({dominant_result_class})"
    if unique_result_count >= 3:
        return "diverse behavior observed"
    if tried_operators == 1:
        return "first observation only"
    return "still under exploration"


def summarize_campaign_history(
    history: list[NasCampaignObservation] | None = None,
    *,
    message_name: str | None = None,
) -> list[NasFamilySummary]:
    history = history or []
    profiles = (
        [_profile_by_name()[_normalize_message_name(message_name)]]
        if message_name
        else list(get_nas_message_profiles())
    )

    family_candidates: dict[tuple[str, str], list[NasMutationCandidate]] = {}
    for profile in profiles:
        for candidate in list_candidates_for_message(profile.message_name):
            family_candidates.setdefault(
                (profile.message_name, candidate.family_name),
                [],
            ).append(candidate)

    relevant_history = [
        entry
        for entry in history
        if message_name is None
        or entry.message_name == _normalize_message_name(message_name)
    ]

    family_entries: dict[tuple[str, str], list[NasCampaignObservation]] = {}
    for entry in relevant_history:
        family_entries.setdefault((entry.message_name, entry.family_name), []).append(entry)

    all_family_keys = sorted(set(family_candidates) | set(family_entries))
    summaries: list[NasFamilySummary] = []
    for family_key in all_family_keys:
        candidates = family_candidates.get(family_key, [])
        entries = family_entries.get(family_key, [])

        tried_operator_keys = {_observation_operator_key(entry) for entry in entries}
        result_counts: dict[str, int] = {}
        live_result_counts: dict[str, int] = {}
        simulation_result_counts: dict[str, int] = {}
        for entry in entries:
            result_counts[entry.result_class] = result_counts.get(entry.result_class, 0) + 1
            if entry.result_class == RESULT_SIMULATION_ARTIFACT:
                simulation_result_counts[entry.result_class] = (
                    simulation_result_counts.get(entry.result_class, 0) + 1
                )
            else:
                live_result_counts[entry.result_class] = live_result_counts.get(entry.result_class, 0) + 1

        dominant_result_class = None
        if result_counts:
            dominant_result_class = sorted(
                result_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )[0][0]

        unique_result_classes = tuple(sorted(result_counts))
        total_known_operators = len({_candidate_key(candidate) for candidate in candidates})
        executable_known_operators = len(
            {_candidate_key(candidate) for candidate in candidates if candidate.executable_now}
        )
        tried_operators = len(tried_operator_keys)
        live_tried_operators = len(
            {
                _observation_operator_key(entry)
                for entry in entries
                if entry.result_class != RESULT_SIMULATION_ARTIFACT
            }
        )
        simulation_tried_operators = len(
            {
                _observation_operator_key(entry)
                for entry in entries
                if entry.result_class == RESULT_SIMULATION_ARTIFACT
            }
        )

        if live_result_counts:
            saturation = _family_saturation_label(
                total_known_operators=total_known_operators,
                tried_operators=live_tried_operators,
                unique_result_count=len(live_result_counts),
                dominant_result_class=sorted(
                    live_result_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )[0][0],
            )
        elif simulation_tried_operators:
            if executable_known_operators > 0 and simulation_tried_operators >= executable_known_operators:
                saturation = "simulation coverage complete (no live outcome yet)"
            elif simulation_tried_operators == 1:
                saturation = "first simulation artifact only"
            else:
                saturation = "simulation-only exploration"
        else:
            saturation = _family_saturation_label(
                total_known_operators=total_known_operators,
                tried_operators=tried_operators,
                unique_result_count=len(unique_result_classes),
                dominant_result_class=dominant_result_class,
            )

        summaries.append(
            NasFamilySummary(
                message_name=family_key[0],
                family_name=family_key[1],
                total_known_operators=total_known_operators,
                executable_known_operators=executable_known_operators,
                tried_operators=tried_operators,
                result_counts=result_counts,
                live_result_counts=live_result_counts,
                simulation_result_counts=simulation_result_counts,
                live_tried_operators=live_tried_operators,
                simulation_tried_operators=simulation_tried_operators,
                dominant_result_class=dominant_result_class,
                unique_result_classes=unique_result_classes,
                saturation=saturation,
            )
        )

    summaries.sort(
        key=lambda item: (
            item.message_name,
            -(item.tried_operators > 0),
            -item.tried_operators,
            item.family_name,
        )
    )
    return summaries


def recommend_next_candidates(
    message_name: str,
    history: list[NasCampaignObservation] | None = None,
    *,
    limit: int = 5,
    executable_only: bool = False,
) -> list[NasSchedulerRecommendation]:
    candidates = list_candidates_for_message(message_name)
    if executable_only:
        candidates = [candidate for candidate in candidates if candidate.live_proxy_capable]

    history = history or []
    normalized = _normalize_message_name(message_name)
    relevant_history = [entry for entry in history if entry.message_name == normalized]

    tried_exact: dict[tuple[str, str, str], list[NasCampaignObservation]] = {}
    for entry in relevant_history:
        tried_exact.setdefault(
            (entry.message_name, entry.family_name, entry.operator),
            [],
        ).append(entry)
    tried_runtime = {}
    for entry in relevant_history:
        runtime_key = _observation_runtime_key(entry)
        if runtime_key is not None:
            tried_runtime[runtime_key] = entry

    family_results: dict[str, list[str]] = {}
    family_live_results: dict[str, list[str]] = {}
    family_simulation_results: dict[str, list[str]] = {}
    family_operator_counts: dict[str, int] = {}
    family_live_operator_counts: dict[str, int] = {}
    family_simulation_operator_counts: dict[str, int] = {}
    family_unique_results: dict[str, set[str]] = {}
    family_total_known_operators: dict[str, int] = {}
    for entry in relevant_history:
        family_results.setdefault(entry.family_name, []).append(entry.result_class)
        if entry.result_class == RESULT_SIMULATION_ARTIFACT:
            family_simulation_results.setdefault(entry.family_name, []).append(entry.result_class)
        else:
            family_live_results.setdefault(entry.family_name, []).append(entry.result_class)
        family_unique_results.setdefault(entry.family_name, set()).add(entry.result_class)
    for family_name in family_results:
        family_operator_counts[family_name] = len(
            {
                _observation_operator_key(entry)
                for entry in relevant_history
                if entry.family_name == family_name
            }
        )
        family_live_operator_counts[family_name] = len(
            {
                _observation_operator_key(entry)
                for entry in relevant_history
                if entry.family_name == family_name and entry.result_class != RESULT_SIMULATION_ARTIFACT
            }
        )
        family_simulation_operator_counts[family_name] = len(
            {
                _observation_operator_key(entry)
                for entry in relevant_history
                if entry.family_name == family_name and entry.result_class == RESULT_SIMULATION_ARTIFACT
            }
        )
    for candidate in candidates:
        family_total_known_operators.setdefault(candidate.family_name, set()).add(
            _candidate_key(candidate)
        )
    family_total_known_operators = {
        family_name: len(operator_keys)
        for family_name, operator_keys in family_total_known_operators.items()
    }

    recommendations: list[NasSchedulerRecommendation] = []
    for candidate in candidates:
        score = PRIORITY_WEIGHT.get(candidate.priority, 0)
        reasons: list[str] = [f"base priority {candidate.priority}"]

        if candidate.executable_now:
            score += 8
            if candidate.execution_mode == "proxy":
                reasons.append("supported by current proxy")
            else:
                reasons.append(f"supported by current implementation via {candidate.execution_mode}")

        tried = tried_runtime.get(_candidate_runtime_key(candidate))
        if tried is None:
            exact_matches = tried_exact.get(_candidate_key(candidate), [])
            candidate_is_simulation = candidate.execution_mode == "nested-simulation"
            matching_mode = [
                entry
                for entry in exact_matches
                if (entry.result_class == RESULT_SIMULATION_ARTIFACT) == candidate_is_simulation
            ]
            if matching_mode:
                tried = matching_mode[-1]
        if tried is None:
            score += 10
            reasons.append("untried operator")
        else:
            score -= 12
            reasons.append(f"already tried with result {tried.result_class}")

        seen_family_results = family_results.get(candidate.family_name, [])
        seen_live_results = family_live_results.get(candidate.family_name, [])
        seen_simulation_results = family_simulation_results.get(candidate.family_name, [])
        seen_unique_results = family_unique_results.get(candidate.family_name, set())
        explored_operator_count = family_operator_counts.get(candidate.family_name, 0)
        explored_live_operator_count = family_live_operator_counts.get(candidate.family_name, 0)
        explored_simulation_operator_count = family_simulation_operator_counts.get(candidate.family_name, 0)
        total_known_operator_count = family_total_known_operators.get(candidate.family_name, 0)
        if seen_live_results:
            saturation = _family_saturation_label(
                total_known_operators=total_known_operator_count,
                tried_operators=explored_live_operator_count,
                unique_result_count=len(set(seen_live_results)),
                dominant_result_class=sorted(
                    seen_live_results,
                    key=seen_live_results.count,
                    reverse=True,
                )[0],
            )
        elif seen_simulation_results:
            if candidate.execution_mode == "nested-simulation":
                saturation = "simulation-only exploration"
            else:
                saturation = "simulation coverage complete (no live outcome yet)"
        else:
            saturation = _family_saturation_label(
                total_known_operators=total_known_operator_count,
                tried_operators=explored_operator_count,
                unique_result_count=len(seen_unique_results),
                dominant_result_class=(
                    sorted(seen_family_results, key=seen_family_results.count, reverse=True)[0]
                    if seen_family_results
                    else None
                ),
            )
        if not seen_family_results:
            score += 6
            reasons.append("family not explored yet")
        else:
            characterization_penalty = min(
                FAMILY_CHARACTERIZATION_PENALTY_CAP,
                max(0, explored_operator_count - 1) * FAMILY_CHARACTERIZATION_PENALTY_STEP,
            )
            if characterization_penalty:
                score -= characterization_penalty
                reasons.append(
                    f"family already characterized by {explored_operator_count} observed operators"
                )
            if RESULT_EARLY_SEMANTIC_REJECT in seen_family_results:
                score -= 3
                reasons.append("family already produced early semantic reject")
            if RESULT_DEEP_DECODER_FAILURE in seen_family_results and tried is None:
                score += 8
                reasons.append("family already produced deep decoder failure")
            if RESULT_UNEXPECTED_ACCEPT in seen_family_results and tried is None:
                score += 12
                reasons.append("family previously produced unexpected accept")
            if RESULT_AMF_CRASH in seen_family_results and tried is None:
                score += 15
                reasons.append("family previously produced AMF crash")
            if tried is None and explored_operator_count <= 1:
                score += 5
                reasons.append("family still underexplored")
            if seen_live_results and saturation.startswith("likely saturated"):
                score -= FAMILY_LIKELY_SATURATED_PENALTY
                reasons.append(f"family appears saturated: {saturation}")
            elif seen_live_results and saturation == "diverse behavior observed" and tried is None:
                score += FAMILY_DIVERSE_BEHAVIOR_BONUS
                reasons.append("family shows diverse behavior; keeping fresh operators attractive")
            elif seen_simulation_results and not seen_live_results:
                reasons.append(
                    f"family currently characterized by simulation only ({explored_simulation_operator_count} operators)"
                )
            if tried is not None and len(seen_unique_results) >= 3:
                score -= FAMILY_DIVERSE_OUTCOME_REPEAT_PENALTY
                reasons.append(
                    f"family already spans {len(seen_unique_results)} outcome classes; deprioritizing revisits"
                )

        if tried is not None:
            score += RESULT_WEIGHT.get(tried.result_class, 0)

        recommendations.append(
            NasSchedulerRecommendation(candidate=candidate, score=score, reasons=reasons)
        )

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
    return recommendations[:limit]
