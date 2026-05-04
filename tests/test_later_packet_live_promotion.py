from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.ngap_nas_fuzz.nas_campaign import build_proxy_campaign_plan
from src.ngap_nas_fuzz.nas_execution_bridge import (
    LIVE_NESTED_OPTIONAL_IE_MUTATION,
    observation_runtime_key,
    resolve_operator_execution,
)
from src.ngap_nas_fuzz.nas_scheduler import (
    RESULT_SIMULATION_ARTIFACT,
    NasCampaignObservation,
    recommend_next_candidates,
)


class LaterPacketLivePromotionTests(unittest.TestCase):
    _NESTED_RR_PREFIX = (
        "container:nested-nas-message,message:Registration Request,occurrence:later,"
    )

    def test_execution_bridge_promotes_requested_nssai_omit_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="requested NSSAI corruption",
            operator="omit IE entirely",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:requested_nssai,action:omit",
        )

    def test_execution_bridge_promotes_requested_nssai_invalid_length_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="requested NSSAI corruption",
            operator="invalid length",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:requested_nssai,action:bad-length,length:0xff",
        )

    def test_execution_bridge_promotes_requested_nssai_duplicate_ie_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="requested NSSAI corruption",
            operator="duplicate IE",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:requested_nssai,action:duplicate",
        )

    def test_execution_bridge_promotes_requested_nssai_unsupported_sst_sd_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="requested NSSAI corruption",
            operator="unsupported SST/SD combination",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:requested_nssai,action:unsupported-sst-sd",
        )

    def test_execution_bridge_promotes_requested_nssai_duplicate_entries_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="requested NSSAI corruption",
            operator="duplicate NSSAI entries",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:requested_nssai,action:duplicate-payload-entries",
        )

    def test_execution_bridge_promotes_fivegmm_omit_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="5GMM capability corruption",
            operator="omit IE entirely",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:fivegmm_capability,action:omit",
        )

    def test_execution_bridge_promotes_fivegmm_oversized_length_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="5GMM capability corruption",
            operator="oversized length",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:fivegmm_capability,action:bad-length,length:0xff",
        )

    def test_execution_bridge_promotes_fivegmm_duplicate_ie_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="5GMM capability corruption",
            operator="duplicate IE",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:fivegmm_capability,action:duplicate",
        )

    def test_execution_bridge_promotes_fivegmm_reserved_bits_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="5GMM capability corruption",
            operator="reserved bits set",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:fivegmm_capability,action:set-reserved-bits",
        )

    def test_execution_bridge_promotes_fivegmm_truncation_to_live_proxy(self) -> None:
        executable, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Registration Request",
            family_name="5GMM capability corruption",
            operator="truncation",
        )

        self.assertTrue(executable)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            proxy_value,
            self._NESTED_RR_PREFIX + "field:fivegmm_capability,action:truncate-payload",
        )

    def test_scheduler_keeps_live_proxy_case_fresh_after_simulation_history(self) -> None:
        history = [
            NasCampaignObservation(
                message_name="Registration Request",
                family_name="requested NSSAI corruption",
                operator="omit IE entirely",
                result_class=RESULT_SIMULATION_ARTIFACT,
                notes="Removed requested_nssai IE from nested Registration Request in simulation.",
                proxy_mutation="nested-registration-request-optional-ie",
                proxy_value="action:omit",
            )
        ]

        recommendations = recommend_next_candidates(
            "Registration Request",
            history,
            limit=100,
            executable_only=True,
        )

        promoted = next(
            (
                rec
                for rec in recommendations
                if rec.candidate.family_name == "requested NSSAI corruption"
                and rec.candidate.operator == "omit IE entirely"
            ),
            None,
        )

        self.assertIsNotNone(promoted)
        assert promoted is not None
        self.assertEqual(promoted.candidate.execution_mode, "proxy")
        self.assertEqual(promoted.candidate.proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            promoted.candidate.proxy_value,
            self._NESTED_RR_PREFIX + "field:requested_nssai,action:omit",
        )
        self.assertIn("untried operator", promoted.reasons)

    def test_proxy_campaign_plan_renders_new_live_flag(self) -> None:
        history = [
            NasCampaignObservation(
                message_name="Registration Request",
                family_name="requested NSSAI corruption",
                operator="omit IE entirely",
                result_class=RESULT_SIMULATION_ARTIFACT,
                notes="Removed requested_nssai IE from nested Registration Request in simulation.",
                proxy_mutation="nested-registration-request-optional-ie",
                proxy_value="action:omit",
            )
        ]

        plan = build_proxy_campaign_plan(
            "Registration Request",
            history,
            limit=100,
        )

        run = next(
            (
                item
                for item in plan.runs
                if item.family_name == "requested NSSAI corruption"
                and item.operator == "omit IE entirely"
            ),
            None,
        )

        self.assertIsNotNone(run)
        assert run is not None
        self.assertIn(
            "--mutate-nested-optional-ie '"
            + self._NESTED_RR_PREFIX
            + "field:requested_nssai,action:omit'",
            run.proxy_command,
        )
        self.assertIn("untried operator", run.recommendation_reasons)

    def test_scheduler_keeps_live_fivegmm_case_fresh_after_simulation_history(self) -> None:
        history = [
            NasCampaignObservation(
                message_name="Registration Request",
                family_name="5GMM capability corruption",
                operator="omit IE entirely",
                result_class=RESULT_SIMULATION_ARTIFACT,
                notes="Removed fivegmm_capability IE from nested Registration Request in simulation.",
                proxy_mutation="nested-registration-request-optional-ie",
                proxy_value="action:omit",
            )
        ]

        recommendations = recommend_next_candidates(
            "Registration Request",
            history,
            limit=100,
            executable_only=True,
        )

        promoted = next(
            (
                rec
                for rec in recommendations
                if rec.candidate.family_name == "5GMM capability corruption"
                and rec.candidate.operator == "omit IE entirely"
            ),
            None,
        )

        self.assertIsNotNone(promoted)
        assert promoted is not None
        self.assertEqual(promoted.candidate.execution_mode, "proxy")
        self.assertEqual(promoted.candidate.proxy_mutation, LIVE_NESTED_OPTIONAL_IE_MUTATION)
        self.assertEqual(
            promoted.candidate.proxy_value,
            self._NESTED_RR_PREFIX + "field:fivegmm_capability,action:omit",
        )
        self.assertIn("untried operator", promoted.reasons)

    def test_proxy_campaign_plan_renders_reserved_bits_live_flag(self) -> None:
        history = [
            NasCampaignObservation(
                message_name="Registration Request",
                family_name="5GMM capability corruption",
                operator="reserved bits set",
                result_class=RESULT_SIMULATION_ARTIFACT,
                notes="Patched fivegmm_capability payload byte from 0x00 to 0xff in simulation.",
                proxy_mutation="nested-registration-request-optional-ie",
                proxy_value="action:set-reserved-bits",
            )
        ]

        plan = build_proxy_campaign_plan(
            "Registration Request",
            history,
            limit=100,
        )

        run = next(
            (
                item
                for item in plan.runs
                if item.family_name == "5GMM capability corruption"
                and item.operator == "reserved bits set"
            ),
            None,
        )

        self.assertIsNotNone(run)
        assert run is not None
        self.assertIn(
            "--mutate-nested-optional-ie '"
            + self._NESTED_RR_PREFIX
            + "field:fivegmm_capability,action:set-reserved-bits'",
            run.proxy_command,
        )
        self.assertIn("untried operator", run.recommendation_reasons)

    def test_legacy_live_history_normalizes_to_generic_runtime_key(self) -> None:
        legacy_key = observation_runtime_key(
            message_name="Registration Request",
            family_name="requested NSSAI corruption",
            operator="omit IE entirely",
            proxy_mutation="nested-requested-nssai-omit",
            proxy_value=None,
        )

        generic_key = observation_runtime_key(
            message_name="Registration Request",
            family_name="requested NSSAI corruption",
            operator="omit IE entirely",
            proxy_mutation=LIVE_NESTED_OPTIONAL_IE_MUTATION,
            proxy_value=self._NESTED_RR_PREFIX + "field:requested_nssai,action:omit",
        )

        self.assertEqual(legacy_key, generic_key)


if __name__ == "__main__":
    unittest.main()
