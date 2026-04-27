from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.ngap_nas_fuzz.nas_campaign import (
    append_observation_from_simulation_run,
    build_simulation_campaign_plan,
)
from src.ngap_nas_fuzz.nas_schema import (
    NasMutationPlan,
    PacketSelector,
    build_nested_optional_ie_mutation_plan,
    build_nested_registration_request_selector,
    build_plain_field_mutation_plan,
    deserialize_mutation_plan_value,
    get_nas_message_schema,
    get_nas_message_schemas,
    resolve_plain_field_mutation_plan,
    resolve_nested_optional_ie_plan,
    serialize_mutation_plan_value,
)
from src.ngap_nas_fuzz.models import Message, ProcedureTrace
from src.ngap_nas_fuzz.nas_execution_bridge import resolve_operator_execution
from src.ngap_nas_fuzz.nas_field_locator import inspect_registration_request_fields
from src.ngap_nas_fuzz.nas_field_locator import inspect_nas_message_fields
from src.ngap_nas_fuzz.nas_field_locator import locate_nas_field
from src.ngap_nas_fuzz.proxy_policy import (
    InitialNasMutationSpec,
    ProxyMutationError,
    apply_nas_mutation_plan,
    apply_initial_registration_mutation,
    apply_registration_request_optional_ie_mutation,
    build_nested_registration_request_optional_ie_plan,
)
from src.ngap_nas_fuzz.proxy_runtime import simulate_plain_nas_field_mutation


class NasSchemaTests(unittest.TestCase):
    _PLAIN_INITIAL_REGISTRATION_REQUEST = (
        "7e:00:41:79:00:0d:01:00:f1:10:00:00:00:00:00:00:00:00:10:2e:04:f0:f0:f0:f0"
    )
    _REGISTRATION_REQUEST_WITH_OPTIONAL_IES = (
        "7e:00:41:79:00:0d:01:00:f1:10:00:00:00:00:00:00:00:00:10:"
        "2e:04:f0:f0:f0:f0:10:01:00:2f:02:01:01"
    )

    def _identity_response_trace(self) -> ProcedureTrace:
        return ProcedureTrace(
            procedure="Identity Request / Response",
            messages=[
                Message(
                    id=1,
                    direction="AMF->gNB",
                    protocol="NGAP",
                    message_type="DownlinkNASTransport",
                    nas={
                        "message_type": "Identity Request",
                        "raw_pdu_hex": "7e:00:56:01",
                    },
                ),
                Message(
                    id=2,
                    direction="gNB->AMF",
                    protocol="NGAP",
                    message_type="UplinkNASTransport",
                    nas={
                        "message_type": "Identity Response",
                        "raw_pdu_hex": "7e:00:5c:11:22:33",
                    },
                ),
            ],
        )

    def test_registration_request_schema_exposes_optional_ie_fields(self) -> None:
        schema = get_nas_message_schema("Registration Request")

        security_header = schema.get_field("security_header")
        self.assertIsNotNone(security_header.locator)
        assert security_header.locator is not None
        self.assertEqual(security_header.locator.strategy, "fixed-offset")
        self.assertEqual(security_header.locator.offset, 1)
        self.assertEqual(security_header.locator.length, 1)

        mobile_identity_length = schema.get_field("mobile_identity_length")
        self.assertIsNotNone(mobile_identity_length.locator)
        assert mobile_identity_length.locator is not None
        self.assertEqual(mobile_identity_length.locator.strategy, "fixed-offset")
        self.assertEqual(mobile_identity_length.locator.offset, 4)
        self.assertEqual(mobile_identity_length.locator.length, 2)

        mobile_identity_value = schema.get_field("mobile_identity_value")
        self.assertIsNotNone(mobile_identity_value.locator)
        assert mobile_identity_value.locator is not None
        self.assertEqual(mobile_identity_value.locator.strategy, "length-prefixed-payload")
        self.assertEqual(mobile_identity_value.locator.offset, 6)
        self.assertEqual(mobile_identity_value.locator.length_from_field, "mobile_identity_length")

        requested_nssai = schema.get_field("requested_nssai")
        self.assertEqual(requested_nssai.kind, "optional_tlv")
        self.assertEqual(requested_nssai.iei_tag, "0x2f")
        self.assertIn("omit", requested_nssai.action_kinds)
        self.assertIn("duplicate-ie", requested_nssai.action_kinds)
        self.assertIn("bad-length", requested_nssai.action_kinds)
        self.assertIn("unsupported-sst-sd", requested_nssai.action_kinds)
        self.assertIn("duplicate IE", requested_nssai.operator_labels)
        self.assertIn("unsupported SST/SD combination", requested_nssai.operator_labels)
        self.assertTrue(requested_nssai.rules)

        fivegmm = schema.get_field("fivegmm_capability")
        self.assertEqual(fivegmm.kind, "tlv_payload")
        self.assertEqual(fivegmm.iei_tag, "0x10")
        self.assertIn("omit", fivegmm.action_kinds)
        self.assertIn("bad-length", fivegmm.action_kinds)
        self.assertIn("truncate-payload", fivegmm.action_kinds)
        self.assertIn("set-reserved-bits", fivegmm.action_kinds)
        self.assertIn("reserved bits set", fivegmm.operator_labels)
        self.assertIn("truncation", fivegmm.operator_labels)
        self.assertTrue(fivegmm.rules)

    def test_multiple_message_schemas_are_available(self) -> None:
        schema_names = {schema.message_name for schema in get_nas_message_schemas()}

        self.assertIn("Registration Request", schema_names)
        self.assertIn("Identity Response", schema_names)
        self.assertIn("Authentication Response", schema_names)
        self.assertIn("Security Mode Complete", schema_names)

        identity_response = get_nas_message_schema("Identity Response")
        identity_payload = identity_response.get_field("identity_payload")
        self.assertIsNotNone(identity_payload.locator)
        assert identity_payload.locator is not None
        self.assertEqual(identity_payload.locator.strategy, "payload-remainder")
        self.assertEqual(identity_payload.locator.offset, 3)

        authentication_response = get_nas_message_schema("Authentication Response")
        auth_payload = authentication_response.get_field("authentication_response_parameter")
        self.assertIsNotNone(auth_payload.locator)
        assert auth_payload.locator is not None
        self.assertEqual(auth_payload.locator.strategy, "payload-remainder")
        self.assertEqual(auth_payload.locator.offset, 3)

    def test_packet_selector_drives_mutation_plan(self) -> None:
        selector = PacketSelector(
            direction="uplink",
            container_type="nested-registration-request",
            message_name="Registration Request",
            occurrence="later",
        )
        plan = NasMutationPlan(
            selector=selector,
            field_name="fivegmm_capability",
            action="bad-length",
            value="0xff",
        )

        self.assertEqual(plan.selector.direction, "uplink")
        self.assertEqual(plan.selector.container_type, "nested-registration-request")
        self.assertEqual(plan.selector.occurrence, "later")
        self.assertEqual(plan.field_name, "fivegmm_capability")
        self.assertEqual(plan.action, "bad-length")
        self.assertEqual(plan.value, "0xff")

    def test_field_locator_uses_schema_defined_optional_ie_metadata(self) -> None:
        report = inspect_registration_request_fields(self._REGISTRATION_REQUEST_WITH_OPTIONAL_IES)
        fields = {field.name: field for field in report.fields}
        mapped_tlvs = {tlv.mapped_field_name: tlv for tlv in report.tlvs if tlv.mapped_field_name}

        security_header = fields["security_header"]
        self.assertTrue(security_header.present)
        self.assertEqual(security_header.start_offset, 1)
        self.assertEqual(security_header.length, 1)
        self.assertEqual(security_header.value_hex, "0x00")

        registration_type = fields["registration_type_and_ngksi"]
        self.assertTrue(registration_type.present)
        self.assertEqual(registration_type.start_offset, 3)
        self.assertEqual(registration_type.length, 1)
        self.assertEqual(registration_type.value_hex, "0x79")

        mobile_identity_length = fields["mobile_identity_length"]
        self.assertTrue(mobile_identity_length.present)
        self.assertEqual(mobile_identity_length.start_offset, 4)
        self.assertEqual(mobile_identity_length.length, 2)
        self.assertEqual(mobile_identity_length.value_hex, "0x000d")

        mobile_identity_value = fields["mobile_identity_value"]
        self.assertTrue(mobile_identity_value.present)
        self.assertEqual(mobile_identity_value.start_offset, 6)
        self.assertEqual(mobile_identity_value.length, 13)
        self.assertEqual(
            mobile_identity_value.value_hex,
            "01:00:f1:10:00:00:00:00:00:00:00:00:10",
        )

        requested_nssai = fields["requested_nssai"]
        self.assertTrue(requested_nssai.present)
        self.assertEqual(requested_nssai.kind, "optional_tlv")
        self.assertEqual(requested_nssai.start_offset, 28)
        self.assertEqual(requested_nssai.value_hex, "0x2f:01:01")

        fivegmm = fields["fivegmm_capability"]
        self.assertTrue(fivegmm.present)
        self.assertEqual(fivegmm.kind, "tlv_payload")
        self.assertEqual(fivegmm.start_offset, 25)
        self.assertEqual(fivegmm.value_hex, "0x10:00")

        self.assertEqual(mapped_tlvs["requested_nssai"].tag, "0x2f")
        self.assertEqual(mapped_tlvs["fivegmm_capability"].tag, "0x10")

    def test_schema_can_resolve_live_nested_optional_ie_plan(self) -> None:
        requested_nssai_plan = resolve_nested_optional_ie_plan(
            message_name="Registration Request",
            family_name="requested NSSAI corruption",
            operator="duplicate NSSAI entries",
        )
        self.assertIsNotNone(requested_nssai_plan)
        assert requested_nssai_plan is not None
        self.assertEqual(requested_nssai_plan.selector.container_type, "nested-registration-request")
        self.assertEqual(requested_nssai_plan.field_name, "requested_nssai")
        self.assertEqual(requested_nssai_plan.action, "duplicate-payload-entries")
        self.assertIsNone(requested_nssai_plan.value)

        fivegmm_plan = resolve_nested_optional_ie_plan(
            message_name="Registration Request",
            family_name="5GMM capability corruption",
            operator="oversized length",
        )
        self.assertIsNotNone(fivegmm_plan)
        assert fivegmm_plan is not None
        self.assertEqual(fivegmm_plan.field_name, "fivegmm_capability")
        self.assertEqual(fivegmm_plan.action, "bad-length")
        self.assertEqual(fivegmm_plan.value, "0xff")

    def test_schema_can_resolve_plain_field_mutation_plan(self) -> None:
        identity_header_plan = resolve_plain_field_mutation_plan(
            message_name="Identity Response",
            family_name="security-header mutation",
            operator="set security header 0x00 -> 0x01",
        )
        self.assertIsNotNone(identity_header_plan)
        assert identity_header_plan is not None
        self.assertEqual(identity_header_plan.selector.container_type, "plain-nas-message")
        self.assertEqual(identity_header_plan.field_name, "security_header")
        self.assertEqual(identity_header_plan.action, "replace-byte")
        self.assertEqual(identity_header_plan.value, "0x01")

        identity_payload_plan = resolve_plain_field_mutation_plan(
            message_name="Identity Response",
            family_name="identity payload corruption",
            operator="truncation",
        )
        self.assertIsNotNone(identity_payload_plan)
        assert identity_payload_plan is not None
        self.assertEqual(identity_payload_plan.field_name, "identity_payload")
        self.assertEqual(identity_payload_plan.action, "truncate-payload")
        self.assertIsNone(identity_payload_plan.value)

        auth_oversized_plan = resolve_plain_field_mutation_plan(
            message_name="Authentication Response",
            family_name="authentication parameter corruption",
            operator="oversized length",
        )
        self.assertIsNotNone(auth_oversized_plan)
        assert auth_oversized_plan is not None
        self.assertEqual(auth_oversized_plan.field_name, "authentication_response_parameter")
        self.assertEqual(auth_oversized_plan.action, "set-leading-length-byte")
        self.assertEqual(auth_oversized_plan.value, "0xff")

        auth_append_plan = resolve_plain_field_mutation_plan(
            message_name="Authentication Response",
            family_name="extra trailing payload",
            operator="append extra bytes",
        )
        self.assertIsNotNone(auth_append_plan)
        assert auth_append_plan is not None
        self.assertEqual(auth_append_plan.field_name, "authentication_response_parameter")
        self.assertEqual(auth_append_plan.action, "append-bytes")
        self.assertEqual(auth_append_plan.value, "0x0000")

    def test_execution_bridge_promotes_selected_auth_payload_case_to_proxy(self) -> None:
        executable_now, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Authentication Response",
            family_name="authentication parameter corruption",
            operator="all-zero response value",
        )

        self.assertTrue(executable_now)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, "authentication-response-zero-response-value")
        self.assertIsNone(proxy_value)

    def test_execution_bridge_promotes_auth_length_case_to_proxy_with_default_value(self) -> None:
        executable_now, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Authentication Response",
            family_name="authentication parameter corruption",
            operator="oversized length",
        )

        self.assertTrue(executable_now)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, "authentication-response-parameter-length")
        self.assertEqual(proxy_value, "0xff")

    def test_identity_response_field_inspection_uses_schema_locator(self) -> None:
        report = inspect_nas_message_fields("7e:00:5c:11:22:33", message_name="Identity Response")
        fields = {field.name: field for field in report.fields}

        self.assertEqual(fields["security_header"].value_hex, "0x00")
        self.assertEqual(fields["message_type"].value_hex, "0x5c")
        self.assertTrue(fields["identity_payload"].present)
        self.assertEqual(fields["identity_payload"].start_offset, 3)
        self.assertEqual(fields["identity_payload"].length, 3)
        self.assertEqual(fields["identity_payload"].value_hex, "11:22:33")

    def test_authentication_response_field_inspection_uses_schema_locator(self) -> None:
        report = inspect_nas_message_fields(
            "7e:00:57:aa:bb",
            message_name="Authentication Response",
        )
        fields = {field.name: field for field in report.fields}

        self.assertEqual(fields["security_header"].value_hex, "0x00")
        self.assertEqual(fields["message_type"].value_hex, "0x57")
        self.assertTrue(fields["authentication_response_parameter"].present)
        self.assertEqual(fields["authentication_response_parameter"].start_offset, 3)
        self.assertEqual(fields["authentication_response_parameter"].length, 2)
        self.assertEqual(fields["authentication_response_parameter"].value_hex, "aa:bb")

    def test_security_mode_complete_field_inspection_uses_protected_locator(self) -> None:
        report = inspect_nas_message_fields(
            "7e:04:e6:4b:16:71:00:7e:00:5e:77:00:09",
            message_name="Security Mode Complete",
        )
        fields = {field.name: field for field in report.fields}

        self.assertEqual(fields["protected_security_header"].value_hex, "0x04")
        self.assertEqual(fields["message_type"].value_hex, "0x5e")
        self.assertEqual(fields["message_type"].start_offset, 9)

    def test_execution_bridge_promotes_security_mode_complete_header_cases_to_proxy(self) -> None:
        msgtype_exec = resolve_operator_execution(
            message_name="Security Mode Complete",
            family_name="message-type substitution",
            operator="replace 0x5e with 0x41",
        )
        self.assertEqual(
            msgtype_exec,
            (True, "proxy", "security-mode-complete-message-type", "0x41"),
        )

        sec_hdr_exec = resolve_operator_execution(
            message_name="Security Mode Complete",
            family_name="security-header inconsistency",
            operator="set security header 0x04 -> 0x00",
        )
        self.assertEqual(
            sec_hdr_exec,
            (True, "proxy", "security-mode-complete-security-header", "0x00"),
        )

    def test_mutation_plan_value_roundtrip_for_live_nested_optional_ie(self) -> None:
        plan = build_nested_optional_ie_mutation_plan(
            field_name="fivegmm_capability",
            action="bad-length",
            value="0xff",
        )

        encoded = serialize_mutation_plan_value(plan, include_field=True)
        decoded = deserialize_mutation_plan_value(
            encoded,
            selector=build_nested_registration_request_selector(),
        )

        self.assertEqual(encoded, "field:fivegmm_capability,action:bad-length,length:0xff")
        self.assertEqual(decoded, plan)

    def test_mutation_plan_value_can_decode_legacy_simulation_shape(self) -> None:
        decoded = deserialize_mutation_plan_value(
            "action:omit",
            selector=build_nested_registration_request_selector(),
            default_field_name="requested_nssai",
        )

        self.assertEqual(decoded.field_name, "requested_nssai")
        self.assertEqual(decoded.action, "omit")
        self.assertIsNone(decoded.value)

    def test_plan_executor_matches_registration_request_optional_ie_wrapper(self) -> None:
        plan = build_nested_registration_request_optional_ie_plan(
            field_name="fivegmm_capability",
            action="bad-length",
            value="0xff",
        )

        direct = apply_nas_mutation_plan(self._REGISTRATION_REQUEST_WITH_OPTIONAL_IES, plan)
        wrapped = apply_registration_request_optional_ie_mutation(
            self._REGISTRATION_REQUEST_WITH_OPTIONAL_IES,
            field_name="fivegmm_capability",
            action="bad-length",
            length_value="0xff",
        )

        self.assertEqual(direct.after_raw_pdu_hex, wrapped.after_raw_pdu_hex)
        self.assertEqual(direct.notes, wrapped.notes)

    def test_plan_executor_rejects_action_not_modeled_for_field(self) -> None:
        plan = build_nested_registration_request_optional_ie_plan(
            field_name="fivegmm_capability",
            action="unsupported-sst-sd",
        )

        with self.assertRaises(ProxyMutationError):
            apply_nas_mutation_plan(self._REGISTRATION_REQUEST_WITH_OPTIONAL_IES, plan)

    def test_plain_field_plan_executor_handles_initial_registration_message_type(self) -> None:
        plan = build_plain_field_mutation_plan(
            message_name="Registration Request",
            field_name="message_type",
            action="replace-byte",
            value="0x5c",
        )

        result = apply_nas_mutation_plan(self._PLAIN_INITIAL_REGISTRATION_REQUEST, plan)
        mutated_field = locate_nas_field(
            result.after_raw_pdu_hex,
            "message_type",
            message_name="Identity Response",
        )

        self.assertEqual(mutated_field.value_hex, "0x5c")
        self.assertIn("patched message type", result.notes[0])

    def test_plain_field_plan_executor_handles_identity_response_payload_truncation(self) -> None:
        plan = build_plain_field_mutation_plan(
            message_name="Identity Response",
            field_name="identity_payload",
            action="truncate-payload",
        )

        result = apply_nas_mutation_plan("7e:00:5c:11:22:33", plan)
        mutated_field = locate_nas_field(
            result.after_raw_pdu_hex,
            "identity_payload",
            message_name="Identity Response",
        )

        self.assertEqual(result.after_raw_pdu_hex, "7e:00:5c:11:22")
        self.assertEqual(mutated_field.value_hex, "11:22")
        self.assertIn("truncated field identity_payload", result.notes[0])

    def test_plain_field_plan_executor_handles_authentication_response_payload_actions(self) -> None:
        oversized = build_plain_field_mutation_plan(
            message_name="Authentication Response",
            field_name="authentication_response_parameter",
            action="set-leading-length-byte",
            value="0xff",
        )
        oversized_result = apply_nas_mutation_plan("7e:00:57:2d:02:aa:bb", oversized)
        self.assertEqual(oversized_result.after_raw_pdu_hex, "7e:00:57:2d:ff:aa:bb")
        self.assertIn("leading length 0x02 -> 0xff", oversized_result.notes[0])

        zero_value = build_plain_field_mutation_plan(
            message_name="Authentication Response",
            field_name="authentication_response_parameter",
            action="zero-payload-value",
        )
        zero_result = apply_nas_mutation_plan("7e:00:57:2d:02:aa:bb", zero_value)
        self.assertEqual(zero_result.after_raw_pdu_hex, "7e:00:57:2d:02:00:00")
        self.assertIn("zeroed field authentication_response_parameter value bytes", zero_result.notes[0])

        append_extra = build_plain_field_mutation_plan(
            message_name="Authentication Response",
            field_name="authentication_response_parameter",
            action="append-bytes",
            value="0x0000",
        )
        append_result = apply_nas_mutation_plan("7e:00:57:2d:02:aa:bb", append_extra)
        self.assertEqual(append_result.after_raw_pdu_hex, "7e:00:57:2d:02:aa:bb:00:00")
        self.assertIn("appended 00:00 after field authentication_response_parameter", append_result.notes[0])

        increment_length = build_plain_field_mutation_plan(
            message_name="Authentication Response",
            field_name="authentication_response_parameter",
            action="increment-leading-length-byte",
        )
        increment_result = apply_nas_mutation_plan("7e:00:57:2d:02:aa:bb", increment_length)
        self.assertEqual(increment_result.after_raw_pdu_hex, "7e:00:57:2d:03:aa:bb")
        self.assertIn("incremented field authentication_response_parameter leading length 0x02 -> 0x03", increment_result.notes[0])

    def test_execution_bridge_promotes_identity_response_header_case_to_proxy(self) -> None:
        executable_now, execution_mode, proxy_mutation, proxy_value = resolve_operator_execution(
            message_name="Identity Response",
            family_name="security-header mutation",
            operator="set security header 0x00 -> 0x01",
        )

        self.assertTrue(executable_now)
        self.assertEqual(execution_mode, "proxy")
        self.assertEqual(proxy_mutation, "identity-response-security-header")
        self.assertEqual(proxy_value, "0x01")

    def test_plain_field_runtime_can_simulate_trace_message(self) -> None:
        trace = self._identity_response_trace()

        result = simulate_plain_nas_field_mutation(
            trace,
            message_index=2,
            message_name="Identity Response",
            field_name="identity_payload",
            action="truncate-payload",
        )

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].message_index, 2)
        self.assertEqual(
            result.trace.messages[1].nas["raw_pdu_hex"],
            "7e:00:5c:11:22",
        )
        self.assertEqual(
            result.trace.mutation_history[-1]["mutation"],
            "proxy-simulated-plain-nas-field",
        )

    def test_simulation_campaign_plan_includes_plain_field_runs(self) -> None:
        trace = self._identity_response_trace()
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = Path(tmpdir) / "identity-trace.json"
            baseline_path.write_text(json.dumps(trace.to_dict(), indent=2) + "\n")

            plan = build_simulation_campaign_plan(
                "Identity Response",
                [],
                baseline_trace=str(baseline_path),
                limit=5,
                base_output_root=str(Path(tmpdir) / "out"),
            )

        self.assertTrue(plan.runs)
        first_run = plan.runs[0]
        self.assertEqual(first_run.container_type, "plain-nas-message")
        self.assertEqual(first_run.target_message_index, 2)
        self.assertIn(
            "simulate-plain-nas-field-mutation",
            first_run.simulate_command,
        )

    def test_plain_simulation_observation_uses_plain_runtime_key(self) -> None:
        trace = self._identity_response_trace()
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = Path(tmpdir) / "identity-trace.json"
            baseline_path.write_text(json.dumps(trace.to_dict(), indent=2) + "\n")

            plan = build_simulation_campaign_plan(
                "Identity Response",
                [],
                baseline_trace=str(baseline_path),
                limit=1,
                base_output_root=str(Path(tmpdir) / "out"),
            )

        observation = append_observation_from_simulation_run(
            plan,
            plan.runs[0].run_id,
            "simulation-artifact",
            notes="simulated plain-field mutation",
        )

        self.assertEqual(observation.proxy_mutation, "plain-nas-field-simulation")
        self.assertTrue(observation.proxy_value.startswith("field:"))

    def test_initial_registration_wrapper_matches_plain_field_plan_executor(self) -> None:
        plan = build_plain_field_mutation_plan(
            message_name="Registration Request",
            field_name="message_type",
            action="replace-byte",
            value="0x5c",
        )

        direct = apply_nas_mutation_plan(self._PLAIN_INITIAL_REGISTRATION_REQUEST, plan)
        wrapped = apply_initial_registration_mutation(
            self._PLAIN_INITIAL_REGISTRATION_REQUEST,
            InitialNasMutationSpec(mutation="message-type", value="0x5c"),
        )

        self.assertEqual(direct.after_raw_pdu_hex, wrapped.after_raw_pdu_hex)
        self.assertEqual(direct.notes, wrapped.notes)

    def test_initial_message_type_mutation_uses_schema_located_field(self) -> None:
        result = apply_initial_registration_mutation(
            self._PLAIN_INITIAL_REGISTRATION_REQUEST,
            InitialNasMutationSpec(mutation="message-type", value="0x5c"),
        )

        mutated_field = locate_nas_field(
            result.after_raw_pdu_hex,
            "message_type",
            message_name="Identity Response",
        )
        self.assertEqual(mutated_field.value_hex, "0x5c")
        self.assertIn("patched message type", result.notes[0])

    def test_initial_security_header_mutation_uses_schema_located_field(self) -> None:
        result = apply_initial_registration_mutation(
            self._PLAIN_INITIAL_REGISTRATION_REQUEST,
            InitialNasMutationSpec(mutation="security-header", value="0x04"),
        )

        mutated_field = locate_nas_field(
            result.after_raw_pdu_hex,
            "security_header",
            message_name="Registration Request",
        )
        self.assertEqual(mutated_field.value_hex, "0x04")
        self.assertIn("patched security header type", result.notes[0])

    def test_initial_registration_type_mutation_uses_schema_located_field(self) -> None:
        result = apply_initial_registration_mutation(
            self._PLAIN_INITIAL_REGISTRATION_REQUEST,
            InitialNasMutationSpec(
                mutation="registration-type-and-ngksi",
                value="0x7f",
            ),
        )

        mutated_field = locate_nas_field(
            result.after_raw_pdu_hex,
            "registration_type_and_ngksi",
            message_name="Registration Request",
        )
        self.assertEqual(mutated_field.value_hex, "0x7f")
        self.assertIn("patched registration type / ngKSI", result.notes[0])

    def test_initial_mobile_identity_length_zero_uses_schema_located_field(self) -> None:
        result = apply_initial_registration_mutation(
            self._PLAIN_INITIAL_REGISTRATION_REQUEST,
            InitialNasMutationSpec(mutation="mobile-identity-length-zero"),
        )

        mutated_field = locate_nas_field(
            result.after_raw_pdu_hex,
            "mobile_identity_length",
            message_name="Registration Request",
        )
        self.assertEqual(mutated_field.value_hex, "0x0000")
        self.assertIn("corrupted mobile-identity length", result.notes[0])

    def test_initial_mobile_identity_toggle_uses_schema_located_field(self) -> None:
        result = apply_initial_registration_mutation(
            self._PLAIN_INITIAL_REGISTRATION_REQUEST,
            InitialNasMutationSpec(mutation="mobile-identity-toggle-type-bits"),
        )

        mutated_field = locate_nas_field(
            result.after_raw_pdu_hex,
            "mobile_identity_value",
            message_name="Registration Request",
        )
        self.assertEqual(mutated_field.value_hex.split(":")[0], "06")
        self.assertIn(
            "toggled mobile identity type bits inconsistently",
            result.notes[0],
        )


if __name__ == "__main__":
    unittest.main()
