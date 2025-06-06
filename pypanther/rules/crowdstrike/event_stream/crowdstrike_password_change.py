from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import key_value_list_to_dict
from pypanther.helpers.crowdstrike_event_streams import cs_alert_context


@panther_managed
class CrowdstrikeUserPasswordChange(Rule):
    id = "Crowdstrike.UserPasswordChange-prototype"
    display_name = "Crowdstrike User Password Changed"
    log_types = [LogType.CROWDSTRIKE_EVENT_STREAMS]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0003:T1098.001", "TA0004:T1098.001"]}
    default_description = "A user's password was changed"
    default_runbook = "Validate this action was authorized."

    def rule(self, event):
        return all([event.deep_get("event", "OperationName") == "changePassword", event.deep_get("event", "Success")])

    def title(self, event):
        audit_keys = key_value_list_to_dict(event.deep_get("event", "AuditKeyValues"), "Key", "ValueString")
        target = audit_keys.get("target_name", "UNKNOWN USER")
        actor = event.deep_get("event", "UserId")
        if target == actor:
            return f"[{actor}] changed their password."
        return f"[{actor}] changed the password of [{target}]"

    def severity(self, event):
        # Downgrade sev if password changed by same uer
        audit_keys = key_value_list_to_dict(event.deep_get("event", "AuditKeyValues"), "Key", "ValueString")
        target = audit_keys.get("target_name", "UNKNOWN USER")
        actor = event.deep_get("event", "UserId")
        if target == actor:
            return "INFO"
        return "DEFAULT"

    def alert_context(self, event):
        return cs_alert_context(event)

    tests = [
        RuleTest(
            name="Own Password Changed",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "target_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                        {"Key": "target_cid", "ValueString": "fake_customer_id"},
                        {"Key": "actor_cid", "ValueString": "fake_customer_id"},
                        {"Key": "trace_id", "ValueString": "f4f8b3233619bdf49ea2a2d108ce39d8"},
                        {"Key": "target_name", "ValueString": "peregrin.took@hobbiton.co"},
                        {"Key": "action_target_name", "ValueString": "peregrin.took@hobbiton.co"},
                    ],
                    "OperationName": "changePassword",
                    "ServiceName": "CrowdStrike Authentication",
                    "Success": True,
                    "UTCTimestamp": "2024-07-22 16:15:36.535000000",
                    "UserId": "peregrin.took@hobbiton.co",
                    "UserIp": "1.1.1.1",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-22 16:15:36.535000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 341447,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Password Changed for Different User",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "target_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                        {"Key": "target_cid", "ValueString": "fake_customer_id"},
                        {"Key": "actor_cid", "ValueString": "fake_customer_id"},
                        {"Key": "trace_id", "ValueString": "f4f8b3233619bdf49ea2a2d108ce39d8"},
                        {"Key": "target_name", "ValueString": "peregrin.took@hobbiton.co"},
                        {"Key": "action_target_name", "ValueString": "peregrin.took@hobbiton.co"},
                    ],
                    "OperationName": "changePassword",
                    "ServiceName": "CrowdStrike Authentication",
                    "Success": True,
                    "UTCTimestamp": "2024-07-22 16:15:36.535000000",
                    "UserId": "bilbo.baggins@hobbiton.co",
                    "UserIp": "1.1.1.1",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-22 16:15:36.535000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 341447,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Unsuccessful Password Change Attempt",
            expected_result=False,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "target_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                        {"Key": "target_cid", "ValueString": "fake_customer_id"},
                        {"Key": "actor_cid", "ValueString": "fake_customer_id"},
                        {"Key": "trace_id", "ValueString": "f4f8b3233619bdf49ea2a2d108ce39d8"},
                        {"Key": "target_name", "ValueString": "peregrin.took@hobbiton.co"},
                        {"Key": "action_target_name", "ValueString": "peregrin.took@hobbiton.co"},
                    ],
                    "OperationName": "changePassword",
                    "ServiceName": "CrowdStrike Authentication",
                    "Success": False,
                    "UTCTimestamp": "2024-07-22 16:15:36.535000000",
                    "UserId": "bilbo.baggins@hobbiton.co",
                    "UserIp": "1.1.1.1",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-22 16:15:36.535000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 341447,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Unrelated Event",
            expected_result=False,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "target_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                        {"Key": "target_cid", "ValueString": "fake_customer_id"},
                        {"Key": "actor_cid", "ValueString": "fake_customer_id"},
                        {"Key": "trace_id", "ValueString": "652fc606f369ef3105925197b34f2c54"},
                        {"Key": "target_name", "ValueString": "peregrin.took@hobbiton.co"},
                        {"Key": "action_target_name", "ValueString": "peregrin.took@hobbiton.co"},
                    ],
                    "OperationName": "userAuthenticate",
                    "ServiceName": "CrowdStrike Authentication",
                    "Success": True,
                    "UTCTimestamp": "2024-07-22 15:50:16.923000000",
                    "UserId": "peregrin.took@hobbiton.co",
                    "UserIp": "1.1.1.1",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-22 15:50:16.923000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 341329,
                    "version": "1.0",
                },
            },
        ),
    ]
