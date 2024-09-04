from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.crowdstrike_event_streams import cs_alert_context


@panther_managed
class CrowdstrikeUserDeleted(Rule):
    id = "Crowdstrike.UserDeleted-prototype"
    display_name = "Crowdstrike User Deleted"
    log_types = [LogType.CROWDSTRIKE_EVENT_STREAMS]
    default_severity = Severity.HIGH
    reports = {"MITRE ATT&CK": ["TA0005:T1070"]}
    default_description = "Someone has deleted multiple users."
    threshold = 3
    default_runbook = "Validate this action was authorized."

    def rule(self, event):
        return all([event.deep_get("event", "OperationName") == "deleteUser", event.deep_get("event", "Success")])

    def title(self, event):
        actor = event.deep_get("event", "UserId", default="UNKNOWN USER")
        return f"[{actor}] has deleted multiple Crowdstrike users within the past hour."

    def alert_context(self, event):
        return cs_alert_context(event)

    tests = [
        RuleTest(
            name="Successful User Deletion",
            expected_result=True,
            log={
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "offset": 341329,
                    "eventType": "AuthActivityAuditEvent",
                    "eventCreationTime": "2024-07-22 15:50:16.923000000",
                    "version": "1.0",
                },
                "event": {
                    "UserId": "sharkey@hobbiton.co",
                    "UserIp": "192.0.2.100",
                    "OperationName": "deleteUser",
                    "ServiceName": "CrowdStrike Authentication",
                    "Success": True,
                    "UTCTimestamp": "2024-07-22 15:50:16.923000000",
                    "AuditKeyValues": [{"Key": "target_name", "ValueString": "frodo.baggins@hobbiton.co"}],
                },
            },
        ),
        RuleTest(
            name="Unsuccessful User Deletion Attempt",
            expected_result=False,
            log={
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "offset": 341329,
                    "eventType": "AuthActivityAuditEvent",
                    "eventCreationTime": "2024-07-22 15:50:16.923000000",
                    "version": "1.0",
                },
                "event": {
                    "UserId": "sharkey@hobbiton.co",
                    "UserIp": "192.0.2.100",
                    "OperationName": "deleteUser",
                    "ServiceName": "CrowdStrike Authentication",
                    "Success": False,
                    "UTCTimestamp": "2024-07-22 15:50:16.923000000",
                    "AuditKeyValues": [{"Key": "target_name", "ValueString": "frodo.baggins@hobbiton.co"}],
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
