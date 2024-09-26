from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import key_value_list_to_dict
from pypanther.helpers.crowdstrike_event_streams import cs_alert_context


@panther_managed
class CrowdstrikeNewUserCreated(Rule):
    id = "Crowdstrike.NewUserCreated-prototype"
    display_name = "Crowdstrike New User Created"
    log_types = [LogType.CROWDSTRIKE_EVENT_STREAMS]
    default_severity = Severity.INFO
    create_alert = False
    reports = {"MITRE ATT&CK": ["TA0003:T1136.003"]}
    default_description = "A new Crowdstrike user was created"
    default_runbook = "Confirm the new user is valid."

    def rule(self, event):
        return all([event.deep_get("event", "OperationName") == "createUser", event.deep_get("event", "Success")])

    def title(self, event):
        audit_keys = key_value_list_to_dict(event.deep_get("event", "AuditKeyValues"), "Key", "ValueString")
        actor = event.deep_get("event", "UserId", "UNKNOWN USER")
        target = audit_keys.get("target_name")
        return f"[{actor}] created a new user: [{target}]"

    def alert_context(self, event):
        context = cs_alert_context(event)
        actor = context.get("actor_user", "UNKNWON_ACTOR")
        target = context.get("target_name", "UNKNOWN_TARGET")
        context["actor_target"] = f"{actor}-{target}"
        return context

    tests = [
        RuleTest(
            name="New User Created",
            expected_result=True,
            log={
                "metadata": {
                    "customerIDString": "face_customer_id",
                    "offset": 1238741,
                    "eventType": "AuthActivityAuditEvent",
                    "eventCreationTime": "2024-07-22 15:50:16.923000000",
                    "version": "1.0",
                },
                "event": {
                    "UserId": "bilbo.baggins@hobbiton.co",
                    "UserIp": "1.1.1.1",
                    "OperationName": "createUser",
                    "ServiceName": "CrowdStrike Authentication",
                    "Success": True,
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
