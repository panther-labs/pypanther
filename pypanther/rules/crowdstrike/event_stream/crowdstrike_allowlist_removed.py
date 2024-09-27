from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.crowdstrike_event_streams import audit_keys_dict, cs_alert_context


@panther_managed
class CrowdstrikeAllowlistRemoved(Rule):
    id = "Crowdstrike.AllowlistRemoved-prototype"
    display_name = "Crowdstrike Allowlist Removed"
    log_types = [LogType.CROWDSTRIKE_EVENT_STREAMS]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0040:T1531"]}
    default_description = "A user deleted an allowlist"
    default_runbook = "Confirm if the deleted allowlist is needed."

    def rule(self, event):
        # Return True if allowlist is deleted
        if event.deep_get("event", "OperationName") == "DeleteAllowlistGroup":
            return True
        # Return True if allowlist is disabled
        if event.deep_get("event", "OperationName") == "UpdateAllowlistGroup":
            audit_keys = audit_keys_dict(event)
            return audit_keys.get("active") == "false" and audit_keys.get("old_active") == "true"
        return False

    def title(self, event):
        actor = event.deep_get("event", "UserId")
        audit_keys = audit_keys_dict(event)
        list_name = audit_keys.get("group_name", "UNKNOWN_GROUP")
        verb = {"DeleteAllowlistGroup": "deleted", "UpdateAllowlistGroup": "disabled"}.get(
            event.deep_get("event", "OperationName"),
            "removed",
        )
        return f'{actor} {verb} IP allowlist "{list_name}"'

    def dedup(self, event):
        # We wanna group alerts if a user disables, then deletes the same allowlist
        actor = event.deep_get("event", "UserId")
        audit_keys = audit_keys_dict(event)
        list_name = audit_keys.get("group_name", "UNKNOWN_GROUP")
        return f"{actor}-{list_name}"

    def alert_context(self, event):
        return cs_alert_context(event)

    def severity(self, event):
        # Downgrade severity if a disabled allowlist was deleted
        if all(
            [
                event.deep_get("event", "OperationName") == "DeleteAllowlistGroup",
                audit_keys_dict(event).get("enabled") == "false",
            ],
        ):
            return "INFO"
        return "DEFAULT"

    tests = [
        RuleTest(
            name="Enabled Allow List Deleted",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "cidrs", "ValueString": "[0.0.0.0/8]"},
                        {"Key": "contexts", "ValueString": "[API]"},
                        {"Key": "active", "ValueString": "true"},
                        {"Key": "allowlist_group_id", "ValueString": "782f842e-98dd-4ee7-9793-33abf8647656"},
                        {"Key": "group_name", "ValueString": "my_allow_list"},
                        {"Key": "description", "ValueString": ""},
                    ],
                    "OperationName": "DeleteAllowlistGroup",
                    "ServiceName": "Crowdstrike Allowlist Management",
                    "Success": True,
                    "UTCTimestamp": "2024-07-26 19:43:35.000000000",
                    "UserId": "wormtongue@isengard.org",
                    "UserIp": "1.2.3.4",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-26 19:43:35.082000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 366125,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Disabled Allow List Deleted",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "cidrs", "ValueString": "[0.0.0.0/8]"},
                        {"Key": "contexts", "ValueString": "[API]"},
                        {"Key": "active", "ValueString": "false"},
                        {"Key": "allowlist_group_id", "ValueString": "782f842e-98dd-4ee7-9793-33abf8647656"},
                        {"Key": "group_name", "ValueString": "my_allow_list"},
                        {"Key": "description", "ValueString": ""},
                    ],
                    "OperationName": "DeleteAllowlistGroup",
                    "ServiceName": "Crowdstrike Allowlist Management",
                    "Success": True,
                    "UTCTimestamp": "2024-07-26 19:43:35.000000000",
                    "UserId": "wormtongue@isengard.org",
                    "UserIp": "1.2.3.4",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-26 19:43:35.082000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 366125,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Allowlist Disabled",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "old_active", "ValueString": "true"},
                        {"Key": "group_name", "ValueString": "my_allow_list"},
                        {"Key": "old_group_name", "ValueString": "b"},
                        {"Key": "cidrs", "ValueString": "[1.2.3.4/8]"},
                        {"Key": "contexts", "ValueString": "[API UI]"},
                        {"Key": "active", "ValueString": "false"},
                        {"Key": "old_allowlist_group_id", "ValueString": "24821376-7e77-431e-9469-74846978fe64"},
                        {"Key": "old_description", "ValueString": ""},
                        {"Key": "old_cidrs", "ValueString": "[1.2.3.4/8]"},
                        {"Key": "allowlist_group_id", "ValueString": "24821376-7e77-431e-9469-74846978fe64"},
                        {"Key": "description", "ValueString": ""},
                        {"Key": "old_contexts", "ValueString": "[API UI]"},
                    ],
                    "OperationName": "UpdateAllowlistGroup",
                    "ServiceName": "Crowdstrike Allowlist Management",
                    "Success": True,
                    "UTCTimestamp": "2024-07-26 19:52:14.000000000",
                    "UserId": "wormtongue@isengard.org",
                    "UserIp": "1.2.3.4",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-26 19:52:14.438000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 366171,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Unrelated Event",
            expected_result=False,
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
    ]
