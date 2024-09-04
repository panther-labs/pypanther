from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.crowdstrike_event_streams import audit_keys_dict, cs_alert_context, str_to_list


@panther_managed
class CrowdstrikeIpAllowlistChanged(Rule):
    id = "Crowdstrike.IpAllowlistChanged-prototype"
    display_name = "Crowdstrike IP Allowlist Changed"
    log_types = [LogType.CROWDSTRIKE_EVENT_STREAMS]
    default_severity = Severity.INFO
    create_alert = False
    reports = {"MITRE ATT&CK": ["TA0003:T1556.009", "TA0005:T1556.009", "TA0006:T1556.009"]}
    default_description = "Updates were made to Falcon console's allowlist. This could indicate a bad actor permitting access from another machine, or could be attackers preventing legitimate actors from accessing the console."
    default_runbook = "Validate this action was authorized."

    def rule(self, event):
        # Only alert if an allow list is created or edited
        op_name = event.deep_get("event", "OperationName")
        if op_name not in ("CreateAllowlistGroup", "UpdateAllowlistGroup"):
            return False
        return True

    def title(self, event):
        actor = event.deep_get("event", "UserId")
        action = {"CreateAllowlistGroup": "created a new", "UpdateAllowlistGroup": "made changes to"}.get(
            event.deep_get("event", "OperationName"),
        )
        group = audit_keys_dict(event).get("group_name", "UNKNWOWN GROUP")
        return f"{actor} {action} Crowdstrike IP allowlist group: {group}"

    def alert_context(self, event):
        context = cs_alert_context(event)
        # Be nice and concert the "lists" into actual lists so customers can easily process the alert
        #   context
        for key in ("cidrs", "old_cidrs", "contexts", "old_contexts"):
            if context.get(key):
                try:
                    context[key] = str_to_list(context[key])
                except ValueError:
                    pass  # Just ignore if we can't unmarshal it
        # Find out what entries were removed, and which were added
        op_name = event.deep_get("event", "OperationName")
        audit_keys = audit_keys_dict(event)
        added_cidrs = []
        removed_cidrs = []
        added_contexts = []
        removed_contexts = []

        def getlist(key: str):
            return str_to_list(audit_keys.get(key))

        match op_name:
            case "UpdateAllowlistGroup":
                new_cidrs = getlist("cidrs")
                old_cidrs = getlist("old_cidrs")
                new_ctx = getlist("contexts")
                old_ctx = getlist("old_contexts")
                added_cidrs = self.get_unique_entries(new_cidrs, old_cidrs)
                removed_cidrs = self.get_unique_entries(old_cidrs, new_cidrs)
                added_contexts = self.get_unique_entries(new_ctx, old_ctx)
                removed_contexts = self.get_unique_entries(old_ctx, new_ctx)
            case "CreateAllowlistGroup":
                added_cidrs = str_to_list(audit_keys.get("cidrs", []))
                added_contexts = str_to_list(audit_keys.get("contexts", []))
        context.update(
            {
                "changes": {
                    "cidr_added": added_cidrs,
                    "cidr_removed": removed_cidrs,
                    "context_added": added_contexts,
                    "context_removed": removed_contexts,
                },
            },
        )
        return context

    def get_unique_entries(self, list1: list, list2: list) -> list:
        """Returns items in l1 that are not in l2."""
        return list(set(list1) - set(list2))

    tests = [
        RuleTest(
            name="A Single IP In Created Allowlist",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "allowlist_group_id", "ValueString": "24821376-7e77-431e-9469-74846978fe64"},
                        {"Key": "group_name", "ValueString": "example_group"},
                        {"Key": "description", "ValueString": ""},
                        {"Key": "cidrs", "ValueString": "[1.1.1.1]"},
                        {"Key": "contexts", "ValueString": "[API]"},
                        {"Key": "active", "ValueString": "false"},
                    ],
                    "OperationName": "CreateAllowlistGroup",
                    "ServiceName": "Crowdstrike Allowlist Management",
                    "Success": True,
                    "UTCTimestamp": "2024-07-26 16:13:13.000000000",
                    "UserId": "wormtongue@isengard.org",
                    "UserIp": "1.2.3.4",
                },
                "metadata": {
                    "customerIDString": "fake_cust_id",
                    "eventCreationTime": "2024-07-26 16:13:13.579000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 365164,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Multiple Single IPs In Created Allowlist",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "allowlist_group_id", "ValueString": "24821376-7e77-431e-9469-74846978fe64"},
                        {"Key": "group_name", "ValueString": "example_group"},
                        {"Key": "description", "ValueString": ""},
                        {"Key": "cidrs", "ValueString": "[1.1.1.1 2.2.2.2 3.3.3.3/32]"},
                        {"Key": "contexts", "ValueString": "[API UI OTHER]"},
                        {"Key": "active", "ValueString": "false"},
                    ],
                    "OperationName": "CreateAllowlistGroup",
                    "ServiceName": "Crowdstrike Allowlist Management",
                    "Success": True,
                    "UTCTimestamp": "2024-07-26 16:13:13.000000000",
                    "UserId": "wormtongue@isengard.org",
                    "UserIp": "1.2.3.4",
                },
                "metadata": {
                    "customerIDString": "fake_cust_id",
                    "eventCreationTime": "2024-07-26 16:13:13.579000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 365164,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Single IP Added to existing Allowlist",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "old_group_name", "ValueString": "my_allowlist"},
                        {"Key": "old_cidrs", "ValueString": "[1.2.3.4/8]"},
                        {"Key": "allowlist_group_id", "ValueString": "24821376-7e77-431e-9469-74846978fe64"},
                        {"Key": "group_name", "ValueString": "my_allowlist"},
                        {"Key": "description", "ValueString": ""},
                        {"Key": "cidrs", "ValueString": "[1.2.3.4/8 32.32.32.32]"},
                        {"Key": "contexts", "ValueString": "[API]"},
                        {"Key": "active", "ValueString": "false"},
                        {"Key": "old_allowlist_group_id", "ValueString": "24821376-7e77-431e-9469-74846978fe64"},
                        {"Key": "old_description", "ValueString": ""},
                        {"Key": "old_contexts", "ValueString": "[API]"},
                        {"Key": "old_active", "ValueString": "false"},
                    ],
                    "OperationName": "UpdateAllowlistGroup",
                    "ServiceName": "Crowdstrike Allowlist Management",
                    "Success": True,
                    "UTCTimestamp": "2024-07-26 19:47:16.000000000",
                    "UserId": "wormtongue@isengard.org",
                    "UserIp": "1.2.3.4",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-26 19:47:16.428000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 366148,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="CIDR Removed from existing Allowlist",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "old_group_name", "ValueString": "my_allowlist"},
                        {"Key": "old_cidrs", "ValueString": "[1.2.3.4/8 8.8.8.8/12]"},
                        {"Key": "allowlist_group_id", "ValueString": "24821376-7e77-431e-9469-74846978fe64"},
                        {"Key": "group_name", "ValueString": "my_allowlist"},
                        {"Key": "description", "ValueString": ""},
                        {"Key": "cidrs", "ValueString": "[1.2.3.4/8]"},
                        {"Key": "contexts", "ValueString": "[API]"},
                        {"Key": "active", "ValueString": "false"},
                        {"Key": "old_allowlist_group_id", "ValueString": "24821376-7e77-431e-9469-74846978fe64"},
                        {"Key": "old_description", "ValueString": ""},
                        {"Key": "old_contexts", "ValueString": "[API]"},
                        {"Key": "old_active", "ValueString": "false"},
                    ],
                    "OperationName": "UpdateAllowlistGroup",
                    "ServiceName": "Crowdstrike Allowlist Management",
                    "Success": True,
                    "UTCTimestamp": "2024-07-26 19:47:16.000000000",
                    "UserId": "wormtongue@isengard.org",
                    "UserIp": "1.2.3.4",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-26 19:47:16.428000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 366148,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Only CIDR Ranges In Created Allowlist",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "allowlist_group_id", "ValueString": "24821376-7e77-431e-9469-74846978fe64"},
                        {"Key": "group_name", "ValueString": "example_group"},
                        {"Key": "description", "ValueString": ""},
                        {"Key": "cidrs", "ValueString": "[1.1.1.1/12 2.2.2.2/8 3.3.3.3/4]"},
                        {"Key": "contexts", "ValueString": "[API UI OTHER]"},
                        {"Key": "active", "ValueString": "false"},
                    ],
                    "OperationName": "CreateAllowlistGroup",
                    "ServiceName": "Crowdstrike Allowlist Management",
                    "Success": True,
                    "UTCTimestamp": "2024-07-26 16:13:13.000000000",
                    "UserId": "wormtongue@isengard.org",
                    "UserIp": "1.2.3.4",
                },
                "metadata": {
                    "customerIDString": "fake_cust_id",
                    "eventCreationTime": "2024-07-26 16:13:13.579000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 365164,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Unrelated Event",
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
                    "Success": True,
                    "UTCTimestamp": "2024-07-22 15:50:16.923000000",
                    "AuditKeyValues": [{"Key": "target_name", "ValueString": "frodo.baggins@hobbiton.co"}],
                },
            },
        ),
    ]
