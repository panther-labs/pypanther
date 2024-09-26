from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.crowdstrike_event_streams import audit_keys_dict, cs_alert_context, str_to_list


@panther_managed
class CrowdstrikeSingleIpAllowlisted(Rule):
    id = "Crowdstrike.SingleIpAllowlisted-prototype"
    display_name = "Crowdstrike Single IP Allowlisted"
    log_types = [LogType.CROWDSTRIKE_EVENT_STREAMS]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0003:T1556.009", "TA0005:T1556.009", "TA0006:T1556.009"]}
    default_description = "A single IP (instead of a CIDR range) was allowlisted. This could indicate a bad actor permitting access from another machine."
    default_runbook = "Validate this action was authorized, and determine the client to which the IP belongs to."

    def get_single_ips(self, event, fieldname="cidrs") -> list[str]:
        """
        Searches the "cidrs" field of the event audit keys, and returns any cidr entries which
        are actually just single IP addresses.
        """
        single_ips = []
        audit_keys = audit_keys_dict(event)
        cidrs = str_to_list(audit_keys.get(fieldname, []))
        for entry in cidrs:
            if "/" not in entry:
                single_ips.append(entry)
            elif entry.endswith("/32"):
                # A 32-bit CIDR range is the same as a single IP address
                single_ips.append(entry[:-3])
        return single_ips

    def rule(self, event):
        # Only alert if an allow list is created or edited
        op_name = event.deep_get("event", "OperationName")
        if op_name not in ("CreateAllowlistGroup", "UpdateAllowlistGroup"):
            return False
        # Only alert if there's a single IP address allowed by the allowlist
        single_ips = self.get_single_ips(event)
        if op_name == "UpdateAllowlistGroup":
            # Remove IPs from single_ips if the weren't recently added
            old_single_ips = set(self.get_single_ips(event, "old_cidrs"))
            single_ips = [ip for ip in single_ips if ip not in old_single_ips]
        # Return true if there were any single IPs
        return len(single_ips) > 0

    def title(self, event):
        # Title format: {actor} granted {contexts_str} access to {a, X} single ip{s}
        single_ips = self.get_single_ips(event)
        actor = event.deep_get("event", "UserId")
        # contexts_str: one of API, UI, or API & UI
        #   Also a more general case: API, UI, and XX (for if they add extra contexts in the future)
        contexts = str_to_list(audit_keys_dict(event).get("contexts", ""))
        if len(contexts) == 0:
            contexts_str = "no contexts"
        elif len(contexts) == 1:
            contexts_str = contexts[0]
        else:
            contexts_str = ", ".join(contexts[:-1]) + " & " + contexts[-1]
        num_ips_str = "a single ip" if len(contexts) == 1 else f"{len(single_ips)} single ips"
        return f"{actor} granted {contexts_str} access to {num_ips_str}"

    def alert_context(self, event):
        context = cs_alert_context(event)
        context.update({"single_ips": self.get_single_ips(event)})
        return context

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
            name="Only CIDR Ranges In Created Allowlist",
            expected_result=False,
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
