from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.crowdstrike_event_streams import cs_alert_context


@panther_managed
class CrowdstrikeAPIKeyDeleted(Rule):
    id = "Crowdstrike.API.Key.Deleted-prototype"
    display_name = "Crowdstrike API Key Deleted"
    reports = {"MITRE ATT&CK": ["TA0040:T1531", "TA0005:T1070"]}
    log_types = [LogType.CROWDSTRIKE_EVENT_STREAMS]
    default_severity = Severity.MEDIUM
    default_description = "A user deleted an API Key in CrowdStrike"
    default_runbook = "Validate this action was authorized."

    def rule(self, event):
        return all([event.deep_get("event", "OperationName") == "DeleteAPIClients", event.deep_get("event", "Success")])

    def title(self, event):
        user = event.deep_get("event", "UserId")
        service = event.deep_get("event", "ServiceName")
        return f"{user} deleted an API key in {service}"

    def alert_context(self, event):
        return cs_alert_context(event)

    tests = [
        RuleTest(
            name="API Key Deleted",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "scope(s)", "ValueString": "alerts:read,api-integrations:read"},
                        {"Key": "actor_user", "ValueString": "tester@panther.com"},
                        {"Key": "actor_user_uuid", "ValueString": "a11a1111-1a11-1a1a-1a11-a11a111a111a"},
                        {"Key": "actor_cid", "ValueString": "aaa111111111111111aaaaaa11a11a11"},
                        {"Key": "trace_id", "ValueString": "1a111111-a1a1-111a-11aa-a111111a1a1a"},
                        {"Key": "APIClientID", "ValueString": "aaa1a11aaa111a1a11a11aaaa1aa1a11"},
                        {"Key": "id", "ValueString": "aaa1a11aaa111a1a11a11aaaa1aa1a11"},
                        {"Key": "name", "ValueString": "key name"},
                    ],
                    "OperationName": "DeleteAPIClients",
                    "ServiceName": "Crowdstrike API Client",
                    "Success": True,
                    "UTCTimestamp": "2024-07-08 14:01:54.000000000",
                    "UserId": "tester@panther.com",
                    "UserIp": "11.1.111.11",
                },
                "metadata": {
                    "customerIDString": "aaa111111111111111aaaaaa11a11a11",
                    "eventCreationTime": "2024-07-08 14:01:54.451000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 111111,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="API Key Delete failed",
            expected_result=False,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "scope(s)", "ValueString": "alerts:read,api-integrations:read"},
                        {"Key": "actor_user", "ValueString": "tester@panther.com"},
                        {"Key": "actor_user_uuid", "ValueString": "a11a1111-1a11-1a1a-1a11-a11a111a111a"},
                        {"Key": "actor_cid", "ValueString": "aaa111111111111111aaaaaa11a11a11"},
                        {"Key": "trace_id", "ValueString": "1a111111-a1a1-111a-11aa-a111111a1a1a"},
                        {"Key": "APIClientID", "ValueString": "aaa1a11aaa111a1a11a11aaaa1aa1a11"},
                        {"Key": "id", "ValueString": "aaa1a11aaa111a1a11a11aaaa1aa1a11"},
                        {"Key": "name", "ValueString": "key name"},
                    ],
                    "OperationName": "DeleteAPIClients",
                    "ServiceName": "Crowdstrike API Client",
                    "Success": False,
                    "UTCTimestamp": "2024-07-08 14:01:54.000000000",
                    "UserId": "tester@panther.com",
                    "UserIp": "11.1.111.11",
                },
                "metadata": {
                    "customerIDString": "aaa111111111111111aaaaaa11a11a11",
                    "eventCreationTime": "2024-07-08 14:01:54.451000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 111111,
                    "version": "1.0",
                },
            },
        ),
    ]
