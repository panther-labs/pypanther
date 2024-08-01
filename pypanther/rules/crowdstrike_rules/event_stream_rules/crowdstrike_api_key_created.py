from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.crowdstrike_event_streams_helpers import cs_alert_context

crowdstrike_api_key_created_tests: list[RuleTest] = [
    RuleTest(
        name="API Key Created",
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
                "OperationName": "CreateAPIClient",
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
]


@panther_managed
class CrowdstrikeAPIKeyCreated(Rule):
    id = "Crowdstrike.API.Key.Created-prototype"
    display_name = "Crowdstrike API Key Created"
    reports = {"MITRE ATT&CK": ["T1098.001"]}
    log_types = [LogType.CROWDSTRIKE_EVENT_STREAMS]
    default_severity = Severity.MEDIUM
    default_description = "A user created an API Key in CrowdStrike"
    default_runbook = "Reach out to the user if needed to validate the activity."
    tests = crowdstrike_api_key_created_tests

    def rule(self, event):
        return all([event.deep_get("event", "OperationName") == "CreateAPIClient", event.deep_get("event", "Success")])

    def title(self, event):
        user = event.deep_get("event", "UserId")
        service = event.deep_get("event", "ServiceName")
        return f"{user} created a new API key in {service}"

    def alert_context(self, event):
        return cs_alert_context(event)
