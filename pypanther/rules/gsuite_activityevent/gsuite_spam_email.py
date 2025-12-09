from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gsuite import gsuite_activityevent_alert_context


@panther_managed
class GSuiteGmailSpamEmailSurge(Rule):
    id = "GSuite.Gmail.Spam.Email.Surge-prototype"
    display_name = "Spam Email Surge"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    reports = {"MITRE ATT&CK": ["TA0001:T1566", "TA0043:T1598"]}
    default_severity = Severity.MEDIUM
    status = "Experimental"
    default_description = "Detects a high number of spam emails received by a single user in a short timeframe. This could indicate the user's email has appeared in data leaks and is being targeted for spam.\n"
    threshold = 20

    def rule(self, event):
        if event.deep_get("id", "applicationName", default="<UNKNOWN_APPLICATION>") != "gmail":
            return False
        return event.deep_get("parameters", "message_info", "is_spam", default=False) is True

    def title(self, event):
        user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
        return f"Surge in spam emails received by user [{user}]"

    def alert_context(self, event):
        return gsuite_activityevent_alert_context(event)

    tests = [
        RuleTest(
            name="Spam Email",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["1.1.1.1"],
                "p_any_actor_ids": ["1234567891234"],
                "p_any_domain_names": ["evil.com"],
                "p_event_time": "2025-11-04 20:44:43.248000000",
                "p_log_type": "GSuite.ActivityEvent",
                "p_parse_time": "2025-11-04 20:49:46.688935963",
                "p_row_id": "0000000000de09c1dc6f0828cbad2ca5",
                "p_schema_version": 0,
                "p_source_id": "7ee69d4d-df1b-40b3-b5e8-6826dee34b1c",
                "p_source_label": "Google Workspace",
                "p_udm": {"source": {"address": "1.1.1.1", "ip": "1.1.1.1"}, "user": {"provider_id": "123456789"}},
                "actor": {"callerType": "USER", "email": "denethor@lotr.com", "profileId": "123456789"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "1A2B3C",
                    "time": "2025-11-04 20:44:43.248000000",
                    "uniqueQualifier": "-123456789",
                },
                "ipAddress": "1.1.1.1",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 368746, "timestamp_usec": 1762289083248347},
                    "message_info": {
                        "action_type": 19,
                        "flattened_destinations": "gmail-for-work-catchall::denethor@lotr.com",
                        "is_spam": True,
                        "link_domain": ["evil.com"],
                        "payload_size": 12345,
                        "subject": "You won 1 Million Dollar",
                    },
                },
                "type": "delivery_type",
            },
        ),
        RuleTest(
            name="Normal Email",
            expected_result=False,
            log={
                "p_any_ip_addresses": ["1.1.1.1"],
                "p_any_actor_ids": ["1234567891234"],
                "p_any_domain_names": ["evil.com"],
                "p_event_time": "2025-11-04 20:44:43.248000000",
                "p_log_type": "GSuite.ActivityEvent",
                "p_parse_time": "2025-11-04 20:49:46.688935963",
                "p_row_id": "165c80e3df1fc1cb9fb49af829c4fe26",
                "p_schema_version": 0,
                "p_source_id": "7ee69d4d-df1b-40b3-b5e8-6826dee34b1c",
                "p_source_label": "Google Workspace",
                "p_udm": {"source": {"address": "1.1.1.1", "ip": "1.1.1.1"}, "user": {"provider_id": "123456789"}},
                "actor": {"callerType": "USER", "email": "aragorn@lotr.com", "profileId": "123456789"},
                "id": {
                    "applicationName": "gmail",
                    "customerId": "1A2B3C",
                    "time": "2025-11-04 20:44:43.248000000",
                    "uniqueQualifier": "-123456789",
                },
                "ipAddress": "1.1.1.1",
                "kind": "admin#reports#activity",
                "name": "delivery",
                "parameters": {
                    "event_info": {"elapsed_time_usec": 368746, "timestamp_usec": 1762289083248347},
                    "message_info": {
                        "action_type": 19,
                        "flattened_destinations": "gmail-for-work-catchall::aragorn@lotr.com",
                        "is_spam": False,
                        "link_domain": ["good.com"],
                        "payload_size": 12345,
                        "subject": "Normal Email",
                    },
                },
                "type": "delivery_type",
            },
        ),
    ]
