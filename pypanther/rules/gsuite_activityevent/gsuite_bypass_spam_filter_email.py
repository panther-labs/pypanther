from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gsuite import gsuite_activityevent_alert_context


@panther_managed
class GSuiteGmailEmailSpamFilterBypass(Rule):
    id = "GSuite.Gmail.Email.SpamFilter.Bypass-prototype"
    display_name = "Gsuite Email Bypassed Spam Filter"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    reports = {"MITRE ATT&CK": ["TA0001:T1566"]}
    default_severity = Severity.MEDIUM
    status = "Experimental"
    default_description = "Detects if an email received by a user has bypassed the organization's spam filter.\n"

    def rule(self, event):
        if event.deep_get("id", "applicationName", default="<UNKNOWN_APPLICATION>") != "gmail":
            return False
        return event.deep_get("parameters", "message_info", "message_set", "type", default=0) == 46

    def title(self, event):
        user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
        subject = event.deep_get("parameters", "message_info", "subject", default="<UNKNOWN_SUBJECT>")
        return f"Message [{subject}] received by user [{user}] has bypassed your organization's spam filter"

    def alert_context(self, event):
        return gsuite_activityevent_alert_context(event)

    tests = [
        RuleTest(
            name="Spam Bypass Email",
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
                        "link_domain": ["evil.com"],
                        "payload_size": 12345,
                        "subject": "You won 1 Million Dollar",
                        "message_set": {"type": 46},
                    },
                },
                "type": "delivery_type",
            },
        ),
        RuleTest(
            name="Other Email Event",
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
                        "link_domain": ["evil.com"],
                        "payload_size": 12345,
                        "subject": "You won 1 Million Dollar",
                        "message_set": {"type": 1},
                    },
                },
                "type": "delivery_type",
            },
        ),
    ]
