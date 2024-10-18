from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.config import config


@panther_managed
class BoxEventTriggeredExternally(Rule):
    id = "Box.Event.Triggered.Externally-prototype"
    display_name = "Box event triggered by unknown or external user"
    enabled = False
    log_types = [LogType.BOX_EVENT]
    tags = ["Box", "Exfiltration:Exfiltration Over Web Service", "Configuration Required"]
    reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    default_severity = Severity.MEDIUM
    default_description = "An external user has triggered a box enterprise event.\n"
    default_reference = "https://support.box.com/hc/en-us/articles/8391393127955-Using-the-Enterprise-Event-Stream"
    default_runbook = "Investigate whether this user's activity is expected.\n"
    summary_attributes = ["ip_address"]
    threshold = 10
    DOMAINS = {"@" + domain for domain in config.ORGANIZATION_DOMAINS}

    def rule(self, event):
        # Check that all events are triggered by internal users
        if event.get("event_type") not in ("FAILED_LOGIN", "SHIELD_ALERT"):
            user = event.get("created_by", {})
            # user id 2 indicates an anonymous user
            if user.get("id", "") == "2":
                return True
            return bool(user.get("login") and (not any(user.get("login", "").endswith(x) for x in self.DOMAINS)))
        return False

    def title(self, event):
        return (
            f"External user [{event.deep_get('created_by', 'login', default='<UNKNOWN_USER>')}] triggered a box event."
        )

    tests = [
        RuleTest(
            name="Regular Event",
            expected_result=False,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example.com", "name": "Bob Cat"},
                "event_type": "DELETE",
            },
        ),
        RuleTest(
            name="Previewed Anonymously",
            expected_result=True,
            log={
                "created_by": {"id": "2", "type": "user", "name": "Unknown User"},
                "event_type": "PREVIEW",
                "type": "event",
                "ip_address": "1.2.3.4",
            },
        ),
        RuleTest(
            name="Missing Created By",
            expected_result=False,
            log={"event_type": "PREVIEW", "type": "event", "ip_address": "1.2.3.4"},
        ),
    ]
