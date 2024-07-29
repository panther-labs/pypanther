from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import box_parse_additional_details, deep_get

box_shield_suspicious_alert_tests: list[RuleTest] = [
    RuleTest(
        name="Regular Event",
        expected_result=False,
        log={
            "type": "event",
            "additional_details": '{"key": "value"}',
            "created_by": {"id": "12345678", "type": "user", "login": "ceo@example", "name": "Bob Cat"},
            "event_type": "DELETE",
        },
    ),
    RuleTest(
        name="Suspicious Login Event",
        expected_result=True,
        log={
            "type": "event",
            "additional_details": '{"shield_alert":{"rule_category":"Suspicious Locations","risk_score":60,"user":{"email":"bob@example"}}}',
            "created_by": {"id": "12345678", "type": "user", "login": "bob@example", "name": "Bob Cat"},
            "event_type": "SHIELD_ALERT",
            "source": {"id": "12345678", "type": "user"},
        },
    ),
    RuleTest(
        name="Suspicious Session Event",
        expected_result=True,
        log={
            "type": "event",
            "additional_details": '{"shield_alert":{"rule_category":"Suspicious Sessions","risk_score":70,"alert_summary":{"description":"First time in prior month user connected from ip 1.2.3.4."},"user":{"email":"bob@example"}}}',
            "created_by": {"id": "12345678", "type": "user", "login": "bob@example", "name": "Bob Cat"},
            "event_type": "SHIELD_ALERT",
            "source": {"id": "12345678", "type": "user"},
        },
    ),
    RuleTest(
        name="Suspicious Session Event - Low Risk",
        expected_result=False,
        log={
            "type": "event",
            "additional_details": '{"shield_alert":{"rule_category":"Suspicious Sessions","risk_score":10,"alert_summary":{"description":"First time in prior month user connected from ip 1.2.3.4."},"user":{"email":"bob@example"}}}',
            "created_by": {"id": "12345678", "type": "user", "login": "bob@example", "name": "Bob Cat"},
            "event_type": "SHIELD_ALERT",
            "source": {"id": "12345678", "type": "user"},
        },
    ),
]


@panther_managed
class BoxShieldSuspiciousAlert(Rule):
    id = "Box.Shield.Suspicious.Alert-prototype"
    display_name = "Box Shield Suspicious Alert Triggered"
    log_types = [LogType.BOX_EVENT]
    tags = ["Box", "Initial Access:Valid Accounts"]
    reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    default_severity = Severity.HIGH
    default_description = "A user login event or session event was tagged as medium to high severity by Box Shield.\n"
    default_reference = "https://developer.box.com/guides/events/shield-alert-events/"
    default_runbook = "Investigate whether this was triggered by an expected user event.\n"
    summary_attributes = ["event_type", "ip_address"]
    tests = box_shield_suspicious_alert_tests
    SUSPICIOUS_EVENT_TYPES = {"Suspicious Locations", "Suspicious Sessions"}

    def rule(self, event):
        if event.get("event_type") != "SHIELD_ALERT":
            return False
        alert_details = box_parse_additional_details(event).get("shield_alert", {})
        if alert_details.get("rule_category", "") in self.SUSPICIOUS_EVENT_TYPES:
            if alert_details.get("risk_score", 0) > 50:
                return True
        return False

    def title(self, event):
        details = box_parse_additional_details(event)
        description = deep_get(details, "shield_alert", "alert_summary", "description", default="")
        if description:
            return description
        return f"Shield medium to high risk, suspicious event alert triggered for user [{deep_get(details, 'shield_alert', 'user', 'email', default='<UNKNOWN_USER>')}]"
