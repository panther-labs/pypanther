from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import box_parse_additional_details, deep_get
from pypanther.log_types import LogType

box_shield_suspicious_alert_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Regular Event",
        ExpectedResult=False,
        Log={
            "type": "event",
            "additional_details": '{"key": "value"}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "ceo@example",
                "name": "Bob Cat",
            },
            "event_type": "DELETE",
        },
    ),
    PantherRuleTest(
        Name="Suspicious Login Event",
        ExpectedResult=True,
        Log={
            "type": "event",
            "additional_details": '{"shield_alert":{"rule_category":"Suspicious Locations","risk_score":60,"user":{"email":"bob@example"}}}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "bob@example",
                "name": "Bob Cat",
            },
            "event_type": "SHIELD_ALERT",
            "source": {"id": "12345678", "type": "user"},
        },
    ),
    PantherRuleTest(
        Name="Suspicious Session Event",
        ExpectedResult=True,
        Log={
            "type": "event",
            "additional_details": '{"shield_alert":{"rule_category":"Suspicious Sessions","risk_score":70,"alert_summary":{"description":"First time in prior month user connected from ip 1.2.3.4."},"user":{"email":"bob@example"}}}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "bob@example",
                "name": "Bob Cat",
            },
            "event_type": "SHIELD_ALERT",
            "source": {"id": "12345678", "type": "user"},
        },
    ),
    PantherRuleTest(
        Name="Suspicious Session Event - Low Risk",
        ExpectedResult=False,
        Log={
            "type": "event",
            "additional_details": '{"shield_alert":{"rule_category":"Suspicious Sessions","risk_score":10,"alert_summary":{"description":"First time in prior month user connected from ip 1.2.3.4."},"user":{"email":"bob@example"}}}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "bob@example",
                "name": "Bob Cat",
            },
            "event_type": "SHIELD_ALERT",
            "source": {"id": "12345678", "type": "user"},
        },
    ),
]


class BoxShieldSuspiciousAlert(PantherRule):
    RuleID = "Box.Shield.Suspicious.Alert-prototype"
    DisplayName = "Box Shield Suspicious Alert Triggered"
    LogTypes = [LogType.Box_Event]
    Tags = ["Box", "Initial Access:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    Severity = PantherSeverity.High
    Description = (
        "A user login event or session event was tagged as medium to high severity by Box Shield.\n"
    )
    Reference = "https://developer.box.com/guides/events/shield-alert-events/"
    Runbook = "Investigate whether this was triggered by an expected user event.\n"
    SummaryAttributes = ["event_type", "ip_address"]
    Tests = box_shield_suspicious_alert_tests
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
