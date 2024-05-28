from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import box_parse_additional_details, deep_get
from pypanther.log_types import LogType

box_shield_anomalous_download_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Regular Event",
        ExpectedResult=False,
        Log={
            "type": "event",
            "additional_details": {'"key": "value"': None},
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "cat@example",
                "name": "Bob Cat",
            },
            "event_type": "DELETE",
        },
    ),
    PantherRuleTest(
        Name="Anomalous Download Event",
        ExpectedResult=True,
        Log={
            "type": "event",
            "additional_details": '{"shield_alert":{"rule_category":"Anomalous Download","risk_score":77,"alert_summary":{"description":"Significant increase in download content week over week, 9999% (50.00 MB) more than last week."}}}',
            "created_by": {
                "id": "12345678",
                "type": "user",
                "login": "bob@example",
                "name": "Bob Cat",
            },
            "event_type": "SHIELD_ALERT",
            "source": {"id": "12345678", "type": "user", "login": "bob@example", "name": "Bob Cat"},
        },
    ),
]


class BoxShieldAnomalousDownload(PantherRule):
    RuleID = "Box.Shield.Anomalous.Download-prototype"
    DisplayName = "Box Shield Detected Anomalous Download Activity"
    LogTypes = [LogType.Box_Event]
    Tags = ["Box", "Exfiltration:Exfiltration Over Web Service"]
    Reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    Severity = PantherSeverity.High
    Description = "A user's download activity has altered significantly.\n"
    Reference = "https://developer.box.com/guides/events/shield-alert-events/"
    Runbook = "Investigate whether this was triggered by expected user download activity.\n"
    SummaryAttributes = ["event_type", "ip_address"]
    Tests = box_shield_anomalous_download_tests

    def rule(self, event):
        if event.get("event_type") != "SHIELD_ALERT":
            return False
        alert_details = box_parse_additional_details(event).get("shield_alert", {})
        if alert_details.get("rule_category", "") == "Anomalous Download":
            if alert_details.get("risk_score", 0) > 50:
                return True
        return False

    def title(self, event):
        details = box_parse_additional_details(event)
        description = deep_get(details, "shield_alert", "alert_summary", "description")
        if description:
            return description
        return f"Anomalous download activity triggered by user [{deep_get(event, 'created_by', 'name', default='<UNKNOWN_USER>')}]."
