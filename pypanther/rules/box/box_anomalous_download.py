from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import deep_get
from pypanther.helpers.box import box_parse_additional_details


@panther_managed
class BoxShieldAnomalousDownload(Rule):
    id = "Box.Shield.Anomalous.Download-prototype"
    display_name = "Box Shield Detected Anomalous Download Activity"
    log_types = [LogType.BOX_EVENT]
    tags = ["Box", "Exfiltration:Exfiltration Over Web Service"]
    reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    default_severity = Severity.HIGH
    default_description = "A user's download activity has altered significantly.\n"
    default_reference = "https://developer.box.com/guides/events/shield-alert-events/"
    default_runbook = "Investigate whether this was triggered by expected user download activity.\n"
    summary_attributes = ["event_type", "ip_address"]

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
        return f"Anomalous download activity triggered by user [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}]."

    tests = [
        RuleTest(
            name="Regular Event",
            expected_result=False,
            log={
                "type": "event",
                "additional_details": {'"key": "value"': None},
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "DELETE",
            },
        ),
        RuleTest(
            name="Anomalous Download Event",
            expected_result=True,
            log={
                "type": "event",
                "additional_details": '{"shield_alert":{"rule_category":"Anomalous Download","risk_score":77,"alert_summary":{"description":"Significant increase in download content week over week, 9999% (50.00 MB) more than last week."}}}',
                "created_by": {"id": "12345678", "type": "user", "login": "bob@example", "name": "Bob Cat"},
                "event_type": "SHIELD_ALERT",
                "source": {"id": "12345678", "type": "user", "login": "bob@example", "name": "Bob Cat"},
            },
        ),
    ]
