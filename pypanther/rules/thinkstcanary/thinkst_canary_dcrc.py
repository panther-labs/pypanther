from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class ThinkstCanaryDCRC(Rule):
    display_name = "Thinkst Canary DCRC"
    id = "Thinkst.CanaryDCRC-prototype"
    default_description = "A Canary has disconnected/reconnected."
    default_severity = Severity.HIGH
    log_types = [LogType.THINKSTCANARY_ALERT]

    def rule(self, event):
        return any(keyword in event.get("Intro", "") for keyword in ["disconnected", "reconnected"])

    def title(self, event):
        return event.get("Intro", "Canary Disconnected/Reconnected")

    def severity(self, event):
        if "reconnected" in event.get("Intro", ""):
            return "Low"
        return "Default"

    tests = [
        RuleTest(
            name="Canary Disconnected",
            expected_result=True,
            log={
                "CanaryID": "00029666d14d454f",
                "CanaryIP": "192.168.20.101",
                "CanaryName": "FS01",
                "Description": "Canary Disconnected",
                "IncidentKey": "incident:devicedied:3b04b62c54dcbb64d17131be::1718794923",
                "Intro": "One of your Canaries (FS01) previously at 192.168.20.101 has disconnected.",
                "MatchedAnnotations": {},
                "Timestamp": "2024-06-19 11:02:03 (UTC)",
            },
        ),
    ]
