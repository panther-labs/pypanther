from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.thinkstcanary import additional_details


@panther_managed
class ThinkstCanaryIncident(Rule):
    display_name = "Thinkst Canary Incident"
    id = "Thinkst.CanaryIncident-prototype"
    default_description = "A Canary incident has been detected."
    default_severity = Severity.HIGH
    log_types = [LogType.THINKSTCANARY_ALERT]

    def rule(self, event):
        return event.get("AlertType") == "CanaryIncident"

    def title(self, event):
        return event.get("Intro", "Canary Incident")

    def alert_context(self, event):
        return additional_details(event)

    tests = [
        RuleTest(
            name="Canary Incident",
            expected_result=True,
            log={
                "AdditionalDetails": [
                    ["User", "guest"],
                    ["Filename", "IT/Default Windows Desktop Configuration.docx"],
                    ["Background Context", "You have had 2 incidents from 192.168.110.14 previously."],
                ],
                "AlertType": "CanaryIncident",
                "CanaryID": "000222326791e1e8",
                "CanaryIP": "192.168.110.27",
                "CanaryLocation": "Server room A",
                "CanaryName": "VirtualCanary-unnamed",
                "CanaryPort": 445,
                "Description": "Shared File Opened",
                "IncidentHash": "f78b692a7716d0d668012bc0eb65c367",
                "IncidentKey": "incident:smbfileopen:89d38322e4e764e202b42bbb:192.168.110.14:1717059335",
                "Intro": "Shared File Opened has been detected against one of your Canaries (VirtualCanary-unnamed) at 192.168.110.27.",
                "ReverseDNS": "",
                "SourceIP": "192.168.110.14",
                "Timestamp": "2024-05-30 08:55:35 (UTC)",
            },
        ),
    ]
