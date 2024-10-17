from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.thinkstcanary import additional_details


@panther_managed
class ThinkstCanaryTokenIncident(Rule):
    display_name = "Thinkst Canarytoken Incident"
    id = "Thinkst.CanaryTokenIncident-prototype"
    default_description = "A Canarytoken incident has been detected."
    default_severity = Severity.HIGH
    log_types = [LogType.THINKSTCANARY_ALERT]

    def rule(self, event):
        return event.get("AlertType") == "CanarytokenIncident"

    def title(self, event):
        return event.get("Intro", "Canary Token Incident")

    def alert_context(self, event):
        return additional_details(event)

    tests = [
        RuleTest(
            name="Canarytoken Incident",
            expected_result=True,
            log={
                "AdditionalDetails": [
                    ["Background Context", "You have had 4 incidents from 123.123.123.123 previously."],
                    ["Dst Port", 80],
                    ["Event Name", "GetCallerIdentity"],
                    ["User-Agent", "TruffleHog"],
                ],
                "AlertType": "CanarytokenIncident",
                "Description": "AWS API Key Canarytoken triggered",
                "IncidentHash": "79cb967bde35e3b2d3b346844c16c4bf",
                "IncidentKey": "incident:canarytoken:94e08d45e5f2c8c13e7b99ae:123.123.123.123:1718797361",
                "Intro": "An AWS API Key Canarytoken was triggered by '123.123.123.123'.",
                "MatchedAnnotations": {
                    "trufflehog_scan": [
                        "This looks like a TruffleHog scan.",
                        "https://help.canary.tools/hc/en-gb/articles/18185364902813-Alert-Annotation-TruffleHog-Scan",
                    ],
                },
                "Reminder": "aws api key inside keepass",
                "SourceIP": "123.123.123.123",
                "Timestamp": "2024-06-19 11:42:41 (UTC)",
                "Token": "jf15ldk2jeaooi8dhlc6rgt9g",
                "Triggered": "2",
            },
        ),
    ]
