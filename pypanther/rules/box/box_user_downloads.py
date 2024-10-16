from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class BoxLargeNumberDownloads(Rule):
    id = "Box.Large.Number.Downloads-prototype"
    display_name = "Box Large Number of Downloads"
    log_types = [LogType.BOX_EVENT]
    tags = ["Box", "Exfiltration:Exfiltration Over Web Service"]
    reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    default_severity = Severity.LOW
    default_description = "A user has exceeded the threshold for number of downloads within a single time frame.\n"
    default_reference = "https://support.box.com/hc/en-us/articles/360043697134-Download-Files-and-Folders-from-Box"
    default_runbook = "Investigate whether this user's download activity is expected.  Investigate the cause of this download activity.\n"
    summary_attributes = ["ip_address"]
    threshold = 100

    def rule(self, event):
        return event.get("event_type") == "DOWNLOAD"

    def title(self, event):
        return f"User [{event.deep_get('created_by', 'login', default='<UNKNOWN_USER>')}] exceeded threshold for number of downloads in the configured time frame."

    tests = [
        RuleTest(
            name="Regular Event",
            expected_result=False,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "DELETE",
            },
        ),
        RuleTest(
            name="User Download",
            expected_result=True,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "DOWNLOAD",
                "source": {"id": "12345678", "type": "user", "login": "user@example", "name": "Bob Cat"},
            },
        ),
    ]
