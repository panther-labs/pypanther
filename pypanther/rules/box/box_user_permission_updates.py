from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class BoxLargeNumberPermissionUpdates(Rule):
    id = "Box.Large.Number.Permission.Updates-prototype"
    display_name = "Box Large Number of Permission Changes"
    log_types = [LogType.BOX_EVENT]
    tags = ["Box", "Privilege Escalation:Abuse Elevation Control Mechanism"]
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    default_severity = Severity.LOW
    default_description = (
        "A user has exceeded the threshold for number of folder permission changes within a single time frame.\n"
    )
    default_reference = "https://support.box.com/hc/en-us/articles/360043697254-Understanding-Folder-Permissions"
    default_runbook = "Investigate whether this user's activity is expected.\n"
    summary_attributes = ["ip_address"]
    threshold = 100
    PERMISSION_UPDATE_EVENT_TYPES = {"CHANGE_FOLDER_PERMISSION", "ITEM_SHARED_CREATE", "ITEM_SHARED", "SHARE"}

    def rule(self, event):
        return event.get("event_type") in self.PERMISSION_UPDATE_EVENT_TYPES

    def title(self, event):
        return f"User [{event.deep_get('created_by', 'login', default='<UNKNOWN_USER>')}] exceeded threshold for number of permission changes in the configured time frame."

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
            name="User Permission Change",
            expected_result=True,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "CHANGE_FOLDER_PERMISSION",
                "source": {"id": "12345678", "type": "user", "login": "user@example", "name": "Bob Cat"},
            },
        ),
        RuleTest(
            name="User Shares Item",
            expected_result=True,
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "ITEM_SHARED_CREATE",
                "source": {"id": "12345678", "type": "user", "login": "user@example", "name": "Bob Cat"},
            },
        ),
    ]
