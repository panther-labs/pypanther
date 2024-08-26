from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

g_suite_workspace_calendar_external_sharing_setting_tests: list[RuleTest] = [
    RuleTest(
        name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
        expected_result=True,
        log={
            "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-11 01:06:26.303000000",
                "uniqueQualifier": "-12345",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "CHANGE_CALENDAR_SETTING",
            "parameters": {
                "DOMAIN_NAME": "example.io",
                "NEW_VALUE": "READ_ONLY_ACCESS",
                "OLD_VALUE": "DEFAULT",
                "ORG_UNIT_NAME": "Example IO",
                "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN",
            },
            "type": "CALENDAR_SETTINGS",
        },
    ),
    RuleTest(
        name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_WRITE_ACCESS",
        expected_result=True,
        log={
            "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-11 01:06:26.303000000",
                "uniqueQualifier": "-12345",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "CHANGE_CALENDAR_SETTING",
            "parameters": {
                "DOMAIN_NAME": "example.io",
                "NEW_VALUE": "READ_WRITE_ACCESS",
                "OLD_VALUE": "READ_ONLY_ACCESS",
                "ORG_UNIT_NAME": "Example IO",
                "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN",
            },
            "type": "CALENDAR_SETTINGS",
        },
    ),
    RuleTest(
        name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
        expected_result=True,
        log={
            "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-11 01:06:26.303000000",
                "uniqueQualifier": "-12345",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "CHANGE_CALENDAR_SETTING",
            "parameters": {
                "DOMAIN_NAME": "example.io",
                "NEW_VALUE": "MANAGE_ACCESS",
                "OLD_VALUE": "READ_WRITE_ACCESS",
                "ORG_UNIT_NAME": "Example IO",
                "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN",
            },
            "type": "CALENDAR_SETTINGS",
        },
    ),
    RuleTest(
        name="Non-Default Calendar SHARING_OUTSIDE_DOMAIN event",
        expected_result=False,
        log={
            "actor": {"callerType": "USER", "email": "user@example.io", "profileId": "111111111111111111111"},
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-12 22:21:40.106000000",
                "uniqueQualifier": "1000000000000000000",
            },
            "kind": "admin#reports#activity",
            "name": "CUSTOMER_TAKEOUT_SUCCEEDED",
            "parameters": {"OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID": "00mmmmmmmmmmmmm"},
            "type": "CUSTOMER_TAKEOUT",
        },
    ),
    RuleTest(
        name="ListObject Type",
        expected_result=False,
        log={
            "actor": {"email": "user@example.io", "profileId": "118111111111111111111"},
            "id": {
                "applicationName": "drive",
                "customerId": "D12345",
                "time": "2022-12-20 17:27:47.080000000",
                "uniqueQualifier": "-7312729053723258069",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "rename",
            "parameters": {
                "actor_is_collaborator_account": None,
                "billable": True,
                "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
                "doc_title": "Document Title- Found Here",
                "doc_type": "presentation",
                "is_encrypted": None,
                "new_value": ["Document Title- Found Here"],
                "old_value": ["Document Title- Old"],
                "owner": "user@example.io",
                "owner_is_shared_drive": None,
                "owner_is_team_drive": None,
                "primary_event": True,
                "visibility": "private",
            },
            "type": "access",
        },
    ),
]


@panther_managed
class GSuiteWorkspaceCalendarExternalSharingSetting(Rule):
    id = "GSuite.Workspace.CalendarExternalSharingSetting-prototype"
    display_name = "GSuite Workspace Calendar External Sharing Setting Change"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    reports = {"MITRE ATT&CK": ["TA0007:T1087"]}
    default_severity = Severity.MEDIUM
    default_description = "A Workspace Admin Changed The Sharing Settings for Primary Calendars\n"
    default_reference = "https://support.google.com/a/answer/60765?hl=en"
    default_runbook = "Restore the calendar sharing setting to the previous value. If unplanned, use indicator search to identify other activity from this administrator.\n"
    summary_attributes = ["actor:email"]
    tests = g_suite_workspace_calendar_external_sharing_setting_tests

    def rule(self, event):
        if not all(
            [
                event.get("name", "") == "CHANGE_CALENDAR_SETTING",
                deep_get(event, "parameters", "SETTING_NAME", default="") == "SHARING_OUTSIDE_DOMAIN",
            ],
        ):
            return False
        return deep_get(event, "parameters", "NEW_VALUE", default="") in [
            "READ_WRITE_ACCESS",
            "READ_ONLY_ACCESS",
            "MANAGE_ACCESS",
        ]

    def title(self, event):
        return f"GSuite workspace setting for default calendar sharing was changed by [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] from [{deep_get(event, 'parameters', 'OLD_VALUE', default='<NO_OLD_SETTING_FOUND>')}] to [{deep_get(event, 'parameters', 'NEW_VALUE', default='<NO_NEW_SETTING_FOUND>')}]"
