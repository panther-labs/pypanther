from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_workspace_data_export_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Workspace Admin Data Export Created",
        ExpectedResult=True,
        Log={
            "actor": {
                "callerType": "USER",
                "email": "admin@example.io",
                "profileId": "11011111111111111111111",
            },
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-10 22:21:40.079000000",
                "uniqueQualifier": "-2833899999999999999",
            },
            "kind": "admin#reports#activity",
            "name": "CUSTOMER_TAKEOUT_CREATED",
            "parameters": {"OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID": "00mmmmmmmmmmmmm"},
            "type": "CUSTOMER_TAKEOUT",
        },
    ),
    PantherRuleTest(
        Name="Workspace Admin Data Export Succeeded",
        ExpectedResult=True,
        Log={
            "actor": {
                "callerType": "USER",
                "email": "admin@example.io",
                "profileId": "11011111111111111111111",
            },
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-12 22:21:40.106000000",
                "uniqueQualifier": "3005999999999999999",
            },
            "kind": "admin#reports#activity",
            "name": "CUSTOMER_TAKEOUT_SUCCEEDED",
            "parameters": {"OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID": "00mmmmmmmmmmmmm"},
            "type": "CUSTOMER_TAKEOUT",
        },
    ),
    PantherRuleTest(
        Name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
        ExpectedResult=False,
        Log={
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
    PantherRuleTest(
        Name="ListObject Type",
        ExpectedResult=False,
        Log={
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


class GSuiteWorkspaceDataExportCreated(PantherRule):
    RuleID = "GSuite.Workspace.DataExportCreated-prototype"
    DisplayName = "GSuite Workspace Data Export Has Been Created"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Severity = PantherSeverity.Medium
    Description = "A Workspace Admin Has Created a Data Export\n"
    Reference = "https://support.google.com/a/answer/100458?hl=en&sjid=864417124752637253-EU"
    Runbook = "Verify the intent of this Data Export. If intent cannot be verified, then a search on the actor's other activities is advised.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_workspace_data_export_created_tests

    def rule(self, event):
        return event.get("name", "").startswith("CUSTOMER_TAKEOUT_")

    def title(self, event):
        return f"GSuite Workspace Data Export [{event.get('name', '<NO_EVENT_NAME>')}] performed by [{deep_get(event, 'actor', 'email', default='<NO_ACTOR_FOUND>')}]"
