from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

google_workspace_apps_new_mobile_app_installed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Android Calculator",
        ExpectedResult=True,
        Log={
            "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-10 22:55:38.478000000",
                "uniqueQualifier": "12345",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "ADD_MOBILE_APPLICATION_TO_WHITELIST",
            "parameters": {
                "DEVICE_TYPE": "Android",
                "DISTRIBUTION_ENTITY_NAME": "/",
                "DISTRIBUTION_ENTITY_TYPE": "ORG_UNIT",
                "MOBILE_APP_PACKAGE_ID": "com.google.android.calculator",
            },
            "type": "MOBILE_SETTINGS",
        },
    ),
    PantherRuleTest(
        Name="Enable User Enrollement",
        ExpectedResult=False,
        Log={
            "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-11 01:35:29.906000000",
                "uniqueQualifier": "-12345",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "CREATE_APPLICATION_SETTING",
            "parameters": {
                "APPLICATION_EDITION": "standard",
                "APPLICATION_NAME": "Security",
                "NEW_VALUE": "true",
                "ORG_UNIT_NAME": "Example IO",
                "SETTING_NAME": "Advanced Protection Program Settings - Enable user enrollment",
            },
            "type": "APPLICATION_SETTINGS",
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


class GoogleWorkspaceAppsNewMobileAppInstalled(PantherRule):
    Description = "A new mobile application was added to your organization's mobile apps whitelist in Google Workspace Apps."
    DisplayName = "Google Workspace Apps New Mobile App Installed"
    Runbook = "https://admin.google.com/ac/apps/unified"
    Reference = "https://support.google.com/a/answer/6089179?hl=en"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.GSuite_ActivityEvent]
    RuleID = "Google.Workspace.Apps.New.Mobile.App.Installed-prototype"
    Tests = google_workspace_apps_new_mobile_app_installed_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        return event.get("name", "") == "ADD_MOBILE_APPLICATION_TO_WHITELIST"

    def title(self, event):
        # If no 'dedup' function is defined, the return value of
        # this method will act as deduplication string.
        mobile_app_pkg_id = event.get("parameters", {}).get(
            "MOBILE_APP_PACKAGE_ID", "<NO_MOBILE_APP_PACKAGE_ID_FOUND>"
        )
        return f"Google Workspace User [{event.get('actor', {}).get('email', '<NO_EMAIL_FOUND>')}] added application [{mobile_app_pkg_id}] to your org's mobile application allowlist for [{event.get('parameters', {}).get('DEVICE_TYPE', '<NO_DEVICE_TYPE_FOUND>')}]."
