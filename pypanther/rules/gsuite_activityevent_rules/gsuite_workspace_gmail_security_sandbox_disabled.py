from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_workspace_gmail_security_sandbox_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Workspace Admin Disables Security Sandbox",
        ExpectedResult=True,
        Log={
            "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-11 03:31:41.212000000",
                "uniqueQualifier": "-12345",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "CHANGE_APPLICATION_SETTING",
            "parameters": {
                "APPLICATION_EDITION": "enterprise",
                "APPLICATION_NAME": "Gmail",
                "NEW_VALUE": "false",
                "ORG_UNIT_NAME": "Example IO",
                "SETTING_NAME": "AttachmentDeepScanningSettingsProto deep_scanning_enabled",
            },
            "type": "APPLICATION_SETTINGS",
        },
    ),
    PantherRuleTest(
        Name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
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
                "NEW_VALUE": "READ_ONLY_ACCESS",
                "OLD_VALUE": "DEFAULT",
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


class GSuiteWorkspaceGmailSecuritySandboxDisabled(PantherRule):
    RuleID = "GSuite.Workspace.GmailSecuritySandboxDisabled-prototype"
    DisplayName = "GSuite Workspace Gmail Security Sandbox Disabled"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1566"]}
    Severity = PantherSeverity.Medium
    Description = "A Workspace Admin Has Disabled The Security Sandbox\n"
    Reference = "https://support.google.com/a/answer/7676854?hl=en#zippy=%2Cfind-security-sandbox-settings%2Cabout-security-sandbox-rules-and-other-scans"
    Runbook = "Gmail's Security Sandbox enables rule based scanning of email content.\nIf this change was not intentional, inspect the other actions taken by this actor.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_workspace_gmail_security_sandbox_disabled_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName", default="").lower() != "admin":
            return False
        if all(
            [
                event.get("name", "") == "CHANGE_APPLICATION_SETTING",
                deep_get(event, "parameters", "APPLICATION_NAME", default="").lower() == "gmail",
                deep_get(event, "parameters", "NEW_VALUE", default="").lower() == "false",
                deep_get(event, "parameters", "SETTING_NAME", default="")
                == "AttachmentDeepScanningSettingsProto deep_scanning_enabled",
            ]
        ):
            return True
        return False

    def title(self, event):
        return f"GSuite Gmail Security Sandbox was disabled for [{deep_get(event, 'parameters', 'ORG_UNIT_NAME', default='<NO_ORG_UNIT_NAME>')}] by [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
