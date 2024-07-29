from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

google_workspace_advanced_protection_program_tests: list[RuleTest] = [
    RuleTest(
        name="parameters json key set to null value",
        expected_result=False,
        log={
            "actor": {"callerType": "USER", "email": "user@example.io", "profileId": "111111111111111111111"},
            "id": {
                "applicationName": "user_accounts",
                "customerId": "C00000000",
                "time": "2022-12-29 22:42:44.467000000",
                "uniqueQualifier": "517500000000000000",
            },
            "parameters": None,
            "ipAddress": "2600:2600:2600:2600:2600:2600:2600:2600",
            "kind": "admin#reports#activity",
            "name": "recovery_email_edit",
            "type": "recovery_info_change",
        },
    ),
    RuleTest(
        name="Allow Security Codes",
        expected_result=True,
        log={
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
                "NEW_VALUE": "ALLOWED_WITH_REMOTE_ACCESS",
                "ORG_UNIT_NAME": "Example IO",
                "SETTING_NAME": "Advanced Protection Program Settings - Allow security codes",
            },
            "type": "APPLICATION_SETTINGS",
        },
    ),
    RuleTest(
        name="Enable User Enrollment",
        expected_result=True,
        log={
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
    RuleTest(
        name="New Custom Role Created",
        expected_result=False,
        log={
            "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "123456"},
            "id": {
                "applicationName": "admin",
                "customerId": "D12345",
                "time": "2022-12-11 02:57:48.693000000",
                "uniqueQualifier": "-12456",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "CREATE_ROLE",
            "parameters": {"ROLE_ID": "567890", "ROLE_NAME": "CustomAdminRoleName"},
            "type": "DELEGATED_ADMIN_SETTINGS",
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
class GoogleWorkspaceAdvancedProtectionProgram(Rule):
    default_description = "Your organization's Google Workspace Advanced Protection Program settings were modified."
    display_name = "Google Workspace Advanced Protection Program"
    default_runbook = "Confirm the changes made were authorized for your organization."
    default_reference = "https://support.google.com/a/answer/9378686?hl=en"
    default_severity = Severity.MEDIUM
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    id = "Google.Workspace.Advanced.Protection.Program-prototype"
    tests = google_workspace_advanced_protection_program_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        setting_name = deep_get(event, "parameters", "SETTING_NAME", default="NO_SETTING_NAME").split("-")[0].strip()
        setting_alert_flag = "Advanced Protection Program Settings"
        return event.get("name") == "CREATE_APPLICATION_SETTING" and setting_name == setting_alert_flag

    def title(self, event):
        # If no 'dedup' function is defined, the return value of this
        # method will act as deduplication string.
        setting = event.deep_get("parameters", "SETTING_NAME", default="NO_SETTING_NAME")
        setting_name = setting.split("-")[-1].strip()
        return f"Google Workspace Advanced Protection Program settings have been updated to [{setting_name}] by Google Workspace User [{event.deep_get('actor', 'email', default='<NO_EMAIL_FOUND>')}]."
