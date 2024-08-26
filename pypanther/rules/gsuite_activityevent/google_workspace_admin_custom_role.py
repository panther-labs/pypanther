from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

google_workspace_admin_custom_role_tests: list[RuleTest] = [
    RuleTest(
        name="Delete Role",
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
            "name": "DELETE_ROLE",
            "parameters": {"ROLE_ID": "567890", "ROLE_NAME": "CustomAdminRoleName"},
            "type": "DELEGATED_ADMIN_SETTINGS",
        },
    ),
    RuleTest(
        name="New Custom Role Created",
        expected_result=True,
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
class GoogleWorkspaceAdminCustomRole(Rule):
    default_description = "A Google Workspace administrator created a new custom administrator role."
    display_name = "Google Workspace Admin Custom Role"
    default_runbook = "Please review this activity with the administrator and ensure this behavior was authorized."
    default_reference = "https://support.google.com/a/answer/2406043?hl=en#:~:text=under%20the%20limit.-,Create%20a%20custom%20role,-Before%20you%20begin"
    default_severity = Severity.MEDIUM
    tags = ["admin", "administrator", "google workspace", "role"]
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    id = "Google.Workspace.Admin.Custom.Role-prototype"
    summary_attributes = ["name", "type"]
    tests = google_workspace_admin_custom_role_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        # Create Alert if there is a custom role created under delegated admin settings
        return event.get("type", "") == "DELEGATED_ADMIN_SETTINGS" and event.get("name", "") == "CREATE_ROLE"

    def title(self, event):
        # (Optional) Return a string which will be shown as the alert title.
        # If no 'dedup' function is defined, the return value of this method
        # will act as deduplication string.
        return f"Google Workspace Administrator [{event.get('actor', {}).get('email', 'NO_EMAIL_FOUND')}] created a new admin role [{event.get('parameters', {}).get('ROLE_NAME', 'NO_ROLE_NAME_FOUND')}]."
