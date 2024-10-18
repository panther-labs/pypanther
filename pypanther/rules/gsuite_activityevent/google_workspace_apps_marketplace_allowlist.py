from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GoogleWorkspaceAppsMarketplaceAllowlist(Rule):
    default_description = "Google Workspace Marketplace application allowlist settings were modified."
    display_name = "Google Workspace Apps Marketplace Allowlist"
    default_runbook = "Confirm with the acting user that this change was authorized."
    default_reference = "https://support.google.com/a/answer/6089179?hl=en"
    default_severity = Severity.MEDIUM
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    id = "Google.Workspace.Apps.Marketplace.Allowlist-prototype"

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        setting_name = event.deep_get("parameters", "SETTING_NAME", default="<NO_SETTING_NAME>")
        old_val = event.deep_get("parameters", "OLD_VALUE", default="<NO_OLD_VALUE_FOUND>")
        new_val = event.deep_get("parameters", "NEW_VALUE", default="<NO_NEW_VALUE_FOUND>")
        return setting_name == "ENABLE_G_SUITE_MARKETPLACE" and old_val != new_val

    def title(self, event):
        # (Optional) Return a string which will be shown as the alert title.
        # If no 'dedup' function is defined, the return value of this
        # method will act as deduplication string.
        value_dict = {
            "DEFAULT": "DEFAULT",
            "1": "Don't allow users to install and run apps from the Marketplace",
            "2": "Allow users to install and run any app from the Marketplace",
            "3": "Allow users to install and run only selected apps from the Marketplace",
        }
        old_val = event.deep_get("parameters", "OLD_VALUE", default="<NO_OLD_VALUE_FOUND>")
        new_val = event.deep_get("parameters", "NEW_VALUE", default="<NO_NEW_VALUE_FOUND>")
        actor = event.deep_get("actor", "email", default="<NO_EMAIL_FOUND>")
        return f"Google Workspace User [{actor}] made an application allowlist setting change from [{value_dict.get(str(old_val))}] to [{value_dict.get(str(new_val))}]"

    tests = [
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
            name="Change Email Setting",
            expected_result=True,
            log={
                "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
                "id": {
                    "applicationName": "admin",
                    "customerId": "D12345",
                    "time": "2022-12-10 23:38:45.125000000",
                    "uniqueQualifier": "-12345",
                },
                "ipAddress": "12.12.12.12",
                "kind": "admin#reports#activity",
                "name": "CHANGE_EMAIL_SETTING",
                "parameters": {
                    "NEW_VALUE": "3",
                    "OLD_VALUE": "2",
                    "ORG_UNIT_NAME": "EXAMPLE IO",
                    "SETTING_NAME": "ENABLE_G_SUITE_MARKETPLACE",
                },
                "type": "EMAIL_SETTINGS",
            },
        ),
        RuleTest(
            name="Change Email Setting Default",
            expected_result=True,
            log={
                "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
                "id": {
                    "applicationName": "admin",
                    "customerId": "D1234",
                    "time": "2022-12-10 23:33:04.667000000",
                    "uniqueQualifier": "-12345",
                },
                "ipAddress": "12.12.12.12",
                "kind": "admin#reports#activity",
                "name": "CHANGE_EMAIL_SETTING",
                "parameters": {
                    "NEW_VALUE": "1",
                    "OLD_VALUE": "DEFAULT",
                    "ORG_UNIT_NAME": "EXAMPLE IO",
                    "SETTING_NAME": "ENABLE_G_SUITE_MARKETPLACE",
                },
                "type": "EMAIL_SETTINGS",
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
