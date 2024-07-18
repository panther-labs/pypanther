import json

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import m365_alert_context

microsoft365_mfa_disabled_tests: list[RuleTest] = [
    RuleTest(
        name="MFA Add Event",
        expected_result=False,
        log={
            "Actor": [
                {"ID": "Azure MFA StrongAuthenticationService", "Type": 1},
                {"ID": "ABC-123", "Type": 2},
                {"ID": "ServicePrincipal_123-abc", "Type": 2},
                {"ID": "321-cba", "Type": 2},
                {"ID": "ServicePrincipal", "Type": 2},
            ],
            "ActorContextId": "123-abc-456",
            "AzureActiveDirectoryEventType": 1,
            "CreationTime": "2022-12-12 17:28:35",
            "ExtendedProperties": [
                {"Name": "additionalDetails", "Value": '{"UserType":"Member"}'},
                {"Name": "extendedAuditEventCategory", "Value": "User"},
            ],
            "Id": "123-abc-123",
            "InterSystemsId": "abc-123-321",
            "IntraSystemId": "aa-bbb-333",
            "ModifiedProperties": [
                {
                    "Name": "StrongAuthenticationMethod",
                    "NewValue": '[{"Default": true,"MethodType": 7}]',
                    "OldValue": "[]",
                },
                {"Name": "Included Updated Properties", "NewValue": "StrongAuthenticationMethod", "OldValue": ""},
                {"Name": "TargetId.UserType", "NewValue": "Member", "OldValue": ""},
            ],
            "ObjectId": "sample.user@yourorg.onmicrosoft.com",
            "Operation": "Update user.",
            "OrganizationId": "111-222-333",
            "RecordType": 8,
            "ResultStatus": "Success",
            "SupportTicketId": "",
            "Target": [
                {"ID": "User_111-222-bbb", "Type": 2},
                {"ID": "111-aa-bbb-321", "Type": 2},
                {"ID": "User", "Type": 2},
                {"ID": "sample.user@yourorg.onmicrosoft.com", "Type": 5},
                {"ID": "123abcdef", "Type": 3},
            ],
            "TargetContextId": "aaa-bb-222",
            "UserId": "ServicePrincipal_aa-bb-ccc",
            "UserKey": "Not Available",
            "UserType": 4,
            "Workload": "AzureActiveDirectory",
        },
    ),
    RuleTest(
        name="MFA Remove event",
        expected_result=True,
        log={
            "Actor": [
                {"ID": "Azure MFA StrongAuthenticationService", "Type": 1},
                {"ID": "ABC-123", "Type": 2},
                {"ID": "ServicePrincipal_123-abc", "Type": 2},
                {"ID": "321-cba", "Type": 2},
                {"ID": "ServicePrincipal", "Type": 2},
            ],
            "ActorContextId": "123-abc-456",
            "AzureActiveDirectoryEventType": 1,
            "CreationTime": "2022-12-12 17:28:35",
            "ExtendedProperties": [
                {"Name": "additionalDetails", "Value": '{"UserType":"Member"}'},
                {"Name": "extendedAuditEventCategory", "Value": "User"},
            ],
            "Id": "123-abc-123",
            "InterSystemsId": "abc-123-321",
            "IntraSystemId": "aa-bbb-333",
            "ModifiedProperties": [
                {
                    "Name": "StrongAuthenticationMethod",
                    "NewValue": "[]",
                    "OldValue": '[{"Default": true,"MethodType": 7}]',
                },
                {"Name": "Included Updated Properties", "NewValue": "StrongAuthenticationMethod", "OldValue": ""},
                {"Name": "TargetId.UserType", "NewValue": "Member", "OldValue": ""},
            ],
            "ObjectId": "sample.user@yourorg.onmicrosoft.com",
            "Operation": "Update user.",
            "OrganizationId": "111-222-333",
            "RecordType": 8,
            "ResultStatus": "Success",
            "SupportTicketId": "",
            "Target": [
                {"ID": "User_111-222-bbb", "Type": 2},
                {"ID": "111-aa-bbb-321", "Type": 2},
                {"ID": "User", "Type": 2},
                {"ID": "sample.user@yourorg.onmicrosoft.com", "Type": 5},
                {"ID": "123abcdef", "Type": 3},
            ],
            "TargetContextId": "aaa-bb-222",
            "UserId": "ServicePrincipal_aa-bb-ccc",
            "UserKey": "Not Available",
            "UserType": 4,
            "Workload": "AzureActiveDirectory",
        },
    ),
]


@panther_managed
class Microsoft365MFADisabled(Rule):
    default_description = "A user's MFA has been removed"
    display_name = "Microsoft365 MFA Disabled"
    reports = {"MITRE ATT&CK": ["TA003:T1556", "TA005:T1556", "TA006:T1556"]}
    default_runbook = "Depending on company policy, either suggest or require the user re-enable two step verification."
    default_reference = "https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/set-up-multi-factor-authentication?view=o365-worldwide"
    default_severity = Severity.LOW
    log_types = [LogType.MICROSOFT365_AUDIT_AZURE_ACTIVE_DIRECTORY]
    id = "Microsoft365.MFA.Disabled-prototype"
    tests = microsoft365_mfa_disabled_tests

    def rule(self, event):
        if event.get("Operation", "") == "Update user.":
            modified_properties = event.get("ModifiedProperties", [])
            for prop in modified_properties:
                if prop.get("Name", "") == "StrongAuthenticationMethod":
                    new_value = prop.get("NewValue")
                    old_value = prop.get("OldValue")
                    if isinstance(new_value, str):
                        new_value = json.loads(new_value)
                    if isinstance(old_value, str):
                        old_value = json.loads(old_value)
                    if old_value and (not new_value):
                        return True
                    break
        return False

    def title(self, event):
        return f"Microsoft365: MFA Removed on [{event.get('ObjectId', '')}]"

    def alert_context(self, event):
        return m365_alert_context(event)
