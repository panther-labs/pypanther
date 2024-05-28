from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import m365_alert_context
from pypanther.log_types import LogType

microsoft365_brute_force_loginby_user_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Failed Login event",
        ExpectedResult=True,
        Log={
            "Actor": [
                {"ID": "012345-abcde-543-xyz", "Type": 0},
                {"ID": "sample.user@yourorg.onmicrosoft.com", "Type": 5},
            ],
            "ActorContextId": "123-abc-xyz-567",
            "ActorIpAddress": "1.2.3.4",
            "ApplicationId": "123-abc-sfa-321",
            "AzureActiveDirectoryEventType": 1,
            "ClientIP": "1.2.3.4",
            "CreationTime": "2022-12-12 15:57:57",
            "ExtendedProperties": [
                {"Name": "ResultStatusDetail", "Value": "Success"},
                {
                    "Name": "UserAgent",
                    "Value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                },
                {"Name": "UserAuthenticationMethod", "Value": "1"},
                {"Name": "RequestType", "Value": "Login:login"},
            ],
            "Id": "abc-def-123",
            "InterSystemsId": "987-432-123",
            "IntraSystemId": "aaa-bbb-ccc",
            "LogonError": "InvalidUserNameOrPassword",
            "ObjectId": "aa-11-22-bb",
            "Operation": "UserLoginFailed",
            "OrganizationId": "11-aa-22-bb",
            "RecordType": 15,
            "ResultStatus": "Success",
            "SupportTicketId": "",
            "Target": [{"ID": "11-22-33", "Type": 0}],
            "TargetContextId": "11-22-33-44",
            "UserId": "sample.user@yourorg.onmicrosoft.com",
            "UserKey": "012345-abcde-543-xyz",
            "UserType": 0,
            "Workload": "AzureActiveDirectory",
        },
    ),
    PantherRuleTest(
        Name="Login Event",
        ExpectedResult=False,
        Log={
            "Actor": [
                {"ID": "012345-abcde-543-xyz", "Type": 0},
                {"ID": "sample.user@yourorg.onmicrosoft.com", "Type": 5},
            ],
            "ActorContextId": "123-abc-xyz-567",
            "ActorIpAddress": "1.2.3.4",
            "ApplicationId": "123-abc-sfa-321",
            "AzureActiveDirectoryEventType": 1,
            "ClientIP": "1.2.3.4",
            "CreationTime": "2022-12-12 15:57:57",
            "ExtendedProperties": [
                {"Name": "ResultStatusDetail", "Value": "Success"},
                {
                    "Name": "UserAgent",
                    "Value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                },
                {"Name": "RequestType", "Value": "Login:reprocess"},
            ],
            "Id": "abc-def-123",
            "InterSystemsId": "987-432-123",
            "IntraSystemId": "aaa-bbb-ccc",
            "ObjectId": "aa-11-22-bb",
            "Operation": "UserLoggedIn",
            "OrganizationId": "11-aa-22-bb",
            "RecordType": 15,
            "ResultStatus": "Success",
            "SupportTicketId": "",
            "Target": [{"ID": "11-22-33", "Type": 0}],
            "TargetContextId": "11-22-33-44",
            "UserId": "sample.user@yourorg.onmicrosoft.com",
            "UserKey": "012345-abcde-543-xyz",
            "UserType": 0,
        },
    ),
]


class Microsoft365BruteForceLoginbyUser(PantherRule):
    Description = "A Microsoft365 user was denied login access several times"
    DisplayName = "Microsoft365 Brute Force Login by User"
    Reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    Runbook = "Analyze the IP they came from and actions taken before/after."
    Reference = "https://learn.microsoft.com/en-us/microsoft-365/troubleshoot/authentication/access-denied-when-connect-to-office-365"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Microsoft365_Audit_AzureActiveDirectory]
    RuleID = "Microsoft365.Brute.Force.Login.by.User-prototype"
    Threshold = 10
    Tests = microsoft365_brute_force_loginby_user_tests

    def rule(self, event):
        return event.get("Operation", "") == "UserLoginFailed"

    def title(self, event):
        return f"Microsoft365: [{event.get('UserId', '<user-not-found>')}] may be undergoing a Brute Force Attack."

    def alert_context(self, event):
        return m365_alert_context(event)
