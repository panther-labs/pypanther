from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.msft import m365_alert_context


@panther_managed
class Microsoft365BruteForceLoginbyUser(Rule):
    default_description = "A Microsoft365 user was denied login access several times"
    display_name = "Microsoft365 Brute Force Login by User"
    reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    default_runbook = "Analyze the IP they came from and actions taken before/after."
    default_reference = "https://learn.microsoft.com/en-us/microsoft-365/troubleshoot/authentication/access-denied-when-connect-to-office-365"
    default_severity = Severity.MEDIUM
    log_types = [LogType.MICROSOFT365_AUDIT_AZURE_ACTIVE_DIRECTORY]
    id = "Microsoft365.Brute.Force.Login.by.User-prototype"
    threshold = 10

    def rule(self, event):
        return event.get("Operation", "") == "UserLoginFailed"

    def title(self, event):
        return f"Microsoft365: [{event.get('UserId', '<user-not-found>')}] may be undergoing a Brute Force Attack."

    def alert_context(self, event):
        return m365_alert_context(event)

    tests = [
        RuleTest(
            name="Failed Login event",
            expected_result=True,
            log={
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
        RuleTest(
            name="Login Event",
            expected_result=False,
            log={
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
