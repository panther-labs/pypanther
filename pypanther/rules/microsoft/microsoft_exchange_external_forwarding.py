from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.config import config


@panther_managed
class Microsoft365ExchangeExternalForwarding(Rule):
    default_description = "Detects creation of forwarding rule to external domains"
    display_name = "Microsoft Exchange External Forwarding"
    reports = {"MITRE ATT&CK": ["TA0009:T1114"]}
    default_reference = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding?view=o365-worldwide"
    default_severity = Severity.HIGH
    log_types = [LogType.MICROSOFT365_AUDIT_EXCHANGE]
    id = "Microsoft365.Exchange.External.Forwarding-prototype"

    def rule(self, event):
        if event.get("operation", "") in ("Set-Mailbox", "New-InboxRule"):
            for param in event.get("parameters", []):
                if param.get("Name", "") in ("ForwardingSmtpAddress", "ForwardTo", "ForwardingAddress"):
                    to_email = param.get("Value", "")
                    if (
                        to_email.lower().replace("smtp:", "")
                        in config.MS_EXCHANGE_ALLOWED_FORWARDING_DESTINATION_EMAILS
                    ):
                        return False
                    for domain in config.MS_EXCHANGE_ALLOWED_FORWARDING_DESTINATION_DOMAINS:
                        if to_email.lower().replace("smtp:", "").endswith(domain):
                            return False
                    return True
        return False

    def title(self, event):
        to_email = "<no-recipient-found>"
        for param in event.get("parameters", []):
            if param.get("Name", "") in ("ForwardingSmtpAddress", "ForwardTo"):
                to_email = param.get("Value", "")
                break
        return f"Microsoft365: External Forwarding Created From [{event.get('userid', '')}] to [{to_email}]"

    tests = [
        RuleTest(
            name="Forwarding Enabled",
            expected_result=True,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {
                        "Name": "Identity",
                        "Value": "ABC1.prod.outlook.com/Microsoft Exchange Hosted Organizations/simpsons.onmicrosoft.com/homer.simpson",
                    },
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:hello@familyguy.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "False"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Forwarding Rule",
            expected_result=True,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "New-InboxRule",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "AlwaysDeleteOutlookRulesBlob", "Value": "False"},
                    {"Name": "Force", "Value": "False"},
                    {"Name": "ForwardTo", "Value": "hello@familyguy.com"},
                    {"Name": "Name", "Value": "test forwarding"},
                    {"Name": "StopProcessingRules", "Value": "True"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Forwarding Rule to Allowed Domain",
            expected_result=False,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "New-InboxRule",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "AlwaysDeleteOutlookRulesBlob", "Value": "False"},
                    {"Name": "Force", "Value": "False"},
                    {"Name": "ForwardTo", "Value": "hello@example.com"},
                    {"Name": "Name", "Value": "test forwarding"},
                    {"Name": "StopProcessingRules", "Value": "True"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Forwarding Rule to Exception",
            expected_result=False,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "New-InboxRule",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {"Name": "AlwaysDeleteOutlookRulesBlob", "Value": "False"},
                    {"Name": "Force", "Value": "False"},
                    {"Name": "ForwardTo", "Value": "postmaster@example.com"},
                    {"Name": "Name", "Value": "test forwarding"},
                    {"Name": "StopProcessingRules", "Value": "True"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Forwarding To Allowed Domain",
            expected_result=False,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {
                        "Name": "Identity",
                        "Value": "ABC1.prod.outlook.com/Microsoft Exchange Hosted Organizations/simpsons.onmicrosoft.com/homer.simpson",
                    },
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:hello@example.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "False"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Forwarding to Exception",
            expected_result=False,
            log={
                "clientip": "1.2.3.4",
                "creationtime": "2022-12-12 22:19:00",
                "externalaccess": False,
                "id": "111-22-33",
                "objectid": "homer.simpson",
                "operation": "Set-Mailbox",
                "organizationid": "11-aa-bb",
                "organizationname": "simpsons.onmicrosoft.com",
                "originatingserver": "QWERTY (1.2.3.4)",
                "parameters": [
                    {
                        "Name": "Identity",
                        "Value": "ABC1.prod.outlook.com/Microsoft Exchange Hosted Organizations/simpsons.onmicrosoft.com/homer.simpson",
                    },
                    {"Name": "ForwardingSmtpAddress", "Value": "smtp:postmaster@example.com"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "False"},
                ],
                "recordtype": 1,
                "resultstatus": "True",
                "userid": "homer.simpson@simpsons.onmicrosoft.com",
                "userkey": "12345",
                "usertype": 2,
                "workload": "Exchange",
            },
        ),
        RuleTest(
            name="Log with ForwardingAddress",
            expected_result=True,
            log={
                "AppAccessContext": {},
                "ClientIP": "20.185.225.251:6688",
                "CreationTime": "2023-10-24 13:06:33.000000000",
                "ExternalAccess": False,
                "Id": "78ab3f60-bd49-42e5-e69d-08dbd4920c3d",
                "ObjectId": "28eb696a-03f7-47bd-a07a-b09d5f6e592e",
                "Operation": "Set-Mailbox",
                "OrganizationId": "18360841-3f87-44a6-8c9a-3ffc680611a0",
                "OrganizationName": "fellowship.lotr.com",
                "OriginatingServer": "AM6PR0402MB3448 (15.20.6933.008)",
                "Parameters": [
                    {"Name": "Identity", "Value": "28eb696a-03f7-47bd-a07a-b09d5f6e592e"},
                    {"Name": "ForwardingAddress", "Value": "sauron@mordor.dev"},
                    {"Name": "ForwardingSmtpAddress", "Value": ""},
                    {"Name": "DeliverToMailboxAndForward", "Value": "False"},
                ],
                "RecordType": 1,
                "ResultStatus": "True",
                "UserId": "saurman@lotr.com",
                "UserKey": "10032002CD6B7EFD",
                "UserType": 2,
                "Workload": "Exchange",
            },
        ),
    ]
