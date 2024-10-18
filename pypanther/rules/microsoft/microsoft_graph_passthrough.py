from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.msft import msft_graph_alert_context


@panther_managed
class MicrosoftGraphPassthrough(Rule):
    default_description = "The Microsoft Graph security API federates queries to all onboarded security providers, including Azure AD Identity Protection, Microsoft 365, Microsoft Defender (Cloud, Endpoint, Identity) and Microsoft Sentinel"
    default_reference = "https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview"
    display_name = "Microsoft Graph Passthrough"
    default_severity = Severity.MEDIUM
    log_types = [LogType.MICROSOFT_GRAPH_SECURITY_ALERT]
    id = "Microsoft.Graph.Passthrough-prototype"

    def rule(self, event):
        return event.get("status") == "newAlert" and event.get("severity", "").lower() != "informational"

    def title(self, event):
        return f"Microsoft Graph Alert ({event.get('title')})"

    def dedup(self, event):
        return event.get("id")

    def severity(self, event):
        if event.get("severity", "").lower() == "informational":
            return "INFO"
        return event.get("severity")

    def alert_context(self, event):
        return msft_graph_alert_context(event)

    tests = [
        RuleTest(
            name="Anonymous Login Event",
            expected_result=True,
            log={
                "azuretenantid": "12345-abcde-a1b2k3",
                "category": "AnonymousLogin",
                "createddatetime": "2022-08-04 14:31:48.438",
                "description": "Sign-in from an anonymous IP address (e.g. Tor browser, anonymizer VPNs)",
                "eventdatetime": "2022-08-04 14:31:48.438",
                "id": "abcd12345efghijk6789",
                "lastmodifieddatetime": "2022-08-04 14:34:56.229",
                "severity": "medium",
                "status": "newAlert",
                "title": "Anonymous IP address",
                "userstates": [
                    {
                        "aadUserId": "011d5ede-0faa-4946-a25e-b2cd0c47a52c",
                        "accountName": "homer.simpson",
                        "domainName": "corporation.onmicrosoft.com",
                        "emailRole": "unknown",
                        "logonDateTime": "2022-08-04 14:31:48.438699700",
                        "logonIp": "185.220.103.6",
                        "logonLocation": "Brooklyn, New York, US",
                        "userPrincipalName": "homer.simpson@corporation.onmicrosoft.com",
                    },
                ],
                "vendorinformation": {"provider": "IPC", "vendor": "Microsoft"},
            },
        ),
        RuleTest(
            name="Password Spray Event",
            expected_result=True,
            log={
                "azuretenantid": "abcdef-123456-ghijklmn",
                "category": "PasswordSpray",
                "createddatetime": "2022-08-17 09:28:04.767",
                "description": "Password spray attack detected",
                "eventdatetime": "2022-08-16 14:22:00.698",
                "id": "abcdefg-123456-hijklmno",
                "lastmodifieddatetime": "2022-08-17 14:30:21.979",
                "severity": "high",
                "status": "newAlert",
                "title": "Password Spray",
                "userstates": [
                    {
                        "aadUserId": "abcdefg-123456-lmnop",
                        "accountName": "homer.simpson",
                        "domainName": "corporation.onmicrosoft.com",
                        "emailRole": "unknown",
                        "logonDateTime": "2022-08-16 14:22:00.698619500",
                        "logonIp": "109.70.100.21",
                        "logonLocation": "San Francisco, CA",
                        "userPrincipalName": "homer.simpson@corporation.onmicrosoft.com",
                    },
                ],
                "vendorinformation": {"provider": "IPC", "vendor": "Microsoft"},
            },
        ),
        RuleTest(
            name="Resolved Event",
            expected_result=False,
            log={
                "azuretenantid": "abcdefg-12345",
                "category": "AnonymousLogin",
                "createddatetime": "2022-09-12 19:54:13.725",
                "description": "Sign-in from an anonymous IP address (e.g. Tor browser, anonymizer VPNs)",
                "eventdatetime": "2022-09-12 19:54:13.725",
                "id": "abcdefg12345hijklmnop",
                "lastmodifieddatetime": "2022-09-12 19:56:57.833",
                "severity": "high",
                "status": "resolved",
                "title": "Anonymous IP address",
                "userstates": [
                    {
                        "aadUserId": "abcdefg1234",
                        "accountName": "homer.simpson",
                        "domainName": "corporation.onmicrosoft.com",
                        "emailRole": "unknown",
                        "logonDateTime": "2022-09-12 19:54:13.725589800",
                        "logonIp": "109.70.100.35",
                        "logonLocation": "San Francisco, CA",
                        "userPrincipalName": "homer.simpson@corporation.onmicrosoft.com",
                    },
                ],
                "vendorinformation": {"provider": "IPC", "vendor": "Microsoft"},
            },
        ),
    ]
