from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class CarbonBlackAuditAPIKeyCreatedRetrieved(Rule):
    id = "CarbonBlack.Audit.API.Key.Created.Retrieved-prototype"
    log_types = [LogType.CARBON_BLACK_AUDIT]
    default_description = "Detects when a user creates a new API key or retrieves an existing key."
    display_name = "Carbon Black API Key Created or Retrieved"
    default_severity = Severity.MEDIUM
    tags = ["Persistence", "Create Account"]
    reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    default_reference = "https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-F3816FB5-969F-4113-80FC-03981C65F969.html"
    PATTERNS = (" retrieved secret for API ID ", "Added API ID ", "Regenerated API key for API ID ", "Updated API ID ")

    def rule(self, event):
        desc = event.get("description", "")
        return any(pattern in desc for pattern in self.PATTERNS)

    def title(self, event):
        user = event.get("loginName", "<NO_USERNAME_FOUND>")
        ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
        desc = event.get("description", "<NO_DESCRIPTION_FOUND>")
        return f"{user} [{ip_addr}] {desc}"

    tests = [
        RuleTest(
            name="API Key Retrieved",
            expected_result=True,
            log={
                "clientIp": "12.34.56.78",
                "description": "User bob.ross@acme.com retrieved secret for API ID JFDNIPS464 in org 12345",
                "eventId": "66443924833011eeac3cb393f3d07f9f",
                "eventTime": "2023-11-14 20:57:19.186000000",
                "flagged": False,
                "loginName": "bob.ross@acme.com",
                "orgName": "acme.com",
                "verbose": False,
            },
        ),
        RuleTest(
            name="Admin granted",
            expected_result=True,
            log={
                "clientIp": "12.34.56.78",
                "description": "Added API ID JFDNIPS464 with name evil-key in org 12345",
                "eventId": "66443924833011eeac3cb393f3d07f9f",
                "eventTime": "2023-11-14 20:57:19.186000000",
                "flagged": False,
                "loginName": "bob.ross@acme.com",
                "orgName": "acme.com",
                "verbose": False,
            },
        ),
        RuleTest(
            name="Other role granted",
            expected_result=False,
            log={
                "clientIp": "12.34.56.78",
                "description": "Created grant: psc:cnn:A1234567:BC1234567890 with role Read Only",
                "eventId": "66443924833011eeac3cb393f3d07f9f",
                "eventTime": "2023-11-14 20:57:19.186000000",
                "flagged": False,
                "loginName": "bob.ross@acme.com",
                "orgName": "acme.com",
                "requestUrl": "/access/v2/orgs/A1234567/grants",
                "verbose": False,
            },
        ),
    ]
