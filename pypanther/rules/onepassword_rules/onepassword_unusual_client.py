from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

one_password_unusual_client_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="1Password - Expected Client",
        ExpectedResult=False,
        Log={
            "uuid": "1234",
            "session_uuid": "12345",
            "timestamp": "2021-12-15 18:02:23",
            "category": "success",
            "type": "credentials_ok",
            "country": "US",
            "target_user": {
                "email": "homer@springfield.gov",
                "name": "Homer Simpson",
                "uuid": "1234",
            },
            "client": {
                "app_name": "1Password for Mac",
                "app_version": "70902005",
                "ip_address": "1.1.1.1",
                "os_name": "MacOSX",
                "os_version": "11.6.1",
                "platform_name": "US - C02FR0H8MD6P",
                "platform_version": "MacBookPro16,1",
            },
            "p_log_type": "OnePassword.SignInAttempt",
        },
    ),
    PantherRuleTest(
        Name="1Password - Bad Client",
        ExpectedResult=True,
        Log={
            "uuid": "1234",
            "session_uuid": "12345",
            "timestamp": "2021-12-15 18:02:23",
            "category": "success",
            "type": "credentials_ok",
            "country": "US",
            "target_user": {
                "email": "homer@springfield.gov",
                "name": "Homer Simpson",
                "uuid": "1234",
            },
            "client": {
                "app_name": "Bartco 1Password Manager",
                "app_version": "70902005",
                "ip_address": "1.1.1.1",
                "os_name": "MacOSX",
                "os_version": "11.6.1",
                "platform_name": "US - C02FR0H8MD6P",
                "platform_version": "MacBookPro16,1",
            },
            "p_log_type": "OnePassword.SignInAttempt",
        },
    ),
]


class OnePasswordUnusualClient(PantherRule):
    RuleID = "OnePassword.Unusual.Client-prototype"
    DedupPeriodMinutes = 120
    DisplayName = "Unusual 1Password Client Detected"
    LogTypes = [LogType.OnePassword_SignInAttempt]
    Severity = PantherSeverity.Medium
    Description = (
        "Detects when unusual or undesirable 1Password clients access your 1Password account"
    )
    Reference = "https://support.1password.com/category/accounts/"
    Tags = ["1Password", "Credential Access:Credentials from Password Stores"]
    Reports = {"MITRE ATT&CK": ["TA0006:T1555"]}
    SummaryAttributes = ["p_any_ip_addresses", "p_any_emails"]
    Tests = one_password_unusual_client_tests
    "\nThis rule detects unusual or unauthorized clients connecting to your 1Password account.\nIn order to get a baseline of what clients are being used in your environment run the following\nquery in Data Explorer:\n\nselect distinct client:app_name from panther_logs.public.onepassword_signinattempt\n\nThe client_allowlist variable is a collection of standard 1Password clients.\nIf this differs from your orginization's needs this rule can be edited to suit your environment\n"

    def rule(self, event):  # Used for automated account provisioning
        client_allowlist = [
            "1Password CLI",
            "1Password for Web",
            "1Password for Mac",
            "1Password SCIM Bridge",
            "1Password for Windows",
            "1Password for iOS",
            "1Password Browser Extension",
            "1Password for Android",
        ]
        return deep_get(event, "client", "app_name") not in client_allowlist

    def title(self, event):
        return f"Unusual 1Password client - {deep_get(event, 'client', 'app_name')} detected"

    def alert_context(self, event):
        context = {}
        context["user"] = deep_get(event, "target_user", "name", default="UNKNOWN_USER")
        context["user_email"] = event.udm("actor_user")
        context["ip_address"] = event.udm("source_ip")
        context["client"] = deep_get(event, "client", "app_name", default="UNKNOWN_CLIENT")
        context["OS"] = deep_get(event, "client", "os_name", default="UNKNOWN_OS")
        context["login_result"] = event.get("category")
        context["time_seen"] = event.get("timestamp")
        return context
