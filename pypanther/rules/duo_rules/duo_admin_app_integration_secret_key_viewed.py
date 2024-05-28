from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

duo_admin_app_integration_secret_key_viewed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Generic Skey View",
        ExpectedResult=True,
        Log={
            "action": "integration_skey_view",
            "isotimestamp": "2022-12-14 20:09:57",
            "object": "Example Integration Name",
            "timestamp": "2022-12-14 20:09:57",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        Name="Duo app install ",
        ExpectedResult=False,
        Log={
            "action": "application_install",
            "isotimestamp": "2022-12-14 20:09:57",
            "object": "Example Integration Name",
            "timestamp": "2022-12-14 20:09:57",
            "username": "Homer Simpson",
        },
    ),
]


class DuoAdminAppIntegrationSecretKeyViewed(PantherRule):
    Description = "An administrator viewed a Secret Key for an Application Integration"
    DisplayName = "Duo Admin App Integration Secret Key Viewed"
    Reference = "https://duo.com/docs/adminapi"
    Runbook = "The security of your Duo application is tied to the security of your secret key (skey). Secure it as you would any sensitive credential. Don't share it with unauthorized individuals or email it to anyone under any circumstances!"
    Severity = PantherSeverity.Medium
    LogTypes = [LogType.Duo_Administrator]
    RuleID = "Duo.Admin.App.Integration.Secret.Key.Viewed-prototype"
    Tests = duo_admin_app_integration_secret_key_viewed_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        return event.get("action", "") == "integration_skey_view"

    def title(self, event):
        # If no 'dedup' function is defined, the return value of
        # this method will act as deduplication string.
        return f"'Duo: [{event.get('username', '<NO_USER_FOUND>')}] viewed the Secret Key for Application [{event.get('object', '<NO_OBJECT_FOUND>')}]"
