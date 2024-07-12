from typing import List

from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity

duo_admin_app_integration_secret_key_viewed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        name="Generic Skey View",
        expected_result=True,
        log={
            "action": "integration_skey_view",
            "isotimestamp": "2022-12-14 20:09:57",
            "object": "Example Integration Name",
            "timestamp": "2022-12-14 20:09:57",
            "username": "Homer Simpson",
        },
    ),
    PantherRuleTest(
        name="Duo app install ",
        expected_result=False,
        log={
            "action": "application_install",
            "isotimestamp": "2022-12-14 20:09:57",
            "object": "Example Integration Name",
            "timestamp": "2022-12-14 20:09:57",
            "username": "Homer Simpson",
        },
    ),
]


class DuoAdminAppIntegrationSecretKeyViewed(PantherRule):
    default_description = "An administrator viewed a Secret Key for an Application Integration"
    display_name = "Duo Admin App Integration Secret Key Viewed"
    default_reference = "https://duo.com/docs/adminapi"
    default_runbook = "The security of your Duo application is tied to the security of your secret key (skey). Secure it as you would any sensitive credential. Don't share it with unauthorized individuals or email it to anyone under any circumstances!"
    default_severity = PantherSeverity.medium
    log_types = [PantherLogType.Duo_Administrator]
    id_ = "Duo.Admin.App.Integration.Secret.Key.Viewed-prototype"
    tests = duo_admin_app_integration_secret_key_viewed_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        return event.get("action", "") == "integration_skey_view"

    def title(self, event):
        # If no 'dedup' function is defined, the return value of
        # this method will act as deduplication string.
        return f"'Duo: [{event.get('username', '<NO_USER_FOUND>')}] viewed the Secret Key for Application [{event.get('object', '<NO_OBJECT_FOUND>')}]"
