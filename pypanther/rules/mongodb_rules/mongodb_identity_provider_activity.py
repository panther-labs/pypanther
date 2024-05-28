from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_mongodb_helpers import mongodb_alert_context
from pypanther.log_types import LogType

mongo_db_identity_provider_activity_tests: List[PantherRuleTest] = [
    PantherRuleTest(Name="Random event", ExpectedResult=False, Log={"eventTypeName": "cat_jumped"}),
    PantherRuleTest(
        Name="FEDERATION_SETTINGS_CREATED",
        ExpectedResult=True,
        Log={"eventTypeName": "FEDERATION_SETTINGS_CREATED"},
    ),
    PantherRuleTest(
        Name="IDENTITY_PROVIDER_CREATED",
        ExpectedResult=True,
        Log={"eventTypeName": "IDENTITY_PROVIDER_CREATED"},
    ),
]


class MongoDBIdentityProviderActivity(PantherRule):
    Description = "Changes to identity provider settings are privileged activities that should be carefully audited.  Attackers may add or change IDP integrations to gain persistence to environments"
    DisplayName = "MongoDB Identity Provider Activity"
    Severity = PantherSeverity.Medium
    Reference = "https://attack.mitre.org/techniques/T1556/007/"
    LogTypes = [LogType.MongoDB_OrganizationEvent]
    RuleID = "MongoDB.Identity.Provider.Activity-prototype"
    Tests = mongo_db_identity_provider_activity_tests

    def rule(self, event):
        important_event_types = {
            "FEDERATION_SETTINGS_CREATED",
            "FEDERATION_SETTINGS_DELETED",
            "FEDERATION_SETTINGS_UPDATED",
            "IDENTITY_PROVIDER_CREATED",
            "IDENTITY_PROVIDER_UPDATED",
            "IDENTITY_PROVIDER_DELETED",
            "IDENTITY_PROVIDER_ACTIVATED",
            "IDENTITY_PROVIDER_DEACTIVATED",
            "IDENTITY_PROVIDER_JWKS_REVOKED",
            "OIDC_IDENTITY_PROVIDER_UPDATED",
            "OIDC_IDENTITY_PROVIDER_ENABLED",
            "OIDC_IDENTITY_PROVIDER_DISABLED",
        }
        return event.deep_get("eventTypeName") in important_event_types

    def title(self, event):
        target_username = event.get("targetUsername", "<USER_NOT_FOUND>")
        org_id = event.get("orgId", "<ORG_NOT_FOUND>")
        return f"MongoDB Atlas: User [{target_username}] roles changed in org [{org_id}]"

    def alert_context(self, event):
        return mongodb_alert_context(event)
