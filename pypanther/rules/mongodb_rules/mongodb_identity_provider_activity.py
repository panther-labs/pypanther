from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_mongodb_helpers import mongodb_alert_context

mongo_db_identity_provider_activity_tests: list[RuleTest] = [
    RuleTest(name="Random event", expected_result=False, log={"eventTypeName": "cat_jumped"}),
    RuleTest(
        name="FEDERATION_SETTINGS_CREATED",
        expected_result=True,
        log={"eventTypeName": "FEDERATION_SETTINGS_CREATED"},
    ),
    RuleTest(
        name="IDENTITY_PROVIDER_CREATED",
        expected_result=True,
        log={"eventTypeName": "IDENTITY_PROVIDER_CREATED"},
    ),
]


@panther_managed
class MongoDBIdentityProviderActivity(Rule):
    default_description = "Changes to identity provider settings are privileged activities that should be carefully audited.  Attackers may add or change IDP integrations to gain persistence to environments"
    display_name = "MongoDB Identity Provider Activity"
    default_severity = Severity.MEDIUM
    default_reference = "https://attack.mitre.org/techniques/T1556/007/"
    log_types = [LogType.MONGODB_ORGANIZATION_EVENT]
    id = "MongoDB.Identity.Provider.Activity-prototype"
    tests = mongo_db_identity_provider_activity_tests

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
