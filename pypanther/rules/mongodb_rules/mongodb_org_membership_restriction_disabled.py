from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_mongodb_helpers import mongodb_alert_context

mongo_d_borg_membership_restriction_disabled_tests: list[RuleTest] = [
    RuleTest(
        name="Restriction disabled",
        expected_result=True,
        log={
            "created": "2024-04-03 15:03:51.000000000",
            "currentValue": {},
            "eventTypeName": "ORG_PUBLIC_API_ACCESS_LIST_NOT_REQUIRED",
            "id": "alert_id",
            "isGlobalAdmin": False,
            "orgId": "some_org_id",
            "remoteAddress": "1.2.3.4",
            "userId": "user_id",
            "username": "some_user@company.com",
        },
    ),
    RuleTest(
        name="Restriction enabled",
        expected_result=False,
        log={
            "created": "2024-04-03 15:03:51.000000000",
            "currentValue": {},
            "eventTypeName": "ORG_PUBLIC_API_ACCESS_LIST_REQUIRED",
            "id": "alert_id",
            "isGlobalAdmin": False,
            "orgId": "some_org_id",
            "remoteAddress": "1.2.3.4",
            "userId": "user_id",
            "username": "some_user@company.com",
        },
    ),
    RuleTest(
        name="Other activity",
        expected_result=False,
        log={
            "alertConfigId": "alert_id",
            "created": "2024-04-01 11:58:52.000000000",
            "currentValue": {},
            "eventTypeName": "ALERT_CONFIG_DELETED_AUDIT",
            "id": "alert_id",
            "isGlobalAdmin": False,
            "links": [],
            "orgId": "some_org_id",
            "remoteAddress": "1.2.3.4",
            "userId": "user_id",
            "username": "some_user@company.com",
        },
    ),
]


@panther_managed
class MongoDBorgMembershipRestrictionDisabled(Rule):
    default_description = "You can configure Atlas to require API access lists at the organization level. When you enable IP access list for the Atlas Administration API, all API calls in that organization must originate from a valid entry in the associated Atlas Administration API key access list. This rule detects when IP access list is disabled"
    display_name = "MongoDB org membership restriction disabled"
    log_types = [LogType.MONGODB_ORGANIZATION_EVENT]
    id = "MongoDB.org.Membership.Restriction.Disabled-prototype"
    default_severity = Severity.HIGH
    reports = {"MITRE ATT&CK": ["T1556"]}
    default_reference = "https://www.mongodb.com/docs/atlas/tutorial/manage-organizations/"
    default_runbook = (
        "Check if this activity is legitimate. If not, re-enable IP access list for the Atlas Administration API"
    )
    tests = mongo_d_borg_membership_restriction_disabled_tests

    def rule(self, event):
        return event.deep_get("eventTypeName", default="") == "ORG_PUBLIC_API_ACCESS_LIST_NOT_REQUIRED"

    def title(self, event):
        user = event.deep_get("username", default="<USER_NOT_FOUND>")
        return f"MongoDB: [{user}] has disabled IP access list for the Atlas Administration API"

    def alert_context(self, event):
        return mongodb_alert_context(event)
