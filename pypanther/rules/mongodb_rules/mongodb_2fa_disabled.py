from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_mongodb_helpers import mongodb_alert_context

mongo_db2_fa_disabled_tests: list[RuleTest] = [
    RuleTest(
        name="2FA ebabled",
        expected_result=False,
        log={
            "created": "2023-06-07 16:57:55",
            "currentValue": {},
            "eventTypeName": "ORG_TWO_FACTOR_AUTH_REQUIRED",
            "id": "6480b7139bd8a012345ABCDE",
            "isGlobalAdmin": False,
            "links": [
                {
                    "href": "https://cloud.mongodb.com/api/atlas/v1.0/orgs/12345xyzlmnce4f17d6e8e130/events/6480b7139bd8a012345ABCDE",
                    "rel": "self",
                },
            ],
            "orgId": "12345xyzlmnce4f17d6e8e130",
            "p_event_time": "2023-06-07 16:57:55",
            "p_log_type": "MongoDB.OrganizationEvent",
            "p_parse_time": "2023-06-07 17:04:42.59",
            "p_row_id": "ea276b16216684d9e198c0d0188a3d",
            "p_schema_version": 0,
            "p_source_id": "7c3cb124-9c30-492c-99e6-46518c232d73",
            "p_source_label": "MongoDB",
            "remoteAddress": "1.2.3.4",
            "targetUsername": "insider@company.com",
            "userId": "647f654f93bebc69123abc1",
            "username": "user@company.com",
        },
    ),
    RuleTest(
        name="2FA disabled",
        expected_result=True,
        log={
            "created": "2023-06-07 16:57:55",
            "currentValue": {},
            "eventTypeName": "ORG_TWO_FACTOR_AUTH_OPTIONAL",
            "id": "6480b7139bd8a012345ABCDE",
            "isGlobalAdmin": False,
            "links": [
                {
                    "href": "https://cloud.mongodb.com/api/atlas/v1.0/orgs/12345xyzlmnce4f17d6e8e130/events/6480b7139bd8a012345ABCDE",
                    "rel": "self",
                },
            ],
            "orgId": "12345xyzlmnce4f17d6e8e130",
            "p_event_time": "2023-06-07 16:57:55",
            "p_log_type": "MongoDB.OrganizationEvent",
            "p_parse_time": "2023-06-07 17:04:42.59",
            "p_row_id": "ea276b16216684d9e198c0d0188a3d",
            "p_schema_version": 0,
            "p_source_id": "7c3cb124-9c30-492c-99e6-46518c232d73",
            "p_source_label": "MongoDB",
            "remoteAddress": "1.2.3.4",
            "targetUsername": "outsider@other.com",
            "userId": "647f654f93bebc69123abc1",
            "username": "user@company.com",
        },
    ),
]


@panther_managed
class MongoDB2FADisabled(Rule):
    default_description = "2FA was disabled."
    display_name = "MongoDB 2FA Disabled"
    default_severity = Severity.MEDIUM
    default_reference = "https://www.mongodb.com/docs/atlas/security-multi-factor-authentication/"
    log_types = [LogType.MONGODB_ORGANIZATION_EVENT]
    id = "MongoDB.2FA.Disabled-prototype"
    tests = mongo_db2_fa_disabled_tests

    def rule(self, event):
        return event.deep_get("eventTypeName", default="") == "ORG_TWO_FACTOR_AUTH_OPTIONAL"

    def title(self, event):
        user = event.deep_get("username", default="<USER_NOT_FOUND>")
        return f"MongoDB Atlas: [{user}] has disabled 2FA"

    def alert_context(self, event):
        return mongodb_alert_context(event)
