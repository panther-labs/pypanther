from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_mongodb_helpers import mongodb_alert_context
from pypanther.log_types import LogType

mongo_db_user_created_or_deleted_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Random event",
        ExpectedResult=False,
        Log={
            "created": "2023-06-07 16:57:55",
            "currentValue": {},
            "eventTypeName": "CAT_JUMPED",
            "id": "6480b7139bd8a012345ABCDE",
            "isGlobalAdmin": False,
            "links": [
                {
                    "href": "https://cloud.mongodb.com/api/atlas/v1.0/orgs/12345xyzlmnce4f17d6e8e130/events/6480b7139bd8a012345ABCDE",
                    "rel": "self",
                }
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
    PantherRuleTest(
        Name="User joined Org",
        ExpectedResult=True,
        Log={
            "created": "2023-06-07 16:57:55",
            "currentValue": {},
            "eventTypeName": "JOINED_ORG",
            "id": "6480b7139bd8a012345ABCDE",
            "isGlobalAdmin": False,
            "links": [
                {
                    "href": "https://cloud.mongodb.com/api/atlas/v1.0/orgs/12345xyzlmnce4f17d6e8e130/events/6480b7139bd8a012345ABCDE",
                    "rel": "self",
                }
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
    PantherRuleTest(
        Name="User removed from Org",
        ExpectedResult=True,
        Log={
            "created": "2023-06-07 16:57:55",
            "currentValue": {},
            "eventTypeName": "REMOVED_FROM_ORG",
            "id": "6480b7139bd8a012345ABCDE",
            "isGlobalAdmin": False,
            "links": [
                {
                    "href": "https://cloud.mongodb.com/api/atlas/v1.0/orgs/12345xyzlmnce4f17d6e8e130/events/6480b7139bd8a012345ABCDE",
                    "rel": "self",
                }
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


class MongoDBUserCreatedOrDeleted(PantherRule):
    Description = "User was created or deleted."
    DisplayName = "MongoDB user was created or deleted"
    Severity = PantherSeverity.Medium
    Reference = "https://www.mongodb.com/docs/v4.2/tutorial/create-users/"
    LogTypes = [LogType.MongoDB_OrganizationEvent]
    RuleID = "MongoDB.User.Created.Or.Deleted-prototype"
    Tests = mongo_db_user_created_or_deleted_tests

    def rule(self, event):
        return event.deep_get("eventTypeName", default="") in ("JOINED_ORG", "REMOVED_FROM_ORG")

    def title(self, event):
        event_name = event.get("eventTypeName")
        target_username = event.get("targetUsername", "<USER_NOT_FOUND>")
        org_id = event.get("orgId", "<ORG_NOT_FOUND>")
        action = "has joined org" if event_name == "JOINED_ORG" else "was removed from org"
        return f"MongoDB Atlas: [{target_username}] {action} [{org_id}]"

    def alert_context(self, event):
        return mongodb_alert_context(event)
