from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_mongodb_helpers import mongodb_alert_context
from pypanther.log_types import LogType

mongo_db_logging_toggled_tests: List[PantherRuleTest] = [
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
        Name="Logging toggled",
        ExpectedResult=True,
        Log={
            "created": "2023-06-07 16:57:55",
            "currentValue": {},
            "eventTypeName": "AUDIT_LOG_CONFIGURATION_UPDATED",
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
]


class MongoDBLoggingToggled(PantherRule):
    Description = "MongoDB logging toggled"
    DisplayName = "MongoDB logging toggled"
    Severity = PantherSeverity.Low
    Reference = "https://attack.mitre.org/techniques/T1562/008/"
    LogTypes = [LogType.MongoDB_ProjectEvent]
    RuleID = "MongoDB.Logging.Toggled-prototype"
    Tests = mongo_db_logging_toggled_tests

    def rule(self, event):
        return event.deep_get("eventTypeName", default="") == "AUDIT_LOG_CONFIGURATION_UPDATED"

    def title(self, event):
        user = event.deep_get("username", default="<USER_NOT_FOUND>")
        return f"MongoDB: [{user}] has changed logging configuration."

    def alert_context(self, event):
        return mongodb_alert_context(event)
