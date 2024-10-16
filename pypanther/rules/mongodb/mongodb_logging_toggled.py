from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.mongodb import mongodb_alert_context


@panther_managed
class MongoDBLoggingToggled(Rule):
    default_description = "MongoDB logging toggled"
    display_name = "MongoDB logging toggled"
    default_severity = Severity.LOW
    default_reference = "https://attack.mitre.org/techniques/T1562/008/"
    log_types = [LogType.MONGODB_PROJECT_EVENT]
    id = "MongoDB.Logging.Toggled-prototype"

    def rule(self, event):
        return event.get("eventTypeName", "") == "AUDIT_LOG_CONFIGURATION_UPDATED"

    def title(self, event):
        user = event.get("username", "<USER_NOT_FOUND>")
        return f"MongoDB: [{user}] has changed logging configuration."

    def alert_context(self, event):
        return mongodb_alert_context(event)

    tests = [
        RuleTest(
            name="Random event",
            expected_result=False,
            log={
                "created": "2023-06-07 16:57:55",
                "currentValue": {},
                "eventTypeName": "CAT_JUMPED",
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
            name="Logging toggled",
            expected_result=True,
            log={
                "created": "2023-06-07 16:57:55",
                "currentValue": {},
                "eventTypeName": "AUDIT_LOG_CONFIGURATION_UPDATED",
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
    ]
