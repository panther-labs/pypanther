import json
from unittest.mock import MagicMock

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.mongodb import mongodb_alert_context


@panther_managed
class MongoDBExternalUserInvited(Rule):
    default_description = "An external user has been invited to a MongoDB org. "
    display_name = "MongoDB External User Invited"
    default_severity = Severity.MEDIUM
    default_reference = "https://www.mongodb.com/docs/v4.2/tutorial/create-users/"
    tags = ["Configuration Required"]
    log_types = [LogType.MONGODB_ORGANIZATION_EVENT]
    id = "MongoDB.External.UserInvited-prototype"
    # Set domains allowed to join the organization ie. company.com
    ALLOWED_DOMAINS = []

    def rule(self, event):
        if isinstance(self.ALLOWED_DOMAINS, MagicMock):
            self.ALLOWED_DOMAINS = json.loads(self.ALLOWED_DOMAINS())  # pylint: disable=not-callable
        if event.get("eventTypeName", "") == "INVITED_TO_ORG":
            target_user = event.get("targetUsername", "")
            target_domain = target_user.split("@")[-1]
            return target_domain not in self.ALLOWED_DOMAINS
        return False

    def title(self, event):
        actor = event.get("username", "<USER_NOT_FOUND>")
        target = event.get("targetUsername", "<USER_NOT_FOUND>")
        org_id = event.get("orgId", "<ORG_NOT_FOUND>")
        return f"MongoDB Atlas: [{actor}] invited external user [{target}] to the org [{org_id}]"

    def alert_context(self, event):
        return mongodb_alert_context(event)

    tests = [
        RuleTest(
            name="Internal Invite",
            expected_result=False,
            mocks=[RuleMock(object_name="ALLOWED_DOMAINS", return_value='[\n  "company.com"\n]')],
            log={
                "created": "2023-06-07 16:57:55",
                "currentValue": {},
                "eventTypeName": "INVITED_TO_ORG",
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
            name="External User Invite",
            expected_result=True,
            mocks=[RuleMock(object_name="ALLOWED_DOMAINS", return_value='[\n  "company.com"\n]')],
            log={
                "created": "2023-06-07 16:57:55",
                "currentValue": {},
                "eventTypeName": "INVITED_TO_ORG",
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
