import json
from typing import List
from unittest.mock import MagicMock

from pypanther.base import PantherRule, PantherRuleMock, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_mongodb_helpers import mongodb_alert_context
from pypanther.log_types import LogType

mongo_db_external_user_invited_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Internal Invite",
        ExpectedResult=False,
        Mocks=[PantherRuleMock(ObjectName="ALLOWED_DOMAINS", ReturnValue='[\n  "company.com"\n]')],
        Log={
            "created": "2023-06-07 16:57:55",
            "currentValue": {},
            "eventTypeName": "INVITED_TO_ORG",
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
        Name="External User Invite",
        ExpectedResult=True,
        Mocks=[PantherRuleMock(ObjectName="ALLOWED_DOMAINS", ReturnValue='[\n  "company.com"\n]')],
        Log={
            "created": "2023-06-07 16:57:55",
            "currentValue": {},
            "eventTypeName": "INVITED_TO_ORG",
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


class MongoDBExternalUserInvited(PantherRule):
    Description = "An external user has been invited to a MongoDB org. "
    DisplayName = "MongoDB External User Invited"
    Severity = PantherSeverity.Medium
    Reference = "https://www.mongodb.com/docs/v4.2/tutorial/create-users/"
    Tags = ["Configuration Required"]
    LogTypes = [LogType.MongoDB_OrganizationEvent]
    RuleID = "MongoDB.External.UserInvited-prototype"
    Tests = mongo_db_external_user_invited_tests
    # Set domains allowed to join the organization ie. company.com
    ALLOWED_DOMAINS = []

    def rule(self, event):
        if isinstance(self.ALLOWED_DOMAINS, MagicMock):
            self.ALLOWED_DOMAINS = json.loads(
                self.ALLOWED_DOMAINS()
            )  # pylint: disable=not-callable
        if deep_get(event, "eventTypeName", default="") == "INVITED_TO_ORG":
            target_user = deep_get(event, "targetUsername", default="")
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
