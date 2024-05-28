from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_mongodb_helpers import mongodb_alert_context
from pypanther.log_types import LogType

mongo_db_alerting_disabled_or_deleted_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Alert added",
        ExpectedResult=False,
        Log={
            "alertConfigId": "alert_id",
            "created": "2024-04-01 11:57:54.000000000",
            "currentValue": {},
            "eventTypeName": "ALERT_CONFIG_ADDED_AUDIT",
            "id": "alert_id",
            "isGlobalAdmin": False,
            "links": [],
            "orgId": "some_org_id",
            "remoteAddress": "1.2.3.4",
            "userId": "user_id",
            "username": "some_user@company.com",
        },
    ),
    PantherRuleTest(
        Name="Alert deleted",
        ExpectedResult=True,
        Log={
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


class MongoDBAlertingDisabledOrDeleted(PantherRule):
    Description = "MongoDB provides security alerting policies for notifying admins when certain conditions are met. This rule detects when these policies are disabled or deleted."
    DisplayName = "MongoDB security alerts disabled or deleted"
    LogTypes = [LogType.MongoDB_OrganizationEvent]
    RuleID = "MongoDB.Alerting.Disabled.Or.Deleted-prototype"
    Severity = PantherSeverity.High
    Reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}
    Reference = "https://www.mongodb.com/docs/atlas/configure-alerts/"
    Runbook = "Re-enable security alerts"
    Tests = mongo_db_alerting_disabled_or_deleted_tests

    def rule(self, event):
        return event.deep_get("eventTypeName", default="") in [
            "ALERT_CONFIG_DISABLED_AUDIT",
            "ALERT_CONFIG_DELETED_AUDIT",
        ]

    def title(self, event):
        user = event.deep_get("username", default="<USER_NOT_FOUND>")
        alert_id = event.deep_get("alertConfigId", default="<ALERT_NOT_FOUND>")
        return f"MongoDB: [{user}] has disabled or deleted security alert [{alert_id}]"

    def alert_context(self, event):
        context = mongodb_alert_context(event)
        context["alertConfigId"] = event.deep_get("alertConfigId", default="<ALERT_NOT_FOUND>")
        return context
