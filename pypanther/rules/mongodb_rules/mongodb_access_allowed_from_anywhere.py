from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_mongodb_helpers import mongodb_alert_context
from pypanther.log_types import LogType

mongo_db_access_allowed_from_anywhere_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Allowed access from anywhere",
        ExpectedResult=True,
        Log={
            "created": "2024-04-03 11:13:04.000000000",
            "currentValue": {},
            "eventTypeName": "NETWORK_PERMISSION_ENTRY_ADDED",
            "groupId": "some_group_id",
            "id": "123abc",
            "isGlobalAdmin": False,
            "remoteAddress": "1.2.3.4",
            "userId": "123abc",
            "username": "some_user@company.com",
            "whitelistEntry": "0.0.0.0/0",
        },
    ),
    PantherRuleTest(
        Name="Allowed access from specific ip",
        ExpectedResult=False,
        Log={
            "created": "2024-04-03 11:13:04.000000000",
            "currentValue": {},
            "eventTypeName": "NETWORK_PERMISSION_ENTRY_ADDED",
            "groupId": "some_group_id",
            "id": "123abc",
            "isGlobalAdmin": False,
            "remoteAddress": "1.2.3.4",
            "userId": "123abc",
            "username": "some_user@company.com",
            "whitelistEntry": "1.2.3.4/32",
        },
    ),
]


class MongoDBAccessAllowedFromAnywhere(PantherRule):
    Description = "Atlas only allows client connections to the database deployment from entries in the project's IP access list. This rule detects when 0.0.0.0/0 is added to that list, which allows access from anywhere."
    DisplayName = "MongoDB access allowed from anywhere"
    LogTypes = [LogType.MongoDB_ProjectEvent]
    RuleID = "MongoDB.Access.Allowed.From.Anywhere-prototype"
    Severity = PantherSeverity.High
    Reports = {"MITRE ATT&CK": ["T1021"]}
    Reference = "https://www.mongodb.com/docs/atlas/security/ip-access-list/"
    Runbook = "Check if this activity was legitimate. If not, delete 0.0.0.0/0 from the list of allowed ips."
    Tests = mongo_db_access_allowed_from_anywhere_tests

    def rule(self, event):
        if (
            event.deep_get("eventTypeName", default="") == "NETWORK_PERMISSION_ENTRY_ADDED"
            and event.deep_get("whitelistEntry", default="") == "0.0.0.0/0"
        ):
            return True
        return False

    def title(self, event):
        user = event.deep_get("username", default="<USER_NOT_FOUND>")
        group_id = event.deep_get("groupId", default="<GROUP_NOT_FOUND>")
        return f"MongoDB: [{user}] has allowed access to group [{group_id}] from anywhere"

    def alert_context(self, event):
        context = mongodb_alert_context(event)
        context["groupId"] = event.deep_get("groupId", default="<GROUP_NOT_FOUND>")
        return context
