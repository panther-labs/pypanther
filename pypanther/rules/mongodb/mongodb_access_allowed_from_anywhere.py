from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.mongodb import mongodb_alert_context


@panther_managed
class MongoDBAccessAllowedFromAnywhere(Rule):
    default_description = "Atlas only allows client connections to the database deployment from entries in the project's IP access list. This rule detects when 0.0.0.0/0 is added to that list, which allows access from anywhere."
    display_name = "MongoDB access allowed from anywhere"
    log_types = [LogType.MONGODB_PROJECT_EVENT]
    id = "MongoDB.Access.Allowed.From.Anywhere-prototype"
    default_severity = Severity.HIGH
    tags = ["MongoDB", "Persistence", "Remote Services", "Modify Authentication Process - Conditional Access Policies"]
    reports = {"MITRE ATT&CK": ["TA0003:T1556.009", "TA0008:T1021.007"]}
    default_reference = "https://www.mongodb.com/docs/atlas/security/ip-access-list/"
    default_runbook = "Check if this activity was legitimate. If not, delete 0.0.0.0/0 from the list of allowed ips."

    def rule(self, event):
        if (
            event.get("eventTypeName", "") == "NETWORK_PERMISSION_ENTRY_ADDED"
            and event.get("whitelistEntry", "") == "0.0.0.0/0"
        ):
            return True
        return False

    def title(self, event):
        user = event.get("username", "<USER_NOT_FOUND>")
        group_id = event.get("groupId", "<GROUP_NOT_FOUND>")
        return f"MongoDB: [{user}] has allowed access to group [{group_id}] from anywhere"

    def alert_context(self, event):
        context = mongodb_alert_context(event)
        context["groupId"] = event.get("groupId", "<GROUP_NOT_FOUND>")
        return context

    tests = [
        RuleTest(
            name="Allowed access from anywhere",
            expected_result=True,
            log={
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
        RuleTest(
            name="Allowed access from specific ip",
            expected_result=False,
            log={
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
