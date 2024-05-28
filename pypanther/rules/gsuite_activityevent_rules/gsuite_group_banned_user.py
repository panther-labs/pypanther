from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

g_suite_group_banned_user_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User Added",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "groups_enterprise"},
            "actor": {"email": "homer.simpson@example.com"},
            "type": "moderator_action",
            "name": "add_member",
        },
    ),
    PantherRuleTest(
        Name="User Banned from Group",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "groups_enterprise"},
            "actor": {"email": "homer.simpson@example.com"},
            "type": "moderator_action",
            "name": "ban_user_with_moderation",
        },
    ),
]


class GSuiteGroupBannedUser(PantherRule):
    RuleID = "GSuite.GroupBannedUser-prototype"
    DisplayName = "GSuite User Banned from Group"
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite"]
    Severity = PantherSeverity.Low
    Description = "A GSuite user was banned from an enterprise group by moderator action.\n"
    Reference = "https://support.google.com/a/users/answer/9303224?hl=en&sjid=864417124752637253-EU"
    Runbook = (
        "Investigate the banned user to see if further disciplinary action needs to be taken.\n"
    )
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_group_banned_user_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "groups_enterprise":
            return False
        if event.get("type") == "moderator_action":
            return bool(event.get("name") == "ban_user_with_moderation")
        return False

    def title(self, event):
        return f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] banned another user from a group."
