from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

g_suite_group_banned_user_tests: list[RuleTest] = [
    RuleTest(
        name="User Added",
        expected_result=False,
        log={
            "id": {"applicationName": "groups_enterprise"},
            "actor": {"email": "homer.simpson@example.com"},
            "type": "moderator_action",
            "name": "add_member",
        },
    ),
    RuleTest(
        name="User Banned from Group",
        expected_result=True,
        log={
            "id": {"applicationName": "groups_enterprise"},
            "actor": {"email": "homer.simpson@example.com"},
            "type": "moderator_action",
            "name": "ban_user_with_moderation",
        },
    ),
]


@panther_managed
class GSuiteGroupBannedUser(Rule):
    id = "GSuite.GroupBannedUser-prototype"
    display_name = "GSuite User Banned from Group"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    default_severity = Severity.LOW
    default_description = "A GSuite user was banned from an enterprise group by moderator action.\n"
    default_reference = "https://support.google.com/a/users/answer/9303224?hl=en&sjid=864417124752637253-EU"
    default_runbook = "Investigate the banned user to see if further disciplinary action needs to be taken.\n"
    summary_attributes = ["actor:email"]
    tests = g_suite_group_banned_user_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "groups_enterprise":
            return False
        if event.get("type") == "moderator_action":
            return bool(event.get("name") == "ban_user_with_moderation")
        return False

    def title(self, event):
        return (
            f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] banned another user from a group."
        )
