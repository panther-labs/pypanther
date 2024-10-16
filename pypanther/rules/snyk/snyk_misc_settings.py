from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snyk import snyk_alert_context


@panther_managed
class SnykMiscSettings(Rule):
    id = "Snyk.Misc.Settings-prototype"
    display_name = "Snyk Miscellaneous Settings"
    log_types = [LogType.SNYK_GROUP_AUDIT, LogType.SNYK_ORG_AUDIT]
    tags = ["Snyk"]
    default_reference = "https://docs.snyk.io/snyk-admin/manage-settings"
    default_severity = Severity.LOW
    default_description = "Detects when Snyk settings that lack a clear security impact are changed\n"
    summary_attributes = ["event"]
    ACTIONS = ["group.cloud_config.settings.edit", "group.feature_flags.edit"]

    def rule(self, event):
        action = event.get("event", "<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        group_or_org = "<GROUP_OR_ORG>"
        operation = "<NO_OPERATION>"
        action = event.get("event", "<NO_EVENT>")
        if "." in action:
            group_or_org = action.split(".")[0].title()
            operation = ".".join(action.split(".")[1:]).title()
        return f"Snyk: [{group_or_org}] Setting [{operation}] performed by [{event.deep_get('userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        return snyk_alert_context(event)

    def dedup(self, event):
        return f"{event.deep_get('userId', default='<NO_USERID>')}{event.deep_get('orgId', default='<NO_ORGID>')}{event.deep_get('groupId', default='<NO_GROUPID>')}{event.deep_get('event', default='<NO_EVENT>')}"

    tests = [
        RuleTest(
            name="Snyk Feature Flags changed",
            expected_result=True,
            log={
                "created": "2023-04-11 23:32:14.173",
                "event": "group.feature_flags.edit",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk User Invite Revoke",
            expected_result=False,
            log={
                "content": {},
                "created": "2023-04-11 23:32:13.248",
                "event": "org.user.invite.revoke",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
    ]
