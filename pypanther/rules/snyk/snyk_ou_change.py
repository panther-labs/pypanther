from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snyk import snyk_alert_context


@panther_managed
class SnykOUChange(Rule):
    id = "Snyk.OU.Change-prototype"
    display_name = "Snyk Org or Group Settings Change"
    log_types = [LogType.SNYK_GROUP_AUDIT, LogType.SNYK_ORG_AUDIT]
    tags = ["Snyk"]
    default_severity = Severity.HIGH
    default_description = "Detects when Snyk Group or Organization Settings are changed.\n"
    default_runbook = "These actions in the Snyk Audit logs indicate that a Organization or Group setting has changed, including Group and Org creation/deletion. Deletion events are marked with HIGH severity Creation events are marked with INFO severity Edit events are marked with MEDIUM Severity\n"
    default_reference = "https://docs.snyk.io/snyk-admin/introduction-to-snyk-administration"
    summary_attributes = ["event"]
    ACTIONS = [
        "group.create",
        "group.delete",
        "group.edit",
        "group.feature_flags.edit",
        "group.org.add",
        "group.org.remove",
        "group.settings.edit",
        "group.settings.feature_flag.edit",
        "org.create",
        "org.delete",
        "org.edit",
        "org.settings.feature_flag.edit",
    ]

    def rule(self, event):
        action = event.get("event", "<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        group_or_org = "<GROUP_OR_ORG>"
        action = event.get("event", "<NO_EVENT>")
        if "." in action:
            group_or_org = action.split(".")[0].title()
        return f"Snyk: [{group_or_org}] Organizational Unit settings have been modified via [{action}] performed by [{event.deep_get('userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        return snyk_alert_context(event)

    def dedup(self, event):
        return f"{event.deep_get('userId', default='<NO_USERID>')}{event.deep_get('orgId', default='<NO_ORGID>')}{event.deep_get('groupId', default='<NO_GROUPID>')}{event.deep_get('event', default='<NO_EVENT>')}"

    def severity(self, event):
        action = event.get("event", "<NO_EVENT>")
        if action.endswith((".remove", ".delete")):
            return "HIGH"
        if action.endswith(".edit"):
            return "MEDIUM"
        return "INFO"

    tests = [
        RuleTest(
            name="Snyk Org Deletion ( HIGH )",
            expected_result=True,
            log={
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "event": "org.delete",
                "content": {"orgName": "expendable-org"},
                "created": "2023-04-09T23:32:14.649Z",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk Group Org Remove ( HIGH )",
            expected_result=True,
            log={
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "event": "group.org.remove",
                "content": {"orgName": "expendable-org"},
                "created": "2023-04-09T23:32:14.649Z",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk Group Edit ( MEDIUM )",
            expected_result=True,
            log={
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "event": "group.edit",
                "content": {"updatedValues": {"projectTestFrequencySetting": "daily"}},
                "created": "2023-04-11T23:22:57.667Z",
            },
        ),
        RuleTest(
            name="Snyk Org Create ( INFO )",
            expected_result=True,
            log={
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "event": "org.create",
                "content": {"newOrgPublicId": "21111111-a222-4eee-8ddd-a99999999999"},
                "created": "2023-04-11T23:12:33.206Z",
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
            },
        ),
        RuleTest(
            name="Snyk Group SSO Membership sync",
            expected_result=False,
            log={
                "content": {},
                "created": "2023-03-15 13:13:13.133",
                "event": "group.sso.membership.sync",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
            },
        ),
    ]
