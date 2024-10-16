from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snyk import snyk_alert_context


@panther_managed
class SnykProjectSettings(Rule):
    id = "Snyk.Project.Settings-prototype"
    display_name = "Snyk Project Settings"
    log_types = [LogType.SNYK_GROUP_AUDIT, LogType.SNYK_ORG_AUDIT]
    tags = ["Snyk"]
    default_reference = "https://docs.snyk.io/snyk-admin/introduction-to-snyk-projects/view-and-edit-project-settings"
    default_severity = Severity.MEDIUM
    default_description = "Detects when Snyk Project settings are changed\n"
    summary_attributes = ["event"]
    # The bodies of these actions are quite diverse.
    # When projects are added, the logged detail is the sourceOrgId.
    # org.project.stop_monitor is logged for individual files
    #   that are ignored.
    # AND the equivalent for licenses",
    ACTIONS = [
        "org.sast_settings.edit",
        "org.project.attributes.edit",
        "org.project.add",
        "org.project.delete",
        "org.project.fix_pr.manual_open",
        "org.project.ignore.create",
        "org.project.ignore.delete",
        "org.project.ignore.edit",
        "org.project.monitor",
        "org.project.pr_check.edit",
        "org.project.remove",
        "org.project.settings.delete",
        "org.project.settings.edit",
        "org.project.stop_monitor",
        "org.license_rule.create",
        "org.license_rule.delete",
        "org.license_rule.edit",
    ]

    def rule(self, event):
        if event.deep_get("content", "after", "description") == "No new Code Analysis issues found":
            return False
        action = event.get("event", "<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        group_or_org = "<GROUP_OR_ORG>"
        operation = "<NO_OPERATION>"
        action = event.get("event", "<NO_EVENT>")
        if "." in action:
            group_or_org = action.split(".")[0].title()
            operation = ".".join(action.split(".")[1:]).title()
        return f"Snyk: [{group_or_org}] [{operation}] performed by [{event.deep_get('userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        a_c = snyk_alert_context(event)
        # merge event in for the alert_context
        a_c.update(event)
        return a_c

    def dedup(self, event):
        return f"{event.deep_get('userId', default='<NO_USERID>')}{event.deep_get('orgId', default='<NO_ORGID>')}{event.deep_get('groupId', default='<NO_GROUPID>')}{event.deep_get('event', default='<NO_EVENT>')}"

    def severity(self, event):
        action = event.get("event", "<NO_EVENT>")
        if action == "org.project.fix_pr.manual_open":
            return "INFO"
        return "LOW"

    tests = [
        RuleTest(
            name="Snyk Org Project Stop Monitor",
            expected_result=True,
            log={
                "content": {
                    "origin": "github",
                    "target": {"branch": "some-branch", "id": 222222222, "name": "repo-name", "owner": "github-org"},
                    "targetFile": "go.mod",
                    "type": "gomodules",
                },
                "created": "2023-03-30 15:38:18.58",
                "event": "org.project.stop_monitor",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "projectId": "05555555-8555-2333-5aaa-600000000000",
                "userId": "05555555-3333-4ddd-8ccc-75555555555",
            },
        ),
        RuleTest(
            name="Project Ignore Create",
            expected_result=True,
            log={
                "content": {
                    "created": "2023-03-20T12:23:06.356Z",
                    "ignorePath": "*",
                    "ignoredBy": {"id": "05555555-3333-4ddd-8ccc-75555555555"},
                    "issueId": "SNYK-JS-UNDICI-3323845",
                    "reason": "dev dependency",
                    "reasonType": "wont-fix",
                },
                "created": "2023-03-20 12:23:08.363",
                "event": "org.project.ignore.create",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "projectId": "05555555-8555-2333-5aaa-600000000000",
                "userId": "05555555-3333-4ddd-8ccc-75555555555",
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
        RuleTest(
            name="Snyk Org Project Edit",
            expected_result=False,
            log={
                "content": {"snapshotId": "69af7170-87cc-4939-bbaf-1fd99f80cde4"},
                "created": "2024-09-02 23:49:37.552000000",
                "event": "org.project.edit",
                "orgId": "69af7170-87cc-4939-bbaf-1fd99f80cde4",
                "projectId": "69af7170-87cc-4939-bbaf-1fd99f80cde4",
            },
        ),
        RuleTest(
            name="Snyk No New Code Issues Found",
            expected_result=False,
            log={
                "content": {
                    "after": {"description": "No new Code Analysis issues found", "state": "success"},
                    "before": {"state": "processing"},
                    "prCheckPublicId": "69af7170-87cc-4939-bbaf-1fd99f80cde4",
                    "prChecksGroupPublicId": "69af7170-87cc-4939-bbaf-1fd99f80cde4",
                },
                "created": "2024-08-27 14:02:48.823000000",
                "event": "org.project.pr_check.edit",
                "orgId": "69af7170-87cc-4939-bbaf-1fd99f80cde4",
                "projectId": "69af7170-87cc-4939-bbaf-1fd99f80cde4",
            },
        ),
    ]
