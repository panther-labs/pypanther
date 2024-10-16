from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.snyk import snyk_alert_context


@panther_managed
class SnykSystemSSO(Rule):
    id = "Snyk.System.SSO-prototype"
    display_name = "Snyk System SSO Settings Changed"
    log_types = [LogType.SNYK_GROUP_AUDIT]
    tags = ["Snyk"]
    default_severity = Severity.HIGH
    default_description = "Detects Snyk SSO Settings have been changed. The reference URL from Snyk indicates that these events are likely to originate exclusively from Snyk Support.\n"
    default_reference = "https://docs.snyk.io/user-and-group-management/setting-up-sso-for-authentication/set-up-snyk-single-sign-on-sso"
    summary_attributes = ["event", "p_any_ip_addresses", "p_any_emails"]
    ACTIONS = [
        "group.sso.auth0_connection.create",
        "group.sso.auth0_connection.edit",
        "group.sso.create",
        "group.sso.edit",
    ]

    def rule(self, event):
        action = event.get("event", "<NO_EVENT>")
        return action in self.ACTIONS

    def title(self, event):
        return f"Snyk: System SSO Setting event [{event.deep_get('event', default='<NO_EVENT>')}] performed by [{event.deep_get('userId', default='<NO_USERID>')}]"

    def alert_context(self, event):
        return snyk_alert_context(event)

    tests = [
        RuleTest(
            name="Snyk System SSO Setting event happened",
            expected_result=True,
            log={
                "userId": "05555555-3333-4ddd-8ccc-755555555555",
                "event": "group.sso.edit",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "content": {"unknown": "contents"},
            },
        ),
        RuleTest(
            name="Snyk Group SSO Membership sync",
            expected_result=False,
            log={
                "content": {
                    "addAsOrgAdmin": [],
                    "addAsOrgCollaborator": ["group.name"],
                    "addAsOrgCustomRole": [],
                    "addAsOrgRestrictedCollaborator": [],
                    "removedOrgMemberships": [],
                    "userPublicId": "05555555-3333-4ddd-8ccc-755555555555",
                },
                "created": "2023-03-15 13:13:13.133",
                "event": "group.sso.membership.sync",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
            },
        ),
    ]
