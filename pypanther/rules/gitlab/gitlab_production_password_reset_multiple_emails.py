from panther_core.immutable import ImmutableList

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.base import deep_get


@panther_managed
class GitLabProductionPasswordResetMultipleEmails(Rule):
    id = "GitLab.Production.Password.Reset.Multiple.Emails-prototype"
    display_name = "CVE-2023-7028 - GitLab Production Password Reset Multiple Emails"
    log_types = [LogType.GITLAB_PRODUCTION]
    tags = ["GitLab", "CVE-2023-7028", "No Pack"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195", "TA0001:T1190", "TA0003:T1098"]}
    default_severity = Severity.HIGH
    default_description = "Attackers are exploiting a Critical (CVSS 10.0) GitLab vulnerability in which user account password reset emails could be delivered to an unverified email address."
    default_reference = "https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released/"

    def rule(self, event):
        path = event.get("path", "")
        if path != "/users/password":
            return False
        params = event.get("params", [])
        for param in params:
            if param.get("key") == "user":
                email = deep_get(param, "value", "email", default=[])
                if isinstance(email, ImmutableList) and len(email) > 1:
                    return True
        return False

    def title(self, event):
        emails = event.deep_get("detail", "target_details", default="")
        return f"Someone tried to reset your password with multiple emails :{emails}"

    tests = [
        RuleTest(
            name="not a password reset",
            expected_result=False,
            log={
                "params": [
                    {"key": "authenticity_token", "value": "[FILTERED]"},
                    {"key": "user", "value": {"email": ["peter@example.com", "bob@example.com"]}},
                ],
                "path": "/cats",
            },
        ),
        RuleTest(
            name="one email",
            expected_result=False,
            log={
                "params": [
                    {"key": "authenticity_token", "value": "[FILTERED]"},
                    {"key": "user", "value": {"email": ["bob@example.com"]}},
                ],
                "path": "/users/password",
            },
        ),
        RuleTest(
            name="multiple emails",
            expected_result=True,
            log={
                "params": [
                    {"key": "authenticity_token", "value": "[FILTERED]"},
                    {"key": "user", "value": {"email": ["peter@example.com", "bob@example.com"]}},
                ],
                "path": "/users/password",
            },
        ),
    ]
