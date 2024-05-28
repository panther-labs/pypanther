from typing import List

from panther_core.immutable import ImmutableList

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

git_lab_production_password_reset_multiple_emails_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="not a password reset",
        ExpectedResult=False,
        Log={
            "params": [
                {"key": "authenticity_token", "value": "[FILTERED]"},
                {"key": "user", "value": {"email": ["peter@example.com", "bob@example.com"]}},
            ],
            "path": "/cats",
        },
    ),
    PantherRuleTest(
        Name="one email",
        ExpectedResult=False,
        Log={
            "params": [
                {"key": "authenticity_token", "value": "[FILTERED]"},
                {"key": "user", "value": {"email": ["bob@example.com"]}},
            ],
            "path": "/users/password",
        },
    ),
    PantherRuleTest(
        Name="multiple emails",
        ExpectedResult=True,
        Log={
            "params": [
                {"key": "authenticity_token", "value": "[FILTERED]"},
                {"key": "user", "value": {"email": ["peter@example.com", "bob@example.com"]}},
            ],
            "path": "/users/password",
        },
    ),
]


class GitLabProductionPasswordResetMultipleEmails(PantherRule):
    RuleID = "GitLab.Production.Password.Reset.Multiple.Emails-prototype"
    DisplayName = "CVE-2023-7028 - GitLab Production Password Reset Multiple Emails"
    LogTypes = [LogType.GitLab_Production]
    Tags = ["GitLab", "CVE-2023-7028"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1195", "TA0001:T1190", "TA0003:T1098"]}
    Severity = PantherSeverity.High
    Description = "Attackers are exploiting a Critical (CVSS 10.0) GitLab vulnerability in which user account password reset emails could be delivered to an unverified email address."
    Reference = "https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released/"
    Tests = git_lab_production_password_reset_multiple_emails_tests

    def rule(self, event):
        path = event.get("path", default="")
        if path != "/users/password":
            return False
        params = event.get("params", default=[])
        for param in params:
            if param.get("key") == "user":
                email = deep_get(param, "value", "email", default=[])
                if isinstance(email, ImmutableList) and len(email) > 1:
                    return True
        return False

    def title(self, event):
        emails = event.deep_get("detail", "target_details", default="")
        return f"Someone tried to reset your password with multiple emails :{emails}"
