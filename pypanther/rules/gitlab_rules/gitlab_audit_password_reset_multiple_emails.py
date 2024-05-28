import json
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_lab_audit_password_reset_multiple_emails_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="not a password reset",
        ExpectedResult=False,
        Log={"detail": {"custom_message": "hello world"}},
    ),
    PantherRuleTest(
        Name="one email",
        ExpectedResult=False,
        Log={
            "detail": {
                "custom_message": "Ask for password reset",
                "target_details": "example@test.com",
            }
        },
    ),
    PantherRuleTest(
        Name="multiple emails",
        ExpectedResult=True,
        Log={
            "detail": {
                "custom_message": "Ask for password reset",
                "target_details": '["example@test.com", "example2@test.com"]',
            }
        },
    ),
]


class GitLabAuditPasswordResetMultipleEmails(PantherRule):
    RuleID = "GitLab.Audit.Password.Reset.Multiple.Emails-prototype"
    DisplayName = "CVE-2023-7028 - GitLab Audit Password Reset Multiple Emails"
    LogTypes = [LogType.GitLab_Audit]
    Tags = ["GitLab", "CVE-2023-7028"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1195", "TA0001:T1190", "TA0003:T1098"]}
    Severity = PantherSeverity.High
    Description = "Attackers are exploiting a Critical (CVSS 10.0) GitLab vulnerability in which user account password reset emails could be delivered to an unverified email address."
    Reference = "https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released/"
    Tests = git_lab_audit_password_reset_multiple_emails_tests

    def rule(self, event):
        custom_message = event.deep_get("detail", "custom_message", default="")
        emails_raw = event.deep_get("detail", "target_details", default="")
        if custom_message != "Ask for password reset":
            return False
        try:
            emails = json.loads(emails_raw)
        except json.decoder.JSONDecodeError:
            return False
        if len(emails) > 1:
            return True
        return False

    def title(self, event):
        emails = event.deep_get("detail", "target_details", default="")
        return f"[GitLab] Multiple password reset emails requested for {emails}"
