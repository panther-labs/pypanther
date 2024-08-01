import json

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

git_lab_audit_password_reset_multiple_emails_tests: list[RuleTest] = [
    RuleTest(name="not a password reset", expected_result=False, log={"detail": {"custom_message": "hello world"}}),
    RuleTest(
        name="one email",
        expected_result=False,
        log={"detail": {"custom_message": "Ask for password reset", "target_details": "example@test.com"}},
    ),
    RuleTest(
        name="multiple emails",
        expected_result=True,
        log={
            "detail": {
                "custom_message": "Ask for password reset",
                "target_details": '["example@test.com", "example2@test.com"]',
            },
        },
    ),
]


@panther_managed
class GitLabAuditPasswordResetMultipleEmails(Rule):
    id = "GitLab.Audit.Password.Reset.Multiple.Emails-prototype"
    display_name = "CVE-2023-7028 - GitLab Audit Password Reset Multiple Emails"
    log_types = [LogType.GITLAB_AUDIT]
    tags = ["GitLab", "CVE-2023-7028"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195", "TA0001:T1190", "TA0003:T1098"]}
    default_severity = Severity.HIGH
    default_description = "Attackers are exploiting a Critical (CVSS 10.0) GitLab vulnerability in which user account password reset emails could be delivered to an unverified email address."
    default_reference = "https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released/"
    tests = git_lab_audit_password_reset_multiple_emails_tests

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
