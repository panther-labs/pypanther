import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_reference_url, github_webhook_alert_context


@panther_managed
class GitHubWebhookWorkflowSkipCommits(Rule):
    id = "GitHub.Webhook.WorkflowSkipCommits-prototype"
    display_name = "GitHub Commits Skipping Workflows"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0005:T1622"]}
    tags = ["CI/CD", "Workflow"]
    default_severity = Severity.MEDIUM
    default_description = "Detects commits from cross-fork scenarios that contain workflow skip directives, which bypass GitHub Actions workflows. These skip patterns ([skip ci], [ci skip], [no ci], [skip actions], [actions skip], skip-checks:true) can be used to avoid security checks and CI/CD processes. This rule only alerts on commits to public forkable repositories.\n"
    default_runbook = "1. Review the commit message and author to determine if the workflow skip was intentional and authorized 2. Verify that skipping workflows is appropriate for the type of changes made 3. Check if the repository has policies requiring workflow runs for certain changes 4. Consider if the skip bypasses important security or quality checks 5. Monitor for patterns of excessive workflow skipping that might indicate policy circumvention\n"
    default_reference = "https://docs.github.com/en/actions/managing-workflow-runs/skipping-workflow-runs"
    SKIP_PATTERNS = [
        "\\[skip ci\\]",
        "\\[ci skip\\]",
        "\\[no ci\\]",
        "\\[skip actions\\]",
        "\\[actions skip\\]",
        "skip-checks:\\s*true",
    ]
    COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in SKIP_PATTERNS]

    def rule(self, event):
        if not event.get("pusher"):
            return False
        repo = event.get("repository", {})
        if repo.get("private") or not repo.get("allow_forking"):
            return False
        messages = event.deep_walk("commits", "message")
        if not isinstance(messages, list):
            messages = [messages]
        for message in messages:
            if self._has_skip_pattern(message):
                return True
        return False

    def _has_skip_pattern(self, message):
        if not message:
            return False
        return any(pattern.search(message) for pattern in self.COMPILED_PATTERNS)

    def title(self, event):
        repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
        head_commit = event.deep_get("head_commit", default={})
        commit_sha = head_commit.get("id", "<NO_SHA>")[:8]
        return f"Cross-fork workflow skip commit detected in {repo_name} ({commit_sha})"

    def alert_context(self, event):
        context = github_webhook_alert_context(event)
        skip_commits = []
        commits = event.get("commits", [{}])
        for commit in commits:
            commit_message = commit.get("message", "")
            if self._has_skip_pattern(commit_message):
                matched_patterns = [
                    self.SKIP_PATTERNS[i]
                    for i, pattern in enumerate(self.COMPILED_PATTERNS)
                    if pattern.search(commit_message)
                ]
                skip_commits.append(
                    {
                        "id": commit.get("id"),
                        "message": commit_message,
                        "author": commit.get("author", {}).get("name"),
                        "matched_patterns": matched_patterns,
                    },
                )
        context["skip_commits"] = skip_commits
        return context

    def reference(self, event):
        if reference_url := github_reference_url(event):
            return reference_url
        return "DEFAULT"

    tests = [
        RuleTest(
            name="Public Forkable Repo with Skip CI Pattern",
            expected_result=True,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "ref": "refs/heads/main",
                "repository": {
                    "id": 123456789,
                    "name": "test-repo",
                    "full_name": "org/test-repo",
                    "private": False,
                    "allow_forking": True,
                    "owner": {"login": "org"},
                },
                "commits": [
                    {
                        "id": "abc123",
                        "message": "Fix documentation [skip ci]",
                        "author": {"name": "Developer", "email": "dev@example.com"},
                    },
                ],
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Public Forkable Repo with Case Insensitive Skip Pattern",
            expected_result=True,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "ref": "refs/heads/feature",
                "repository": {
                    "id": 123456789,
                    "name": "test-repo",
                    "full_name": "org/test-repo",
                    "private": False,
                    "allow_forking": True,
                },
                "commits": [{"id": "def456", "message": "Update config [SKIP CI]"}],
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Public Forkable Repo with Multiple Skip Patterns",
            expected_result=True,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "ref": "refs/heads/main",
                "repository": {"private": False, "allow_forking": True, "full_name": "org/test-repo"},
                "commits": [
                    {"id": "ghi789", "message": "Regular commit"},
                    {"id": "jkl012", "message": "Minor fix [ci skip]"},
                ],
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Private Repo with Skip CI Pattern (Should Not Alert)",
            expected_result=False,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "ref": "refs/heads/main",
                "repository": {"private": True, "allow_forking": True, "full_name": "org/private-repo"},
                "commits": [{"id": "private123", "message": "Internal change [skip ci]"}],
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Public Repo with Forking Disabled and Skip CI (Should Not Alert)",
            expected_result=False,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "ref": "refs/heads/main",
                "repository": {"private": False, "allow_forking": False, "full_name": "org/no-fork-repo"},
                "commits": [{"id": "nofork123", "message": "Change [skip ci]"}],
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Public Forkable Repo without Skip Patterns (Should Not Alert)",
            expected_result=False,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "ref": "refs/heads/main",
                "repository": {"private": False, "allow_forking": True, "full_name": "org/test-repo"},
                "commits": [{"id": "clean123", "message": "Add new feature with tests"}],
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Non-Push Event with Skip Pattern (Should Not Alert)",
            expected_result=False,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "pull_request": {"id": 123, "title": "Fix bug [skip ci]"},
                "repository": {"private": False, "allow_forking": True, "full_name": "org/test-repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Public Forkable Repo with Skip Actions Pattern",
            expected_result=True,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "ref": "refs/heads/main",
                "repository": {"private": False, "allow_forking": True, "full_name": "org/test-repo"},
                "commits": [{"id": "actions123", "message": "Update README [skip actions]"}],
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Public Forkable Repo with Skip Checks Trailer",
            expected_result=True,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "ref": "refs/heads/main",
                "repository": {"private": False, "allow_forking": True, "full_name": "org/test-repo"},
                "commits": [{"id": "trailer123", "message": "Minor typo fix\n\nskip-checks: true"}],
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Public Forkable Repo with No CI Pattern",
            expected_result=True,
            log={
                "pusher": {"name": "Developer", "email": "dev@example.com"},
                "ref": "refs/heads/main",
                "repository": {"private": False, "allow_forking": True, "full_name": "org/test-repo"},
                "commits": [{"id": "noci123", "message": "Documentation update [no ci]"}],
                "p_log_type": "GitHub.Webhook",
            },
        ),
    ]
