from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.github import github_alert_context


@panther_managed
class GitHubRepoRulesetModified(Rule):
    id = "GitHub.Repo.RulesetModified-prototype"
    display_name = "GitHub Repository Ruleset Modified"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Defense Evasion", "Impair Defenses", "Disable or Modify Tools"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_reference = "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets"
    default_severity = Severity.INFO
    default_description = "Disabling repository ruleset controls could indicate malicious use of admin credentials in an attempt to hide activity."
    default_runbook = "Verify that ruleset modifications are intended and authorized."

    def rule(self, event):
        return event.get("action").startswith("repository_ruleset.")

    def title(self, event):
        action = "modified"
        if event.get("action").endswith("destroy"):
            action = "deleted"
        elif event.get("action").endswith("create"):
            action = "created"
        title_str = f"Github repository ruleset for [{event.get('repo', '<UNKNOWN_REPO>')}] {action} by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
        if event.get("ruleset_source_type", default="<UNKNOWN_SOURCE_TYPE>") == "Organization":
            title_str = f"Github repository ruleset for Organization [{event.get('org', '<UNKNOWN_ORG>')}] {action} by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
        return title_str

    def dedup(self, event):
        return event.get("_document_id", "")

    def severity(self, event):
        if event.get("action").endswith("create"):
            return "INFO"
        if event.get("action").endswith("update"):
            return "MEDIUM"
        if event.get("action").endswith("destroy"):
            return "HIGH"
        return "DEFAULT"

    def alert_context(self, event):
        ctx = github_alert_context(event)
        ctx["user"] = event.get("actor", "")
        ctx["actor_is_bot"] = event.get("actor_is_bot", "")
        ctx["actor_user_agent"] = event.get("user_agent", "")
        ctx["business"] = event.get("business", "")
        ctx["public_repo"] = event.get("public_repo", "")
        ctx["operation_type"] = event.get("operation_type", "")
        ctx["ruleset_bypass_actors"] = event.deep_walk("ruleset_bypass_actors")
        ctx["ruleset_conditions"] = event.deep_walk("ruleset_conditions")
        ctx["ruleset_rules"] = event.deep_walk("ruleset_rules")
        return ctx

    tests = [
        RuleTest(
            name="GitHub - Ruleset Created",
            expected_result=True,
            log={
                "action": "repository_ruleset.create",
                "actor": "dog",
                "actor_id": "999999999",
                "actor_is_bot": False,
                "actor_location": {"country_code": "US"},
                "business": "bizname",
                "business_id": "12345",
                "created_at": "2024-12-17 00:00:00000000",
                "operation_type": "create",
                "org": "some-org",
                "org_id": 12345678,
                "public_repo": True,
                "repo": "some-org/ruleset-repo",
                "repo_id": 123456789,
                "ruleset_bypass_actors": [
                    {"actor_id": 123456, "actor_type": "Integration", "bypass_mode": "always", "id": 123456},
                    {"actor_id": 123456, "actor_type": "Team", "bypass_mode": "always", "id": 1234567},
                ],
                "ruleset_conditions": [
                    {
                        "id": 1234567,
                        "parameters": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
                        "target": "ref_name",
                    },
                ],
                "ruleset_enforcement": "enabled",
                "ruleset_id": "1234567",
                "ruleset_name": "a-ruleset-name",
                "ruleset_rules": [
                    {
                        "id": 12345678,
                        "parameters": {
                            "allowed_merge_methods": ["merge", "squash", "rebase"],
                            "authorized_dismissal_actors_only": False,
                            "automatic_copilot_code_review_enabled": False,
                            "dismiss_stale_reviews_on_push": False,
                            "ignore_approvals_from_contributors": False,
                            "require_code_owner_review": False,
                            "require_last_push_approval": False,
                            "required_approving_review_count": 1,
                            "required_review_thread_resolution": False,
                            "required_reviewers": [],
                        },
                        "type": "pull_request",
                    },
                    {"id": 12345678, "parameters": {}, "type": "deletion"},
                    {"id": 12345678, "parameters": {}, "type": "non_fast_forward"},
                ],
                "ruleset_source_type": "Repository",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            },
        ),
        RuleTest(
            name="GitHub - Ruleset Deleted",
            expected_result=True,
            log={
                "action": "repository_ruleset.destroy",
                "actor": "dog",
                "actor_id": "999999999",
                "actor_is_bot": False,
                "actor_location": {"country_code": "US"},
                "business": "bizname",
                "business_id": "12345",
                "created_at": "2024-12-17 00:00:00000000",
                "operation_type": "remove",
                "org": "some-org",
                "org_id": 12345678,
                "public_repo": False,
                "repo": "some-org/ruleset-repo",
                "repo_id": 123456789,
                "ruleset_bypass_actors": [
                    {"actor_id": 123456, "actor_type": "Integration", "bypass_mode": "always", "id": 123456},
                    {"actor_id": 123456, "actor_type": "Team", "bypass_mode": "always", "id": 1234567},
                ],
                "ruleset_conditions": [
                    {
                        "id": 1234567,
                        "parameters": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
                        "target": "ref_name",
                    },
                ],
                "ruleset_enforcement": "enabled",
                "ruleset_id": "1234567",
                "ruleset_name": "a-ruleset-name",
                "ruleset_rules": [
                    {
                        "id": 10994218,
                        "parameters": {
                            "allowed_merge_methods": ["merge", "squash", "rebase"],
                            "authorized_dismissal_actors_only": False,
                            "automatic_copilot_code_review_enabled": True,
                            "dismiss_stale_reviews_on_push": False,
                            "ignore_approvals_from_contributors": False,
                            "require_code_owner_review": False,
                            "require_last_push_approval": False,
                            "required_approving_review_count": 1,
                            "required_review_thread_resolution": False,
                            "required_reviewers": [],
                        },
                        "type": "pull_request",
                    },
                    {"id": 10994219, "parameters": {}, "type": "deletion"},
                    {"id": 10994220, "parameters": {}, "type": "non_fast_forward"},
                ],
                "ruleset_source_type": "Repository",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            },
        ),
        RuleTest(
            name="GitHub - Non Webhook Event",
            expected_result=False,
            log={
                "actor": "cat",
                "action": "org.invite_member",
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "repo": "my-org/my-repo",
            },
        ),
        RuleTest(
            name="Github - Ruleset Modified",
            expected_result=True,
            log={
                "action": "repository_ruleset.update",
                "actor": "dog",
                "actor_id": "999999999",
                "actor_is_bot": False,
                "actor_location": {"country_code": "US"},
                "business": "bizname",
                "business_id": "12345",
                "created_at": "2024-12-17 00:00:00000000",
                "operation_type": "modify",
                "org": "some-org",
                "org_id": 12345678,
                "public_repo": False,
                "repo": "some-org/ruleset-repo",
                "repo_id": 123456789,
                "ruleset_bypass_actors": [
                    {"actor_id": 123456, "actor_type": "Integration", "bypass_mode": "always", "id": 123456},
                    {"actor_id": 123456, "actor_type": "Team", "bypass_mode": "always", "id": 1234567},
                ],
                "ruleset_conditions": [
                    {
                        "id": 1234567,
                        "parameters": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
                        "target": "ref_name",
                    },
                ],
                "ruleset_enforcement": "enabled",
                "ruleset_id": "1234567",
                "ruleset_name": "a-ruleset-name",
                "ruleset_rules_updated": [
                    {
                        "id": 12345678,
                        "old_parameters": {
                            "allowed_merge_methods": ["merge", "squash", "rebase"],
                            "authorized_dismissal_actors_only": False,
                            "automatic_copilot_code_review_enabled": False,
                            "dismiss_stale_reviews_on_push": False,
                            "ignore_approvals_from_contributors": False,
                            "require_code_owner_review": False,
                            "require_last_push_approval": False,
                            "required_approving_review_count": 1,
                            "required_review_thread_resolution": False,
                            "required_reviewers": [],
                        },
                        "parameters": {
                            "allowed_merge_methods": ["merge", "squash", "rebase"],
                            "authorized_dismissal_actors_only": False,
                            "automatic_copilot_code_review_enabled": True,
                            "dismiss_stale_reviews_on_push": False,
                            "ignore_approvals_from_contributors": False,
                            "require_code_owner_review": False,
                            "require_last_push_approval": False,
                            "required_approving_review_count": 1,
                            "required_review_thread_resolution": False,
                            "required_reviewers": [],
                        },
                        "type": "pull_request",
                    },
                ],
                "ruleset_source_type": "Repository",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            },
        ),
        RuleTest(
            name="Github - Ruleset Modified for entire Organization",
            expected_result=True,
            log={
                "action": "repository_ruleset.update",
                "actor": "dog",
                "actor_id": "999999999",
                "actor_is_bot": False,
                "actor_location": {"country_code": "US"},
                "business": "bizname",
                "business_id": "12345",
                "created_at": "2024-12-17 00:00:00000000",
                "operation_type": "modify",
                "org": "some-org",
                "org_id": 12345678,
                "ruleset_enforcement": "disabled",
                "ruleset_id": "1082915",
                "ruleset_name": "Name of org-wide ruleset",
                "ruleset_old_enforcement": "evaluate",
                "ruleset_source_type": "Organization",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            },
        ),
    ]
