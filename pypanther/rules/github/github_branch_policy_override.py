from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GitHubBranchPolicyOverride(Rule):
    id = "GitHub.Branch.PolicyOverride-prototype"
    display_name = "GitHub Branch Protection Policy Override"
    log_types = [LogType.GITHUB_AUDIT]
    tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    default_severity = Severity.HIGH
    default_description = "Bypassing branch protection controls could indicate malicious use of admin credentials in an attempt to hide activity."
    default_runbook = "Verify that the GitHub admin performed this activity and validate its use."
    default_reference = "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule"

    def rule(self, event):
        return event.get("action") == "protected_branch.policy_override"

    def title(self, event):
        return f"A branch protection requirement in the repository [{event.get('repo', '<UNKNOWN_REPO>')}] was overridden by user [{event.udm('actor_user')}]"

    tests = [
        RuleTest(
            name="GitHub - Branch Protection Policy Override",
            expected_result=True,
            log={
                "actor": "cat",
                "action": "protected_branch.policy_override",
                "created_at": 1621305118553,
                "p_log_type": "GitHub.Audit",
                "org": "my-org",
                "repo": "my-org/my-repo",
            },
        ),
        RuleTest(
            name="GitHub - Protected Branch Name Updated",
            expected_result=False,
            log={
                "actor": "cat",
                "action": "protected_branch.update_name",
                "created_at": 1621305118553,
                "org": "my-org",
                "p_log_type": "GitHub.Audit",
                "repo": "my-org/my-repo",
            },
        ),
    ]
