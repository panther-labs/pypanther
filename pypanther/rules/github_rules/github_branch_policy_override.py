from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_hub_branch_policy_override_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Branch Protection Policy Override",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "protected_branch.policy_override",
            "created_at": 1621305118553,
            "p_log_type": "GitHub.Audit",
            "org": "my-org",
            "repo": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Protected Branch Name Updated",
        ExpectedResult=False,
        Log={
            "actor": "cat",
            "action": "protected_branch.update_name",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
]


class GitHubBranchPolicyOverride(PantherRule):
    RuleID = "GitHub.Branch.PolicyOverride-prototype"
    DisplayName = "GitHub Branch Protection Policy Override"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    Severity = PantherSeverity.High
    Description = "Bypassing branch protection controls could indicate malicious use of admin credentials in an attempt to hide activity."
    Runbook = "Verify that the GitHub admin performed this activity and validate its use."
    Reference = "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule"
    Tests = git_hub_branch_policy_override_tests

    def rule(self, event):
        return event.get("action") == "protected_branch.policy_override"

    def title(self, event):
        return f"A branch protection requirement in the repository [{event.get('repo', '<UNKNOWN_REPO>')}] was overridden by user [{event.udm('actor_user')}]"
