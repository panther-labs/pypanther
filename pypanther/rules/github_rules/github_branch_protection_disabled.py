from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_hub_branch_protection_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Branch Protection Disabled",
        ExpectedResult=True,
        Log={
            "actor": "cat",
            "action": "protected_branch.destroy",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
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


class GitHubBranchProtectionDisabled(PantherRule):
    RuleID = "GitHub.Branch.ProtectionDisabled-prototype"
    DisplayName = "GitHub Branch Protection Disabled"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    Severity = PantherSeverity.High
    Description = "Disabling branch protection controls could indicate malicious use of admin credentials in an attempt to hide activity."
    Runbook = "Verify that branch protection should be disabled on the repository and re-enable as necessary."
    Reference = "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule"
    Tests = git_hub_branch_protection_disabled_tests

    def rule(self, event):
        return event.get("action") == "protected_branch.destroy"

    def title(self, event):
        return f"A branch protection was removed from the repository [{event.get('repo', '<UNKNOWN_REPO>')}] by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
