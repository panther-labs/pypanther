from typing import List

from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity

git_hub_branch_protection_disabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        name="GitHub - Branch Protection Disabled",
        expected_result=True,
        log={
            "actor": "cat",
            "action": "protected_branch.destroy",
            "created_at": 1621305118553,
            "org": "my-org",
            "p_log_type": "GitHub.Audit",
            "repo": "my-org/my-repo",
        },
    ),
    PantherRuleTest(
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


class GitHubBranchProtectionDisabled(PantherRule):
    id_ = "GitHub.Branch.ProtectionDisabled-prototype"
    display_name = "GitHub Branch Protection Disabled"
    log_types = [PantherLogType.GitHub_Audit]
    tags = ["GitHub", "Initial Access:Supply Chain Compromise"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195"]}
    default_severity = PantherSeverity.high
    default_description = "Disabling branch protection controls could indicate malicious use of admin credentials in an attempt to hide activity."
    default_runbook = "Verify that branch protection should be disabled on the repository and re-enable as necessary."
    default_reference = "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule"
    tests = git_hub_branch_protection_disabled_tests

    def rule(self, event):
        return event.get("action") == "protected_branch.destroy"

    def title(self, event):
        return f"A branch protection was removed from the repository [{event.get('repo', '<UNKNOWN_REPO>')}] by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
