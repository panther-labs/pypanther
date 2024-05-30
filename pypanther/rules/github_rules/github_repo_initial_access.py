from typing import List

from panther_detection_helpers.caching import get_string_set, put_string_set

from pypanther.base import PantherRule, PantherRuleMock, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

git_hub_repo_initial_access_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GitHub - Initial Access",
        ExpectedResult=True,
        Mocks=[
            PantherRuleMock(ObjectName="get_string_set", ReturnValue=""),
            PantherRuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "@timestamp": 1623971719091,
            "business": "",
            "org": "my-org",
            "repo": "my-org/my-repo",
            "action": "git.push",
            "p_log_type": "GitHub.Audit",
            "protocol_name": "ssh",
            "repository": "my-org/my-repo",
            "repository_public": False,
            "actor": "cat",
            "user": "",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Repeated Access",
        ExpectedResult=False,
        Mocks=[PantherRuleMock(ObjectName="get_string_set", ReturnValue='"cat":"my-repo"\n')],
        Log={
            "@timestamp": 1623971719091,
            "business": "",
            "org": "my-org",
            "repo": "my-org/my-repo",
            "action": "git.push",
            "p_log_type": "GitHub.Audit",
            "protocol_name": "ssh",
            "repository": "my-org/my-repo",
            "repository_public": False,
            "actor": "cat",
            "user": "",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Initial Access Public Repo",
        ExpectedResult=False,
        Mocks=[
            PantherRuleMock(ObjectName="get_string_set", ReturnValue=""),
            PantherRuleMock(ObjectName="put_string_set", ReturnValue=""),
        ],
        Log={
            "@timestamp": 1623971719091,
            "business": "",
            "org": "my-org",
            "repo": "my-org/my-repo",
            "action": "git.push",
            "p_log_type": "GitHub.Audit",
            "protocol_name": "ssh",
            "repository": "my-org/my-repo",
            "repository_public": True,
            "actor": "cat",
            "user": "",
        },
    ),
    PantherRuleTest(
        Name="GitHub - Clone without Actor",
        ExpectedResult=False,
        Log={
            "@timestamp": 1623971719091,
            "business": "",
            "org": "my-org",
            "repo": "my-org/my-repo",
            "action": "git.push",
            "p_log_type": "GitHub.Audit",
            "protocol_name": "ssh",
            "repository": "my-org/my-repo",
            "repository_public": False,
            "actor": "",
            "user": "",
        },
    ),
]


class GitHubRepoInitialAccess(PantherRule):
    RuleID = "GitHub.Repo.InitialAccess-prototype"
    DisplayName = "GitHub User Initial Access to Private Repo"
    LogTypes = [LogType.GitHub_Audit]
    Tags = ["GitHub"]
    Reference = "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/managing-an-individuals-access-to-an-organization-repository"
    Severity = PantherSeverity.Info
    Description = "Detects when a user initially accesses a private organization repository."
    Tests = git_hub_repo_initial_access_tests
    CODE_ACCESS_ACTIONS = ["git.clone", "git.push", "git.fetch"]

    def rule(self, event):
        # if the actor field is empty, short circuit the rule
        if not event.udm("actor_user"):
            return False
        if event.get("action") in self.CODE_ACCESS_ACTIONS and (not event.get("repository_public")):
            # Compute unique entry for this user + repo
            key = self.get_key(event)
            previous_access = get_string_set(key)
            if not previous_access:
                put_string_set(key, key)
                return True
        return False

    def title(self, event):
        return f"A user [{event.udm('actor_user')}] accessed a private repository [{event.get('repo', '<UNKNOWN_REPO>')}] for the first time."

    def get_key(self, event):
        return __name__ + ":" + str(event.udm("actor_user")) + ":" + str(event.get("repo"))
