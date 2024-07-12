from typing import List

from panther_detection_helpers.caching import get_string_set, put_string_set

from pypanther import PantherLogType, PantherRule, PantherRuleMock, PantherRuleTest, PantherSeverity

git_hub_repo_initial_access_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        name="GitHub - Initial Access",
        expected_result=True,
        mocks=[
            PantherRuleMock(object_name="get_string_set", return_value=""),
            PantherRuleMock(object_name="put_string_set", return_value=""),
        ],
        log={
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
        name="GitHub - Repeated Access",
        expected_result=False,
        mocks=[PantherRuleMock(object_name="get_string_set", return_value='"cat":"my-repo"\n')],
        log={
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
        name="GitHub - Initial Access Public Repo",
        expected_result=False,
        mocks=[
            PantherRuleMock(object_name="get_string_set", return_value=""),
            PantherRuleMock(object_name="put_string_set", return_value=""),
        ],
        log={
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
        name="GitHub - Clone without Actor",
        expected_result=False,
        log={
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
    id_ = "GitHub.Repo.InitialAccess-prototype"
    display_name = "GitHub User Initial Access to Private Repo"
    log_types = [PantherLogType.GitHub_Audit]
    tags = ["GitHub"]
    default_reference = "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/managing-an-individuals-access-to-an-organization-repository"
    default_severity = PantherSeverity.info
    default_description = (
        "Detects when a user initially accesses a private organization repository."
    )
    tests = git_hub_repo_initial_access_tests
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
