from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class GSuiteGoogleAccess(Rule):
    id = "GSuite.GoogleAccess-prototype"
    display_name = "Google Accessed a GSuite Resource"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite"]
    default_severity = Severity.LOW
    default_description = (
        "Google accessed one of your GSuite resources directly, most likely in response to a support incident.\n"
    )
    default_reference = "https://support.google.com/a/answer/9230474?hl=en"
    default_runbook = "Your GSuite Super Admin can visit the Access Transparency report in the GSuite Admin Dashboard to see more details about the access.\n"
    summary_attributes = ["actor:email"]

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "access_transparency":
            return False
        return bool(event.get("type") == "GSUITE_RESOURCE")

    tests = [
        RuleTest(
            name="Normal Login Event",
            expected_result=False,
            log={"id": {"applicationName": "login"}, "type": "login"},
        ),
        RuleTest(
            name="Resource Accessed by Google",
            expected_result=True,
            log={"id": {"applicationName": "access_transparency"}, "type": "GSUITE_RESOURCE"},
        ),
    ]
