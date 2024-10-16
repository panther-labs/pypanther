from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.config import config


@panther_managed
class GSuiteDocOwnershipTransfer(Rule):
    id = "GSuite.DocOwnershipTransfer-prototype"
    display_name = "GSuite Document External Ownership Transfer"
    enabled = False
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Configuration Required", "Collection:Data from Information Repositories"]
    reports = {"MITRE ATT&CK": ["TA0009:T1213"]}
    default_severity = Severity.LOW
    default_description = "A GSuite document's ownership was transferred to an external party.\n"
    default_reference = (
        "https://support.google.com/drive/answer/2494892?hl=en&co=GENIE.Platform%3DDesktop&sjid=864417124752637253-EU"
    )
    default_runbook = "Verify that this document did not contain sensitive or private company information.\n"
    summary_attributes = ["actor:email"]
    GSUITE_TRUSTED_OWNERSHIP_DOMAINS = {"@" + domain for domain in config.GSUITE_TRUSTED_OWNERSHIP_DOMAINS}

    def rule(self, event):
        if event.deep_get("id", "applicationName") != "admin":
            return False
        if bool(event.get("name") == "TRANSFER_DOCUMENT_OWNERSHIP"):
            new_owner = event.deep_get("parameters", "NEW_VALUE", default="<UNKNOWN USER>")
            return bool(new_owner) and (not any(new_owner.endswith(x) for x in self.GSUITE_TRUSTED_OWNERSHIP_DOMAINS))
        return False

    tests = [
        RuleTest(
            name="Ownership Transferred Within Organization",
            expected_result=False,
            log={
                "id": {"applicationName": "admin"},
                "name": "TRANSFER_DOCUMENT_OWNERSHIP",
                "parameters": {"NEW_VALUE": "homer.simpson@example.com"},
            },
        ),
        RuleTest(
            name="Document Transferred to External User",
            expected_result=True,
            log={
                "id": {"applicationName": "admin"},
                "name": "TRANSFER_DOCUMENT_OWNERSHIP",
                "parameters": {"NEW_VALUE": "monty.burns@badguy.com"},
            },
        ),
    ]
