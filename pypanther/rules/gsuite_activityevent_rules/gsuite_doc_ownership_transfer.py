from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_config import config
from pypanther.log_types import LogType

g_suite_doc_ownership_transfer_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Ownership Transferred Within Organization",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "admin"},
            "name": "TRANSFER_DOCUMENT_OWNERSHIP",
            "parameters": {"NEW_VALUE": "homer.simpson@example.com"},
        },
    ),
    PantherRuleTest(
        Name="Document Transferred to External User",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "admin"},
            "name": "TRANSFER_DOCUMENT_OWNERSHIP",
            "parameters": {"NEW_VALUE": "monty.burns@badguy.com"},
        },
    ),
]


class GSuiteDocOwnershipTransfer(PantherRule):
    RuleID = "GSuite.DocOwnershipTransfer-prototype"
    DisplayName = "GSuite Document External Ownership Transfer"
    Enabled = False
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite", "Configuration Required", "Collection:Data from Information Repositories"]
    Reports = {"MITRE ATT&CK": ["TA0009:T1213"]}
    Severity = PantherSeverity.Low
    Description = "A GSuite document's ownership was transferred to an external party.\n"
    Reference = "https://support.google.com/drive/answer/2494892?hl=en&co=GENIE.Platform%3DDesktop&sjid=864417124752637253-EU"
    Runbook = (
        "Verify that this document did not contain sensitive or private company information.\n"
    )
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_doc_ownership_transfer_tests
    GSUITE_TRUSTED_OWNERSHIP_DOMAINS = {
        "@" + domain for domain in config.GSUITE_TRUSTED_OWNERSHIP_DOMAINS
    }

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "admin":
            return False
        if bool(event.get("name") == "TRANSFER_DOCUMENT_OWNERSHIP"):
            new_owner = deep_get(event, "parameters", "NEW_VALUE", default="<UNKNOWN USER>")
            return bool(new_owner) and (
                not any((new_owner.endswith(x) for x in self.GSUITE_TRUSTED_OWNERSHIP_DOMAINS))
            )
        return False
