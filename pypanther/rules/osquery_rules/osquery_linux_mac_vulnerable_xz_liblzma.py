from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

osquery_linux_mac_vulnerable_x_zliblzma_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Vulnerable liblzma",
        ExpectedResult=True,
        Log={
            "name": "pack_vuln-management_rpm_packages",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "source": "test-host",
                "name": "liblzma.so",
                "version": "5.6.1.000",
                "status": "Potentially vulnerable",
            },
        },
    ),
    PantherRuleTest(
        Name="Vulnerable xz",
        ExpectedResult=True,
        Log={
            "name": "pack_vuln-management_deb_packages",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "source": "test-host",
                "name": "xz",
                "version": "5.6.0.000",
                "status": "Potentially vulnerable",
            },
        },
    ),
    PantherRuleTest(
        Name="Not vulnerable",
        ExpectedResult=False,
        Log={
            "name": "pack_vuln-management_rpm_packages",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "source": "test-host",
                "name": "liblzma.so",
                "version": "5.4.6.000",
                "status": "Most likely not vulnerable",
            },
        },
    ),
]


class OsqueryLinuxMacVulnerableXZliblzma(PantherRule):
    RuleID = "Osquery.Linux.Mac.VulnerableXZliblzma-prototype"
    DisplayName = "A backdoored version of XZ or liblzma is vulnerable to CVE-2024-3094"
    LogTypes = [LogType.Osquery_Differential]
    Tags = ["Osquery", "MacOS", "Linux", "Emerging Threats", "Supply Chain Compromise"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1195.001"]}
    Severity = PantherSeverity.High
    Description = "Detects vulnerable versions of XZ and liblzma on Linux and MacOS using Osquery logs. Versions 5.6.0 and 5.6.1 of xz and liblzma are most likely vulnerable to backdoor exploit. Vuln management pack must be enabled: https://github.com/osquery/osquery/blob/master/packs/vuln-management.conf\n"
    Runbook = "Upgrade/downgrade xz and liblzma to non-vulnerable versions"
    Reference = "https://gist.github.com/jamesspi/ee8319f55d49b4f44345c626f80c430f"
    SummaryAttributes = ["name", "hostIdentifier", "action"]
    Tests = osquery_linux_mac_vulnerable_x_zliblzma_tests
    QUERY_NAMES = {
        "pack_vuln-management_homebrew_packages",
        "pack_vuln-management_deb_packages",
        "pack_vuln-management_rpm_packages",
    }
    VULNERABLE_PACKAGES = {"xz", "liblzma", "xz-libs", "xz-utils"}
    VULNERABLE_VERSIONS = {"5.6.0", "5.6.1"}

    def rule(self, event):
        package = event.deep_get("columns", "name", default="")
        version = event.deep_get("columns", "version", default="")
        return all(
            [
                event.get("name") in self.QUERY_NAMES,
                package in self.VULNERABLE_PACKAGES or package.startswith("liblzma"),
                any((version.startswith(v) for v in self.VULNERABLE_VERSIONS)),
            ]
        )

    def title(self, event):
        host = event.get("hostIdentifier")
        name = event.deep_get("columns", "name", default="")
        version = event.deep_get("columns", "version", default="")
        return f"[CVE-2024-3094] {name} {version} Potentially vulnerable on {host}"
