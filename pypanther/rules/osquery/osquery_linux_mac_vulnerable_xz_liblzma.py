from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OsqueryLinuxMacVulnerableXZliblzma(Rule):
    id = "Osquery.Linux.Mac.VulnerableXZliblzma-prototype"
    display_name = "A backdoored version of XZ or liblzma is vulnerable to CVE-2024-3094"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "MacOS", "Linux", "Emerging Threats", "Supply Chain Compromise"]
    reports = {"MITRE ATT&CK": ["TA0001:T1195.001"]}
    default_severity = Severity.HIGH
    default_description = "Detects vulnerable versions of XZ and liblzma on Linux and MacOS using Osquery logs. Versions 5.6.0 and 5.6.1 of xz and liblzma are most likely vulnerable to backdoor exploit. Vuln management pack must be enabled: https://github.com/osquery/osquery/blob/master/packs/vuln-management.conf\n"
    default_runbook = "Upgrade/downgrade xz and liblzma to non-vulnerable versions"
    default_reference = "https://gist.github.com/jamesspi/ee8319f55d49b4f44345c626f80c430f"
    summary_attributes = ["name", "hostIdentifier", "action"]
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
                any(version.startswith(v) for v in self.VULNERABLE_VERSIONS),
            ],
        )

    def title(self, event):
        host = event.get("hostIdentifier")
        name = event.deep_get("columns", "name", default="")
        version = event.deep_get("columns", "version", default="")
        return f"[CVE-2024-3094] {name} {version} Potentially vulnerable on {host}"

    tests = [
        RuleTest(
            name="Vulnerable liblzma",
            expected_result=True,
            log={
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
        RuleTest(
            name="Vulnerable xz",
            expected_result=True,
            log={
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
        RuleTest(
            name="Not vulnerable",
            expected_result=False,
            log={
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
