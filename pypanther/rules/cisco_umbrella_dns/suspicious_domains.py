from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

cisco_umbrella_dns_suspicious_tests: list[RuleTest] = [
    RuleTest(
        name="Suspicious Domain",
        expected_result=True,
        log={
            "action": "Allow",
            "internalIp": "136.24.229.58",
            "externalIp": "136.24.229.58",
            "timestamp": "2020-05-21 19:20:25.000",
            "responseCode": "NOERROR",
            "domain": "cron.photoscape.ch.",
        },
    ),
    RuleTest(
        name="Safe Domain",
        expected_result=False,
        log={
            "action": "Allowed",
            "internalIp": "136.24.229.58",
            "externalIp": "136.24.229.58",
            "timestamp": "2020-05-21 19:20:25.000",
            "responseCode": "NOERROR",
            "domain": "google.com.",
        },
    ),
]


@panther_managed
class CiscoUmbrellaDNSSuspicious(Rule):
    id = "CiscoUmbrella.DNS.Suspicious-prototype"
    display_name = "Cisco Umbrella Suspicious Domains"
    enabled = False
    dedup_period_minutes = 480
    log_types = [LogType.CISCO_UMBRELLA_DNS]
    tags = ["DNS", "Configuration Required"]
    default_reference = "https://umbrella.cisco.com/blog/abcs-of-dns"
    default_severity = Severity.LOW
    default_description = "Monitor suspicious or known malicious domains"
    default_runbook = "Inspect the domain and check the host for other indicators of compromise"
    summary_attributes = ["action", "internalIp", "externalIp", "domain", "responseCode"]
    tests = cisco_umbrella_dns_suspicious_tests
    DOMAINS_TO_MONITOR = {"photoscape.ch"}  # Sample malware domain

    def rule(self, event):
        return any(domain in event.get("domain") for domain in self.DOMAINS_TO_MONITOR)

    def title(self, event):
        return "Suspicious lookup to domain " + event.get("domain", "<UNKNOWN_DOMAIN>")
