from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class CiscoUmbrellaDNSBlocked(Rule):
    id = "CiscoUmbrella.DNS.Blocked-prototype"
    display_name = "Cisco Umbrella Domain Blocked"
    dedup_period_minutes = 480
    log_types = [LogType.CISCO_UMBRELLA_DNS]
    tags = ["DNS"]
    default_severity = Severity.LOW
    default_description = "Monitor blocked domains"
    default_runbook = "Inspect the blocked domain and lookup for malware"
    default_reference = "https://support.umbrella.com/hc/en-us/articles/230563627-How-to-determine-if-a-domain-or-resource-is-being-blocked-using-Chrome-Net-Internals"
    summary_attributes = ["action", "internalIp", "externalIp", "domain", "responseCode"]

    def rule(self, event):
        return event.get("action") == "Blocked"

    def title(self, event):
        return "Access denied to domain " + event.get("domain", "<UNKNOWN_DOMAIN>")

    tests = [
        RuleTest(
            name="Domain Blocked",
            expected_result=True,
            log={
                "action": "Blocked",
                "internalIp": "136.24.229.58",
                "externalIp": "136.24.229.58",
                "timestamp": "2020-05-21 19:20:25.000",
                "responseCode": "NOERROR",
                "domain": "malware.gvt2.com.",
            },
        ),
        RuleTest(
            name="Action Allowed",
            expected_result=False,
            log={
                "action": "Allowed",
                "internalIp": "136.24.229.58",
                "externalIp": "136.24.229.58",
                "timestamp": "2020-05-21 19:20:25.000",
                "responseCode": "NOERROR",
                "domain": "beacons3.gvt2.com.",
            },
        ),
    ]
