from difflib import SequenceMatcher

from pypanther import PantherLogType, PantherRule, PantherSeverity


class CiscoUmbrellaDNSFuzzyMatching(PantherRule):
    RuleID = "CiscoUmbrella.DNS.FuzzyMatching-prototype"
    DisplayName = "Cisco Umbrella Domain Name Fuzzy Matching"
    Enabled = False
    DedupPeriodMinutes = 15
    LogTypes = [PantherLogType.CiscoUmbrella_DNS]
    Tags = ["Configuration Required", "DNS"]
    Reference = "https://umbrella.cisco.com/blog/abcs-of-dns"
    Severity = PantherSeverity.Medium
    Description = "Identify lookups to suspicious domains that could indicate a phishing attack."
    Runbook = "Validate if your organization owns the domain, otherwise investigate the host that made the domain resolution.\n"
    DOMAIN = ""  # The domain to monitor for phishing, for example "google.com"
    # List all of your known-good domains here
    ALLOW_SET = {}
    SIMILARITY_RATIO = 0.7

    def rule(self, event):
        # Domains coming through umbrella end with a dot, such as google.com.
        domain = ".".join(event.get("domain").rstrip(".").split(".")[-2:]).lower()
        return (
            domain not in self.ALLOW_SET and SequenceMatcher(None, self.DOMAIN, domain).ratio() >= self.SIMILARITY_RATIO
        )

    def title(self, event):
        return f"Suspicious DNS resolution to {event.get('domain')}"
