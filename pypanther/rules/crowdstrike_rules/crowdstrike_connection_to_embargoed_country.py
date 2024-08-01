from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import crowdstrike_network_detection_alert_context

connectionto_embargoed_country_tests: list[RuleTest] = [
    RuleTest(
        name="Connection To CU",
        expected_result=True,
        log={
            "ConfigBuild": "1007.3.0016606.11",
            "ConfigStateHash": "1431649125",
            "ContextProcessId": "1685738",
            "ContextTimeStamp": "2023-04-28 18:49:37.731",
            "Entitlements": "15",
            "InContext": "0",
            "aid": "877761efa8db44d7redacted",
            "aip": "1.1.1.1",
            "cid": "cfe6986909644340redacted",
            "event": {
                "ConfigBuild": "1007.3.0016606.11",
                "ConfigStateHash": "1431649125",
                "ConnectionDirection": "0",
                "ConnectionFlags": "0",
                "ContextProcessId": "1685738",
                "ContextTimeStamp": "1682707777.731",
                "EffectiveTransmissionClass": "3",
                "Entitlements": "15",
                "EventOrigin": "1",
                "InContext": "0",
                "LocalAddressIP4": "10.0.0.1",
                "LocalPort": "137",
                "Protocol": "17",
                "RemoteAddressIP4": "152.206.0.1",
                "RemotePort": "443",
                "aid": "877761efa8db44d7redacted",
                "aip": "1.1.1.1",
                "cid": "cfe6986909644340redacted",
                "event_platform": "Win",
                "event_simpleName": "NetworkConnectIP4",
                "id": "34019b0c-c7de-4725-9f93-4b8d16688673",
                "name": "NetworkConnectIP4V12",
                "timestamp": "1682707778681",
            },
            "event_platform": "Win",
            "event_simpleName": "NetworkConnectIP4",
            "fdr_event_type": "NetworkConnectIP4",
            "id": "34019b0c-c7de-4725-9f93-4b8d16688673",
            "name": "NetworkConnectIP4V12",
            "p_any_ip_addresses": ["152.206.0.1", "10.0.0.1", "1.1.1.1"],
            "p_enrichment": {
                "greynoise_riot_advanced": {
                    "p_any_ip_addresses": [
                        {
                            "ip_cidr": "1.1.1.1/32",
                            "provider": {
                                "category": "public_dns",
                                "description": "Cloudflare, Inc. is an American...",
                                "explanation": "Public DNS services are used as...",
                                "name": "Cloudflare Public DNS",
                                "precedence": 0,
                                "trust_level": "1",
                            },
                            "scan_time": "2023-04-28 21:11:03.820349735",
                        },
                    ],
                },
                "ipinfo_asn": {
                    "p_any_ip_addresses": [
                        {
                            "asn": "AS27725",
                            "domain": "etecsa.cu",
                            "name": "Empresa de Telecomunicaciones de Cuba, S.A.",
                            "route": "152.206.0.0/17",
                            "type": "isp",
                        },
                        {
                            "asn": "AS13335",
                            "domain": "cloudflare.com",
                            "name": "Cloudflare, Inc.",
                            "route": "1.1.1.0/24",
                            "type": "hosting",
                        },
                    ],
                },
                "ipinfo_location": {
                    "p_any_ip_addresses": [
                        {
                            "city": "Matanzas",
                            "country": "CU",
                            "lat": "23.04111",
                            "lng": "-81.5775",
                            "postal_code": "",
                            "region": "Matanzas Province",
                            "region_code": "04",
                            "timezone": "America/Havana",
                        },
                        {
                            "city": "Los Angeles",
                            "country": "US",
                            "lat": "34.0522",
                            "lng": "-118.2437",
                            "postal_code": "90076",
                            "region": "California",
                            "region_code": "CA",
                            "timezone": "America/Los_Angeles",
                        },
                    ],
                },
                "ipinfo_privacy": {
                    "p_any_ip_addresses": [
                        {"hosting": True, "proxy": False, "relay": False, "service": "", "tor": False, "vpn": False},
                    ],
                },
            },
            "p_log_type": "Crowdstrike.FDREvent",
            "timestamp": "2023-04-28 18:49:38.681",
        },
    ),
    RuleTest(
        name="Google DNS",
        expected_result=False,
        log={
            "p_any_ip_addresses": ["8.8.8.8"],
            "p_enrichment": {
                "ipinfo_location": {
                    "p_any_ip_addresses": [
                        {
                            "city": "Mountain View",
                            "country": "US",
                            "lat": "37.4056",
                            "lng": "-122.0775",
                            "postal_code": "94043",
                            "region": "California",
                            "region_code": "CA",
                            "timezone": "America/Los_Angeles",
                        },
                    ],
                },
            },
            "p_log_type": "Crowdstrike.FDREvent",
        },
    ),
]


@panther_managed
class ConnectiontoEmbargoedCountry(Rule):
    default_description = "Detection to alert when internal asset is communicating with an sanctioned destination. This detection leverages Panther UDM and IPInfo enrichment."
    default_reference = "U.S. Sanctioned Destinations - https://www.bis.doc.gov/index.php/policy-guidance/country-guidance/sanctioned-destinations"
    display_name = "Connection to Embargoed Country"
    log_types = [LogType.CROWDSTRIKE_FDR_EVENT]
    id = "Connection.to.Embargoed.Country-prototype"
    default_severity = Severity.LOW
    tests = connectionto_embargoed_country_tests
    # U.S. Gov Sanctioned Destinations
    # Cuba
    # Iran
    # DPRK
    # Syria
    EMBARGO_COUNTRY_CODES = {"CU", "IR", "KP", "SY"}

    def get_enrichment_obj(self, event):
        return event.deep_get("p_enrichment", "ipinfo_location", "p_any_ip_addresses", default=None)

    def rule(self, event):
        enrichment_obj = self.get_enrichment_obj(event)
        # enrichment_object returns a list.
        # Iterate over list and check if the "country" value matches the country codes.
        if enrichment_obj:
            for i in enrichment_obj:
                if i.get("country") in self.EMBARGO_COUNTRY_CODES:
                    return True
        return False

    def title(self, event):
        enrichment_obj = self.get_enrichment_obj(event)
        country_codes = set(i.get("country") for i in enrichment_obj if i.get("country") in self.EMBARGO_COUNTRY_CODES)
        return f"Connection made to embargoed country: [{country_codes}]."

    def alert_context(self, event):
        if event.get("p_log_type") == "Crowdstrike.FDREvent":
            return crowdstrike_network_detection_alert_context(event) | {
                "p_any_ip_addresses": event.get("p_any_ip_addresses"),
            }
        return {"p_any_ip_addresses": event.get("p_any_ip_addresses")}
