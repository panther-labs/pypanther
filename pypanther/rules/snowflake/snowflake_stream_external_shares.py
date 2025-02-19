from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed


@panther_managed
class SnowflakeStreamExternalShares(Rule):
    id = "Snowflake.Stream.ExternalShares-prototype"
    display_name = "Snowflake External Data Share"
    log_types = [LogType.SNOWFLAKE_DATA_TRANSFER_HISTORY]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0010:T1537"]}
    default_description = (
        "Detect when an external share has been initiated from one source cloud to another target cloud."
    )
    default_runbook = "Determine if this occurred as a result of a valid business request."
    tags = ["Configuration Required", "Snowflake", "[MITRE] Exfiltration", "[MITRE] Transfer Data to Cloud Account"]
    # CONFIGURATION REQUIRED
    #   Be sure to add code to exclude any transfers from acounts designed to host data shares. Either
    #   add those account names to the set below, or add a rule filter to exclude events with those
    #   account names.
    # Add account names here
    DATA_SHARE_HOSTING_ACCOUNTS = {}

    def rule(self, event):
        return all(
            [
                event.get("ACCOUNT_NAME") not in self.get_data_share_hosting_accounts(),
                event.get("SOURCE_CLOUD"),
                event.get("TARGET_CLOUD"),
                event.get("BYTES_TRANSFERRED", 0) > 0,
            ],
        )

    def title(self, event):
        return f"{event.get('ORGANIZATION_NAME', '<UNKNOWN ORGANIZATION>')}: A data export has been initiated from source cloud {event.get('SOURCE_CLOUD', '<UNKNOWN SOURCE CLOUD>')} in source region {event.get('SOURCE_REGION', '<UNKNOWN SOURCE REGION>')} to target cloud {event.get('TARGET_CLOUD', '<UNKNOWN TARGET CLOUD>')} in target region {event.get('TARGET_REGION', '<UNKNOWN TARGET REGION>')} with transfer type {event.get('TRANSFER_TYPE', '<UNKNOWN TRANSFER TYPE>')} for {event.get('BYTES_TRANSFERRED', '<UNKNOWN VOLUME>')} bytes"

    def get_data_share_hosting_accounts(self):
        """Getter function. Used so we can mock during unit tests."""
        return self.DATA_SHARE_HOSTING_ACCOUNTS

    tests = [
        RuleTest(
            name="Allowed Share",
            expected_result=False,
            mocks=[
                RuleMock(
                    object_name="get_data_share_hosting_accounts",
                    return_value="{DP_EUROPE}, {DP_ASIA}, {DP_AMERICA}",
                ),
            ],
            log={
                "ORGANIZATION_NAME": "DAILY_PLANET",
                "ACCOUNT_NAME": "DP_EUROPE",
                "REGION": "US-EAST-2",
                "SOURCE_CLOUD": "AWS",
                "SOURCE_REGION": "US-EAST-2",
                "TARGET_CLOUD": "AWS",
                "TARGET_REGION": "EU-WEST-1",
                "BYTES_TRANSFERRED": 61235879,
                "TRANSFER_TYPE": "COPY",
            },
        ),
        RuleTest(
            name="Disallowed Share",
            expected_result=True,
            mocks=[
                RuleMock(
                    object_name="get_data_share_hosting_accounts",
                    return_value="{DP_EUROPE}, {DP_ASIA}, {DP_AMERICA}",
                ),
            ],
            log={
                "ORGANIZATION_NAME": "LEXCORP",
                "ACCOUNT_NAME": "LEX_SECRET_ACCOUNT",
                "REGION": "US-EAST-2",
                "SOURCE_CLOUD": "AWS",
                "SOURCE_REGION": "US-EAST-2",
                "TARGET_CLOUD": "AWS",
                "TARGET_REGION": "EU-WEST-1",
                "BYTES_TRANSFERRED": 61235879,
                "TRANSFER_TYPE": "COPY",
            },
        ),
    ]
