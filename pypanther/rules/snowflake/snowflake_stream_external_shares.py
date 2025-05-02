from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


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
    tags = ["Snowflake", "[MITRE] Exfiltration", "[MITRE] Transfer Data to Cloud Account"]

    def rule(self, event):
        return all([event.get("SOURCE_CLOUD"), event.get("TARGET_CLOUD"), event.get("BYTES_TRANSFERRED", 0) > 0])

    def title(self, event):
        return f"A data export has been initiated from source cloud {event.get('SOURCE_CLOUD', '<UNKNOWN SOURCE CLOUD>')} in source region {event.get('SOURCE_REGION', '<UNKNOWN SOURCE REGION>')} to target cloud {event.get('TARGET_CLOUD', '<UNKNOWN TARGET CLOUD>')} in target region {event.get('TARGET_REGION', '<UNKNOWN TARGET REGION>')} with transfer type {event.get('TRANSFER_TYPE', '<UNKNOWN TRANSFER TYPE>')} for {event.get('BYTES_TRANSFERRED', '<UNKNOWN VOLUME>')} bytes"

    tests = [
        RuleTest(
            name="Zero byte transfer",
            expected_result=False,
            log={
                "REGION": "US-EAST-2",
                "SOURCE_CLOUD": "AWS",
                "SOURCE_REGION": "US-EAST-2",
                "TARGET_CLOUD": "AWS",
                "TARGET_REGION": "EU-WEST-1",
                "BYTES_TRANSFERRED": 0,
                "TRANSFER_TYPE": "COPY",
            },
        ),
        RuleTest(
            name="Disallowed Share",
            expected_result=True,
            log={
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
