import yaml

from pypanther.lookups import FileLookup, InlineLookup, S3Lookup


class IPInfoLocationLookup(S3Lookup):
    lookup_id = "ipinfo_location"
    schema_id = "IPInfo.LocationCIDR"
    enabled = True
    refresh = S3Lookup.Refresh(
        aws_role_arn="arn:aws:iam::893421435052:role/panther-ipinfo-access-role",
        s3_object_path="s3://panther-ipinfo-ha771dhqm13j11czzb6kcpuy6ueccusw2a-s3alias/luts/data/ipinfo/location.mmdb",
        period_minutes=1440,
    )
    tags = ["IPinfo", "GeoIP"]
    description = (
        "IpInfo Location data is the identification of an IP address' "
        "geographic location in the real world. This dataset is for detection engine. "
        "For the datalake, also enable ipinfo_location_datalake."
    )
    reference = "https://docs.panther.com/enrichment/ipinfo"
    log_type_map = {"PrimaryKey": "cidrblock", "AssociatedLogTypes": []}


class AWSAccountLabelsLookup(InlineLookup):
    lookup_id = "aws_account_labels"
    schema_id = "AWS.AccountLabels"
    enabled = True
    description = "AWS Account Labels"
    reference = "https://docs.panther.com/enrichment/aws_account_labels"
    log_type_map = {"PrimaryKey": "account_id", "AssociatedLogTypes": []}
    tags = ["AWS"]
    data = [
        {"account_id": "123456789012", "account_name": "Acme Corp"},
        {"account_id": "234567890123", "account_name": "Globex Corporation"},
        {"account_id": "345678901234", "account_name": "Soylent Corp"},
        {"account_id": "456789012345", "account_name": "Initech"},
        {"account_id": "567890123456", "account_name": "Umbrella Corporation"},
        {"account_id": "678901234567", "account_name": "Hooli"},
        {"account_id": "789012345678", "account_name": "Stark Industries"},
    ]


class TrailDiscoverLookup(FileLookup):
    lookup_id = "trail_discover"
    schema_id = "TrailDiscover"
    enabled = True
    filename = "./schemas/trail_discover.jsonl"
    tags = ["AWS"]


def test_s3_lookup():
    s3_lookup = IPInfoLocationLookup()

    assert s3_lookup.to_dict() == {
        "analysis_type": "LOOKUP_TABLE",
        "enabled": True,
        "lookup_name": "ipinfo_location",
        "schema": "IPInfo.LocationCIDR",
        "log_type_map": {"PrimaryKey": "cidrblock", "AssociatedLogTypes": []},
        "description": (
            "IpInfo Location data is the identification of an IP address' "
            "geographic location in the real world. This dataset is for detection engine. "
            "For the datalake, also enable ipinfo_location_datalake."
        ),
        "reference": "https://docs.panther.com/enrichment/ipinfo",
        "tags": ["IPinfo", "GeoIP"],
    }


ipinfo_location_schema = yaml.safe_load("""
schema: IPInfo.LocationCIDR
description: IPInfo Location Cidr block data
referenceURL: https://ipinfo.io/developers/data-types#geolocation-data
fields:
    - name: cidrblock
      required: true
      description: CIDR Block
      type: string
      validate:
        cidr: any
    - name: city
      description: City field
      type: string
    - name: country
      description: Country field
      type: string
    - name: lat
      description: Latitude field
      type: string
    - name: lng
      description: Longitude field
      type: string
    - name: postal_code
      description: PostalCode field
      type: string
    - name: region
      description: Region field
      type: string
    - name: region_code
      description: RegionCode field
      type: string
    - name: timezone
      description: TimeZone field
      type: string
    - name: processing_time
      description: Last update time
      type: timestamp
      timeFormats:
        - rfc3339
      isEventTime: true
""")
