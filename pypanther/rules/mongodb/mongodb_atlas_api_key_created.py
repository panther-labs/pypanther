from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.mongodb import mongodb_alert_context


@panther_managed
class MongoDBAtlasApiKeyCreated(Rule):
    default_description = "A MongoDB Atlas api key's access list was updated"
    display_name = "MongoDB Atlas API Key Created"
    default_severity = Severity.MEDIUM
    default_reference = "https://www.mongodb.com/docs/atlas/configure-api-access/#std-label-about-org-api-keys"
    log_types = [LogType.MONGODB_ORGANIZATION_EVENT]
    id = "MongoDB.Atlas.ApiKeyCreated-prototype"

    def rule(self, event):
        return event.get("eventTypeName", "") == "API_KEY_ACCESS_LIST_ENTRY_ADDED"

    def title(self, event):
        user = event.get("username", "<USER_NOT_FOUND>")
        public_key = event.get("targetPublicKey", "<PUBLIC_KEY_NOT_FOUND>")
        return f"MongoDB Atlas: [{user}] updated the allowed access list for API Key [{public_key}]"

    def alert_context(self, event):
        context = mongodb_alert_context(event)
        links = event.deep_walk("links", "href", return_val="first", default="<LINKS_NOT_FOUND>")
        extra_context = {
            "links": links,
            "event_type_name": event.get("eventTypeName", "<EVENT_TYPE_NOT_FOUND>"),
            "target_public_key": event.get("targetPublicKey", "<PUBLIC_KEY_NOT_FOUND>"),
        }
        context.update(extra_context)
        return context

    tests = [
        RuleTest(
            name="API Key Deleted",
            expected_result=False,
            log={
                "created": "2023-06-14 15:47:15",
                "currentvalue": {},
                "eventtypename": "API_KEY_ACCESS_LIST_ENTRY_DELETED",
                "id": "1234abcd13f2804962409423",
                "isglobaladmin": False,
                "links": [
                    {
                        "href": "https://cloud.mongodb.com/api/atlas/v1.0/orgs/9876xyz123lmnop0/events/1234abcd13f2804962409423",
                        "rel": "self",
                    },
                ],
                "orgid": "9876xyz123lmnop0",
                "p_event_time": "2023-06-14 15:47:15",
                "p_log_type": "MongoDB.OrganizationEvent",
                "p_parse_time": "2023-06-14 15:53:42.415",
                "p_row_id": "5ad9c2df49e19aac98def9e118e236",
                "p_schema_version": 0,
                "p_source_id": "a2e8f928-c6e5-4110-b6f9-1b741176041d",
                "p_source_label": "mongo-test-2",
                "remoteaddress": "1.2.3.4",
                "targetpublickey": "xfvcfwtt",
                "userid": "abcd1234userid988",
                "username": "user@company.com",
                "whitelistentry": "1.2.3.4",
            },
        ),
        RuleTest(
            name="API Key Created",
            expected_result=True,
            log={
                "created": "2023-06-14 15:47:15",
                "currentvalue": {},
                "eventtypename": "API_KEY_ACCESS_LIST_ENTRY_ADDED",
                "id": "1234abcd13f2804962409423",
                "isglobaladmin": False,
                "links": [
                    {
                        "href": "https://cloud.mongodb.com/api/atlas/v1.0/orgs/9876xyz123lmnop0/events/1234abcd13f2804962409423",
                        "rel": "self",
                    },
                ],
                "orgid": "9876xyz123lmnop0",
                "p_event_time": "2023-06-14 15:47:15",
                "p_log_type": "MongoDB.OrganizationEvent",
                "p_parse_time": "2023-06-14 15:53:42.415",
                "p_row_id": "5ad9c2df49e19aac98def9e118e236",
                "p_schema_version": 0,
                "p_source_id": "a2e8f928-c6e5-4110-b6f9-1b741176041d",
                "p_source_label": "mongo-test-2",
                "remoteaddress": "1.2.3.4",
                "targetpublickey": "xfvcfwtt",
                "userid": "abcd1234userid988",
                "username": "user@company.com",
                "whitelistentry": "1.2.3.4",
            },
        ),
    ]
