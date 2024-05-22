from panther_analysis.base import PantherRule, Severity


class AsanaRule(PantherRule):
    RuleID = "Asana.Base-prototype"
    Enabled = True
    LogTypes = ["Asana.Audit"]
    Severity = Severity.Info

    def alert_context(self, event):
        alert_context = {
            "actor": "<NO_ACTOR>",
            "context": "<NO_CONTEXT>",
            "event_type": "<NO_EVENT_TYPE>",
            "resource_type": "<NO_RESOURCE_TYPE>",
            "resource_name": "<NO_RESOURCE_NAME>",
            "resource_gid": "<NO_RESOURCE_GID>",
        }
        if event.deep_get("actor", "actor_type", default="") == "user":
            alert_context["actor"] = event.deep_get("actor", "email", default="<NO_ACTOR_EMAIL>")
        else:
            alert_context["actor"] = event.deep_get("actor", "actor_type", default="<NO_ACTOR>")
        if "event_type" in event:
            # Events have categories and event_type
            # We have not seen category overlap -> only including event_type
            alert_context["event_type"] = event.get("event_type")
        alert_context["resource_name"] = event.deep_get(
            "resource", "name", default="<NO_RESOURCE_NAME>"
        )
        alert_context["resource_gid"] = event.deep_get(
            "resource", "gid", default="<NO_RESOURCE_GID>"
        )
        res_type = event.deep_get("resource", "resource_type")
        if res_type:
            alert_context["resource_type"] = res_type
        res_subtype = event.deep_get("resource", "resource_subtype")
        if res_type and res_subtype and res_subtype != res_type:
            alert_context["resource_type"] += "__" + res_subtype
        context = event.deep_get("context", "context_type")
        if context:
            alert_context["context"] = context
        return alert_context
