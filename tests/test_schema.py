from ..pypanther.schema import Schema


def test_use_schema():
    class CustomSchema(Schema):
        Tags = ["test"]
        LogTypes = [""]
        RuleID = "test_register_duplicate"


