def test_pypanther_imports():
    """Ensures things import in the init file can be used directly from pypanther"""
    from pypanther import (
        DataModel,  # noqa: F401
        DataModelMapping,  # noqa: F401
        LogType,  # noqa: F401
        Rule,  # noqa: F401
        RuleMock,  # noqa: F401
        RuleTest,  # noqa: F401
        Severity,  # noqa: F401
        get_panther_rules,  # noqa: F401
        get_rules,  # noqa: F401
        register,  # noqa: F401
        registered_rules,  # noqa: F401
    )
