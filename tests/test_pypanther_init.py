def test_pypanther_imports():
    """Ensures things import in the init file can be used directly from pypanther"""
    from pypanther import DataModel  # noqa: F401
    from pypanther import DataModelMapping  # noqa: F401
    from pypanther import LogType  # noqa: F401
    from pypanther import Rule  # noqa: F401
    from pypanther import RuleMock  # noqa: F401
    from pypanther import RuleTest  # noqa: F401
    from pypanther import Severity  # noqa: F401
    from pypanther import get_panther_rules  # noqa: F401
    from pypanther import get_rules  # noqa: F401
    from pypanther import register  # noqa: F401
    from pypanther import registered_rules  # noqa: F401
