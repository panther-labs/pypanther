from typing import Any, Callable


def exclude(func: Callable[[Any], bool]):
    """Add a filter to exclude events from a rule. If func returns True, the event is excluded. Otherwise the rule is applied."""

    def cls_wrapper(cls):
        _rule = cls.rule

        def wrapper(self, event):
            if func(event):
                return False
            return _rule(self, event)

        cls.rule = wrapper
        return cls

    return cls_wrapper


def include(func: Callable[[Any], bool]):
    """Add a filter to include events for a rule. If func returns False, the event is excluded. Otherwise the rule is applied."""

    def cls_wrapper(cls):
        _rule = cls.rule

        def wrapper(self, event):
            if not func(event):
                return False
            return _rule(self, event)

        cls.rule = wrapper
        return cls

    return cls_wrapper
