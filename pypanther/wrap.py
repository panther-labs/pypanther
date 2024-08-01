from typing import Any, Callable, Type

from pypanther.base import Rule


def exclude(func: Callable[[Any], bool]):
    """
    Add a filter to exclude events from a rule. If `func` returns `True`, the `event` is excluded. Otherwise the rule is applied.

    Can be used as a decorator:
    ```
    # ignore events where event.foo == bar
    @exclude(lambda event: event["foo"] == "bar")
    class FilteredRule(TestRule):
        pass
    ```

    Can also be used standalone:
    ```
    # ignore events where event.foo == bar
    exclude(lambda event: event["foo"] == "bar")(FilteredRule)
    ```
    """

    def cls_wrapper(cls: Type[Rule]):
        _rule = cls.rule

        def wrapper(self, event):
            if func(event):
                return False
            return _rule(self, event)

        setattr(cls, "rule", wrapper)  # noqa: B010
        return cls

    return cls_wrapper


def include(func: Callable[[Any], bool]):
    """
    Add a filter to include events for a rule. If `func` returns `False`, the `event` is excluded. Otherwise the rule is applied.

    Can be used as a decorator:
    ```
    # require that event.foo == bar
    @include(lambda event: event["foo"] == "bar")
    class FilteredRule(TestRule):
        pass
    ```

    Can also be used standalone:
    ```
    # require that event.foo == bar
    include(lambda event: event["foo"] == "bar")(FilteredRule)
    ```
    """

    def cls_wrapper(cls: Type[Rule]):
        _rule = cls.rule

        def wrapper(self, event):
            if not func(event):
                return False
            return _rule(self, event)

        setattr(cls, "rule", wrapper)  # noqa: B010
        return cls

    return cls_wrapper
