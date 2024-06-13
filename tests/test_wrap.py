from pypanther.wrap import exclude, include


def test_exclude():
    class TestRule:
        def rule(self, event):
            return True

    @exclude(lambda event: event["foo"] == "bar")
    class FilteredRule(TestRule):
        pass

    assert not FilteredRule().rule({"foo": "bar"})
    assert FilteredRule().rule({"foo": "baz"})


def test_include():
    class TestRule:
        def rule(self, event):
            return True

    @include(lambda event: event["foo"] == "bar")
    class FilteredRule(TestRule):
        pass

    assert FilteredRule().rule({"foo": "bar"})
    assert not FilteredRule().rule({"foo": "baz"})
