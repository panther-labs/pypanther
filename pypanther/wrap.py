def add_filter(func):
    def cls_wrapper(cls):
        _rule = cls.rule

        def wrapper(self, event):
            if func(event):
                return False
            return _rule(self, event)

        cls.rule = wrapper
        return cls

    return cls_wrapper
