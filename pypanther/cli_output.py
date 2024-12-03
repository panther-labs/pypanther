class BColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    @classmethod
    def wrap(cls, start: str, text: str) -> str:
        return f"{start}{text}{cls.ENDC}"


def bold(text: str) -> str:
    return BColors.wrap(BColors.BOLD, text)


def header(text: str) -> str:
    return BColors.wrap(BColors.HEADER, text)


def blue(text: str) -> str:
    return BColors.wrap(BColors.OKBLUE, text)


def cyan(text: str) -> str:
    return BColors.wrap(BColors.OKCYAN, text)


def success(text: str) -> str:
    return BColors.wrap(BColors.OKGREEN, text)


def warning(text: str) -> str:
    return BColors.wrap(BColors.WARNING, text)


def underline(text: str) -> str:
    return BColors.wrap(BColors.UNDERLINE, text)


def failed(text: str) -> str:
    return BColors.wrap(BColors.FAIL, text)
