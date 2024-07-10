from unittest import mock

from pypanther import upload


class TestConfirm:
    def test_confirmed(self) -> None:
        with mock.patch("builtins.input", return_value="y"):
            err = upload.confirm()
            assert err is None

    def test_not_confirmed(self) -> None:
        with mock.patch("builtins.input", return_value="n"):
            err = upload.confirm()
            assert err is not None
