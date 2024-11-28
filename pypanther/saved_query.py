import abc

from pydantic import NonNegativeInt


class SavedQuery(metaclass=abc.ABCMeta):
    id: str
    schedule: NonNegativeInt
    timeout: NonNegativeInt = 60

    @abc.abstractmethod
    def query(self) -> list[dict]:
        raise NotImplementedError("You must implement the query method in your scheduled rule class.")
