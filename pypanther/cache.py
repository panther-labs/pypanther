from pypanther.base import DataModel
from pypanther.get import get_panther_data_models


class DataModelCache:
    def __init__(self):
        self.data_models = {}

        for data_model in get_panther_data_models():
            for log_type in data_model.log_types:
                self.data_models[log_type] = data_model()

    def data_model_of_logtype(self, log_type: str) -> DataModel:
        return self.data_models.get(log_type)


__data_model_cache = None


def data_model_cache():
    global __data_model_cache
    if __data_model_cache is None:
        __data_model_cache = DataModelCache()
    return __data_model_cache
