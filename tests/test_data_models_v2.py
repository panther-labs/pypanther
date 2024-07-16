from pypanther.data_models_v2 import DataModel, Field, FieldType, FieldMapping


def test_data_model_inheritance():
    test_field_1 = Field(
        name="test1",
        field_type=FieldType.STRING,
        mappings=[
            FieldMapping(log_type="Custom.Test", field_path="field.nested1")
        ]
    )
    test_field_2 = Field(
        name="test2",
        field_type=FieldType.STRING,
        mappings=[
            FieldMapping(log_type="Custom.Test", field_path="field.nested2")
        ]
    )

    test_field_3 = Field(
        name="test3",
        field_type=FieldType.STRING,
        mappings=[
            FieldMapping(log_type="Custom.Test", field_path="field.nested3")
        ]
    )

    class Test(DataModel):
        data_model_id = "test"
        fields = [test_field_1]

    class Test2(Test):
        data_model_id = "test2"

    # values are inherited as copies
    assert Test2.fields == [test_field_1]
    assert Test.fields == [test_field_1]
    assert Test.fields is not Test2.fields

    # updates do not affect the parent or children
    Test2.fields.append(test_field_2)
    assert Test2.fields == [test_field_1, test_field_2]
    assert Test.fields == [test_field_1]
    Test.fields.append(test_field_3)
    assert Test2.fields == [test_field_1, test_field_2]
    assert Test.fields == [test_field_1, test_field_3]
