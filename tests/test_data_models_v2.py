from pypanther.data_models_v2 import DataModel, Field, FieldMapping, FieldType


def test_data_model_inheritance():
    test_field_1 = Field(
        name="test1",
        type=FieldType.STRING,
        mappings=[FieldMapping(log_type="Custom.Test", field_path="field.nested1")],
    )
    test_field_2 = Field(
        name="test2",
        type=FieldType.STRING,
        mappings=[FieldMapping(log_type="Custom.Test", field_path="field.nested2")],
    )

    test_field_3 = Field(
        name="test3",
        type=FieldType.STRING,
        mappings=[FieldMapping(log_type="Custom.Test", field_path="field.nested3")],
    )

    class Test(DataModel):
        fields = [test_field_1]

    class Test2(Test):
        pass

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


def test_override():
    class Test(DataModel):
        description = "old description"
        enabled = True
        fields = [
            Field(
                name="test1",
                type=FieldType.STRING,
                mappings=[FieldMapping(log_type="Custom.Test", field_path="field.nested1")],
            ),
        ]

    assert Test.description == "old description"
    assert Test.enabled
    assert Test.fields == [
        Field(
            name="test1",
            type=FieldType.STRING,
            mappings=[FieldMapping(log_type="Custom.Test", field_path="field.nested1")],
        ),
    ]

    Test.override(
        description="new description",
        enabled=False,
        fields=[
            Field(
                name="test2",
                type=FieldType.STRING,
                mappings=[FieldMapping(log_type="Custom.Test", field_path="field.nested2")],
            ),
        ],
    )

    assert Test.description == "new description"
    assert not Test.enabled
    assert Test.fields == [
        Field(
            name="test2",
            type=FieldType.STRING,
            mappings=[FieldMapping(log_type="Custom.Test", field_path="field.nested2")],
        ),
    ]


def test_asdict():
    class Test(DataModel):
        description = "old description"
        enabled = True
        fields = [
            Field(
                name="test1",
                type=FieldType.STRING,
                mappings=[FieldMapping(log_type="Custom.Test", field_path="field.nested1")],
            ),
        ]

    assert Test.asdict() == {
        "description": "old description",
        "enabled": True,
        "fields": [
            {
                "name": "test1",
                "type": FieldType.STRING,
                "mappings": [{"log_type": "Custom.Test", "field_path": "field.nested1"}],
                "description": "",
            },
        ],
    }
