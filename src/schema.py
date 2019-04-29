import os
import json

ascl = {
    "type": "dict",
    "schema": {
        "cat": {"type": "string"},
        "diss": {
            "type": "list",
            "schema": {"type": "string"}
        }
    }
}

attachment = {
    "type": "dict",
    "schema": {
        "_sec": ascl,
        "documents": {"type": "list"}
    }
}


def get_schema(schema_name):
    schema = json.loads(os.environ['SCHEMA'])
    return schema.get(schema_name, {})
