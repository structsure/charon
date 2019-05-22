class Schema(object):
    _all_schemas = {}

    @property
    def all_schemas(self):
        return type(self)._all_schemas

    @all_schemas.setter
    def all_schemas(self, val):
        type(self)._all_schemas = val


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

sec_string = {
    "type": "dict",
    "schema": {
        "value": {"type": "string"},
        "_sec": ascl
    }
}

schema_stub = {
    "users": {
        "name": {"type": "string"}
    },
    "ascl_rule": {
        "name": {"type": "string"},
        "conditions": {
            "type": "list",
            "schema": {
                "type": "dict",
                "schema": {
                    "attrib": {"type": "string"},
                    "value": {"type": "string"}
                }
            }
        }
    },
}


def update_schema(schema_definition):
    sc = Schema()
    sc.all_schemas = schema_stub
    for schema in schema_definition:
        sc.all_schemas[schema] = schema_definition[schema]
        for var in schema_definition[schema].get("vars", {}):
            sc.all_schemas[schema][var] = eval(schema_definition[schema]["vars"][var].strip('/"'))
        sc.all_schemas[schema].pop("vars")
    return sc.all_schemas


def get_schema(schema_name):
    sc = Schema()
    return sc.all_schemas.get(schema_name, {})


def get_security_enabled_fields(schema_name):
    """Get list of fields with ASCL applied from the schema."""
    schema = get_schema(schema_name)
    return parse(schema, [""])


def parse(current, fields):
    """Recursive method to identify ASCL-tagged fields in schema."""
    if type(current) == dict:
        for key, value in current.items():
            if type(value) == dict and value.get('schema') is not None:
                # Check if this schema includes security rules
                if value.get('schema').get('_sec') is not None:
                    fields.append(key)
                # Recurse on any key that has schema fields
                fields = parse(value.get('schema'), fields)
    return fields
