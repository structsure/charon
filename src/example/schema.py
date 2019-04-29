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

all_schemas = {
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
    "fees": {
        "FeeID": {"type": "string"},
        "BuildingID": {"type": "string"},
        "BoroID": {"type": "string"},
        "Boro": {"type": "string"},
        "HouseNumber": {"type": "string"},
        "StreetName": {"type": "string"},
        "Zip": {"type": "string"},
        "Block": {"type": "string"},
        "Lot": {"type": "string"},
        "LifeCycle": {"type": "string"},
        "FeeTypeID": {"type": "string"},
        "FeeType": {"type": "string"},
        "FeeSourceTypeID": {"type": "string"},
        "FeeSourceType": {"type": "string"},
        "FeeSourceID": {"type": "string"},
        "FeeIssuedDate": {"type": "string"},
        "FeeAmount": {"type": "string"},
        "DoFAccountType": {"type": "string"},
        "DoFTransferDate": {"type": "string"},
        "attachments": attachment,
        "_sec": ascl
    },
    "fees_nested": {
        "FeeID": sec_string,
        "BuildingID": {"type": "string"},
        "BoroID": {"type": "string"},
        "Boro": {"type": "string"},
        "HouseNumber": {"type": "string"},
        "StreetName": {"type": "string"},
        "Zip": {"type": "string"},
        "Block": {"type": "string"},
        "Lot": {"type": "string"},
        "LifeCycle": {"type": "string"},
        "FeeTypeID": {"type": "string"},
        "FeeType": {"type": "string"},
        "FeeSourceTypeID": {"type": "string"},
        "FeeSourceType": {"type": "string"},
        "FeeSourceID": {"type": "string"},
        "FeeIssuedDate": {"type": "string"},
        "FeeAmount": {"type": "string"},
        "DoFAccountType": {"type": "string"},
        "DoFTransferDate": {"type": "string"},
        "_sec": ascl
    },
}


def get_schema(schema_name):
    # TO DO - get schemas from Mongo
    return all_schemas.get(schema_name, {})
