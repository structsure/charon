import os
import json
from schema import get_schema, update_schema

X_DOMAIN = "*"
X_HEADERS = ["Access-Control-Allow-Origin", "Access-Control-Allow-Headers"]
X_EXPOSE_HEADERS = ["Access-Control-Allow-Origin", "Access-Control-Allow-Headers"]

MONGO_USERNAME = ""
MONGO_PASSWORD = ""
MONGO_AUTH_SOURCE = "admin"
MONGO_DBNAME = "dbz-mongo-test"
MONGO_HOST = "127.0.0.1"
MONGO_PORT = 27017

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY', "")
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY', "")
AWS_S3_BUCKET_NAME = os.getenv('AWS_S3_BUCKET_NAME', "")
S3_ATTACHMENTS = os.getenv('S3_ATTACHMENTS', True)

RENDERERS = [
    'eve.render.JSONRenderer'
]


def register_schema(schema):
    all_schemas = update_schema(schema)
    for rsc in all_schemas.keys():
        rsc_read = {
            "schema": get_schema(rsc),
            "datasource": {
                "aggregation": {
                    "pipeline": [
                        {"$match": {"_id": "$id"}}
                    ]
                }
            },
            "pagination": False,
            "item_methods": ["GET"]
        }

        rsc_write = {
            "schema": get_schema(rsc),
            "datasource": {
                "source": rsc
            },
            "resource_methods": ["POST"],
            "item_methods": ["PATCH", "DELETE"]  # PUT doesn't have a valid use case at this point
        }
        DOMAIN[rsc] = rsc_read
        DOMAIN['{}_write'.format(rsc)] = rsc_write


SCHEMA = json.loads(os.getenv('TEST_SCHEMA', "{}"))  # Needs a valid default to load before tests set TEST_SCHEMA

DOMAIN = {}
register_schema(SCHEMA)
