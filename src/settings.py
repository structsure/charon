import os
import json
from schema import get_schema, update_schema

MONGO_HOST = os.environ['MONGO_HOST']
MONGO_PORT = os.getenv('MONGO_PORT', 27017)

X_DOMAIN = "*"
X_HEADERS = ["Access-Control-Allow-Origin", "Access-Control-Allow-Headers"]
X_EXPOSE_HEADERS = ["Access-Control-Allow-Origin", "Access-Control-Allow-Headers"]

MONGO_USERNAME = os.getenv("MONGO_USERNAME", "")
MONGO_PASSWORD = os.getenv("MONGO_PASSWORD", "")
MONGO_AUTH_SOURCE = os.getenv("MONGO_AUTH_SOURCE", "admin")
MONGO_DBNAME = os.environ['MONGO_DBNAME']

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY', "")
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY', "")
AWS_S3_BUCKET_NAME = 'test_bucket'
S3_ATTACHMENTS = os.getenv('S3_ATTACHMENTS', False)

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


SCHEMA = json.loads(os.environ['SCHEMA'])
DOMAIN = {}
register_schema(SCHEMA)
