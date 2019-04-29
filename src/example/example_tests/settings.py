import os

from schema import get_schema
from auth import AssignSecAuth

MONGO_HOST = os.environ['MONGO_HOST']
MONGO_PORT = 27017

X_DOMAIN = "*"
X_HEADERS = ["Access-Control-Allow-Origin", "Access-Control-Allow-Headers"]
X_EXPOSE_HEADERS = ["Access-Control-Allow-Origin", "Access-Control-Allow-Headers"]

MONGO_USERNAME = ""
MONGO_PASSWORD = ""
MONGO_AUTH_SOURCE = "admin"
MONGO_DBNAME = "dbz-mongo-test"
MONGO_HOST = "127.0.0.1"

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY', "")
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY', "")
AWS_S3_BUCKET_NAME = os.getenv('AWS_S3_BUCKET_NAME', "")
S3_ATTACHMENTS = os.getenv('S3_ATTACHMENTS', False)

public_methods = ["GET", "POST", "DELETE"]
ITEM_METHODS = ["GET", "PATCH", "PUT", "DELETE"]

RENDERERS = [
    'eve.render.JSONRenderer'
]

users = {
    "schema": get_schema('users_schema'),
    "authentication": AssignSecAuth
}

def register_resources(rscs):
    if rscs == []:
        raise Exception('Please define resources in settings.py')
    else:
        for rsc in rscs:
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
                "public_methods": ["GET"],
                "item_methods": ["GET"]
            }

            rsc_write = {
                "schema": get_schema(rsc),
                "datasource": {
                    "source": rsc
                },
                "public_methods": ["POST"],
                "resource_methods": ["POST"],
                "item_methods": ["PATCH"]  # PUT and DELETE don't have valid use cases at this point
            }

            DOMAIN[rsc] = rsc_read
            DOMAIN['{}_write'.format(rsc)] = rsc_write


DOMAIN = {}
rscs = []
register_resources(rscs)
