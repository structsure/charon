import json
from pymongo import MongoClient
from bson import ObjectId
from aggregators import get_security_enabled_fields, redact_field
from flask import g, current_app, abort


def check_perms_for_patch(resource, request, lookup):
    """
    Checks the object in the database to ensure that the user has permission to modify the existing data.
    Does not check user's permissions for new data - use pre-insert methods to check new data.
    """
    rsc = resource[:-6]  # take off "_write" from the end of the string
    current_app.logger.info('Checking permissions for user {} to update {} object.'.format(g.username, rsc))
    oid = request.url.split('{}/'.format(resource))[1]

    updates = json.loads(request.data)

    pipeline = []
    pipeline.append({"$match": {"_id": ObjectId(oid=oid)}})
    pipeline = redact_field('', pipeline)  # Security at the top level
    sec_enabled_fields = get_security_enabled_fields(rsc)
    for key in updates.keys():
        if key in sec_enabled_fields:
            pipeline = redact_field(key, pipeline)

    # Get object from DB, confirm user has permissions to update the fields in the PATCH
    coll = MongoClient(current_app.config.get('MONGO_HOST'), 27017)[current_app.config.get('MONGO_DBNAME')][rsc]

    agg_result = list(coll.aggregate(pipeline))
    if len(agg_result) > 0:
        agg_result = agg_result[0]
    else:
        agg_result = {}

    # Check document level
    if "false" in agg_result.get('cat_matches') or "false" in agg_result.get('diss_matches'):
        current_app.logger.info('User {} has insufficient permissions to modify data in the {} object'.format(
            g.username, rsc))
        abort(403)

    # Check field level for all requested fields
    for key in updates.keys():
        val = agg_result.get(key)
        if type(val) == dict:
            if "false" in val.get('cat_matches', []):
                current_app.logger.info('User {} has insufficient permissions to modify data in the {} object'.format(
                    g.username, rsc))
                abort(403)
            if "false" in val.get('diss_matches', []):
                current_app.logger.info('User {} has insufficient permissions to modify data in the {} object'.format(
                    g.username, rsc))
                abort(403)
    current_app.logger.info('User {} has sufficient permissions to modify data in the {} object.'.format(
        g.username, rsc))
