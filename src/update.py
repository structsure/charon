import json
from pymongo import MongoClient
from bson import ObjectId
from aggregators import redact_field
from flask import g, current_app, abort
from schema import get_security_enabled_fields


def check_perms_in_db(resource, request, lookup):
    """
    Checks the object in the database to ensure that the user has permission to modify the existing data.
    Does not check user's permissions for new data - use pre-insert methods to check new data.
    """
    rsc = resource[:-6]  # take off "_write" from the end of the string
    current_app.logger.info('Checking permissions for user {} to update {} object.'.format(g.user, rsc))
    oid = request.url.split('{}/'.format(resource))[1]

    sec_enabled_fields = get_security_enabled_fields(rsc)

    # Build pipeline to return whether user has permission to modify security-enabled fields
    pipeline, updates = make_perm_check_pipeline(oid, sec_enabled_fields, request)

    # Run the aggregation pipeline
    agg_result = perform_perm_check_aggregation(rsc, pipeline)

    # Check document level permissions
    if "false" in agg_result.get('cat_matches') or "false" in agg_result.get('diss_matches'):
        current_app.logger.info('User {} has insufficient permissions to modify data in the {} object'.format(
            g.user, rsc))
        abort(403)

    # Check user permissions at the field level for all security enabled fields being updated.
    fields_to_check = []
    if request.method == 'PATCH':
        fields_to_check = updates.keys()
    elif request.method == 'DELETE':
        fields_to_check = sec_enabled_fields

    for key in fields_to_check:
        abort_request_if_insufficient_perms(key, agg_result, rsc)

    current_app.logger.debug('User {} has sufficient permissions to modify data in the {} object.'.format(
        g.user, rsc))


def make_perm_check_pipeline(oid, sec_enabled_fields, request):
    pipeline = []
    pipeline.append({"$match": {"_id": ObjectId(oid=oid)}})
    pipeline = redact_field('', pipeline)  # Security at the top level

    # Add pipeline stage to evaluate whether data in database is allowed based on user context
    if request.method == 'PATCH':
        # Only consider security-enabled fields being updated by this request
        updates = json.loads(request.data)
        for key in updates.keys():
            if key in sec_enabled_fields:
                pipeline = redact_field(key, pipeline)
    elif request.method == 'DELETE':
        # Consider all security-enabled fields (DELETE affects the entire object)
        updates = None
        for key in sec_enabled_fields:
            pipeline = redact_field(key, pipeline)

    return pipeline, updates


def perform_perm_check_aggregation(rsc, pipeline):
    # Get object from DB, confirm user has permissions to update the fields in the PATCH
    coll = MongoClient(current_app.config.get('MONGO_HOST'), 27017)[current_app.config.get('MONGO_DBNAME')][rsc]

    agg_result = list(coll.aggregate(pipeline))
    if len(agg_result) > 0:
        agg_result = agg_result[0]
    else:
        agg_result = {}
    return agg_result


def abort_request_if_insufficient_perms(key, agg_result, rsc):
    val = agg_result.get(key)
    if type(val) == dict:
        if "false" in val.get('cat_matches', []):
            current_app.logger.info('User {} has insufficient permissions to modify data in the {} object'.format(
                g.user, rsc))
            abort(403)
        if "false" in val.get('diss_matches', []):
            current_app.logger.info('User {} has insufficient permissions to modify data in the {} object'.format(
                g.user, rsc))
            abort(403)
