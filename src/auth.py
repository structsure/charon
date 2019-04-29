import json

from pymongo import MongoClient
from eve.auth import BasicAuth
from flask import g, abort, current_app
from aggregators import get_security_enabled_fields


class AssignSecAuth(BasicAuth):
    def check_auth(self, username, allowed_roles, resource, method, tag=None, password=None,):
        current_app.logger.info('Checking auth for username %s'.format(username))
        print('Auth: ')
        print('\tusername: {}'.format(username + g.user))
        print('\ttag: {}'.format(tag))
        return True


def assign_auth(resource, request, lookup=None):
    auth = request.headers.get("Authorization", [])
    rem = "Basic "
    if rem in auth:
        g.user = auth.replace(rem, '')
        print("Here's our user: [{}]".format(g.user))
    else:
        g.user = None


def set_context(resource, request, lookup=None):
    """
        STAND IN FOR TESTING ONLY
    """
    current_app.logger.info('Setting security context for user {}'.format(g.user))

    users = [
        # US Citizen
        {
            "username": "us_unclassified_only",
            "cat": ["usg_unclassified"],
            "diss": ["usg_noforn", "usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "us_confidential_only",
            "cat": ["usg_confidential"],
            "diss": ["usg_noforn", "usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "us_secret_cumul",
            "cat": ["usg_unclassified", "usg_confidential", "usg_secret"],
            "diss": ["usg_noforn", "usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "us_topsecret_cumul",
            "cat": ["usg_unclassified", "usg_confidential", "usg_secret", "usg_topsecret"],
            "diss": ["usg_noforn", "usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "us_topsecret_only",
            "cat": ["usg_topsecret"],
            "diss": ["usg_noforn", "usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "us_secret_only",
            "cat": ["usg_secret"],
            "diss": ["usg_noforn", "usg_relfvey", "usg_relgbr"]
        },
        # CAN citizen (or NZL, or AUS)
        {
            "username": "can_unclassified",
            "cat": ["usg_unclassified"],
            "diss": ["usg_relfvey"]
        },
        {
            "username": "can_confidential_only",
            "cat": ["usg_confidential"],
            "diss": ["usg_relfvey"]
        },
        {
            "username": "can_secret_cumul",
            "cat": ["usg_unclassified", "usg_confidential", "usg_secret"],
            "diss": ["usg_relfvey"]
        },
        {
            "username": "can_topsecret_cumul",
            "cat": ["usg_unclassified", "usg_confidential", "usg_secret", "usg_topsecret"],
            "diss": ["usg_relfvey"]
        },
        {
            "username": "can_topsecret_only",
            "cat": ["usg_topsecret"],
            "diss": ["usg_relfvey"]
        },
        {
            "username": "can_secret_only",
            "cat": ["usg_secret"],
            "diss": ["usg_relfvey"]
        },
        # GBR citizen
        {
            "username": "gbr_unclassified",
            "cat": ["usg_unclassified"],
            "diss": ["usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "gbr_confidential_only",
            "cat": ["usg_confidential"],
            "diss": ["usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "gbr_secret_cumul",
            "cat": ["usg_unclassified", "usg_confidential", "usg_secret"],
            "diss": ["usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "gbr_topsecret_cumul",
            "cat": ["usg_unclassified", "usg_confidential", "usg_secret", "usg_topsecret"],
            "diss": ["usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "gbr_topsecret_only",
            "cat": ["usg_topsecret"],
            "diss": ["usg_relfvey", "usg_relgbr"]
        },
        {
            "username": "gbr_secret_only",
            "cat": ["usg_secret"],
            "diss": ["usg_relfvey", "usg_relgbr"]
        }
    ]
    user_obj = {}
    if g.user:
        for user in users:
            if user.get('username') == g.user:
                user_obj = user
                print('Found user.\n\n')
    else:
        current_app.logger.critical('Using default user context - not suitable for production.')
        default_user = {
            "username": "default_for_testing",
            "cat": ["usg_unclassified"],
            "diss": []
        }
        user_obj = default_user

    g.username = user_obj.get('username')
    g._cat = user_obj.get('cat', [])
    g._diss = user_obj.get('diss', [])
    # /temporary


def user_match(user_ctx, new_field_name):
    stage = {
        "$addFields": {
            new_field_name: {
                "$map": {
                    "input": ["$conditions"],
                    "as": "cond",
                    "in": {
                        "$cond": {
                            "if": {
                                "$gt": [
                                    {
                                        "$size":
                                            {"$setIntersection": [
                                                "$$cond",
                                                user_ctx
                                            ]}
                                    },
                                    0
                                ]
                            },
                            "then": "true",
                            "else": "false"
                        }
                    }
                }
            }
        }
    }
    return stage


def redact_unmatched_rules(field_name):
    """If ANY of the conditions for a given rule were met, the user matches a rule - Logical OR."""
    field = '${}'.format(field_name)
    stage = {
        "$redact": {
            "$cond": {
                "if": {
                    "$setIsSubset": [
                        ["true"],
                        {
                            "$ifNull": [field, ["true"]]  # If field is not set, don't redact
                        }
                    ]
                },
                "then": "$$DESCEND",
                "else": "$$PRUNE"
            }
        }
    }
    return stage


def group_match_fields(fields):
    stage = {
        "$addFields": {
            "__rule_match": {
                "$concatArrays": fields
            }
        }
    }
    return stage


def get_user_ascl_rules(user_ctx):
    """Returns a list of named rules in the Mongo ascl_rule collection"""
    # client = MongoClient(db=db, username=username, password=password, authSource=authSource)

    client = MongoClient(current_app.config.get('MONGO_HOST'))
    db = client[current_app.config.get('MONGO_DBNAME')]
    coll = db['ascl_rule']

    try:
        pipeline = []
        pipeline.append(user_match(user_ctx, "__match_field"))
        pipeline.append(redact_unmatched_rules("__match_field"))

        pipeline.append({"$project": {"name": 1}})

        # Do the aggregation
        matched_rules = list(coll.aggregate(pipeline))
    # TO DO - what exceptions do we expect here?
    except Exception as exc:
        current_app.logger.error('Failed to get user permissions: %s'.format(exc))
        return []

    rule_names = []
    for rule in matched_rules:
        rule_names.append(rule.get('name'))

    return rule_names


def check_insert_data_context(resource, request, lookup=None):
    cat = []
    diss = []
    sec_enabled = get_security_enabled_fields(resource[:-6])
    try:
        # assign incoming object ascl to sec_obj
        req_data = json.loads(request.data)

        sec_obj = req_data.get('_sec', {})
        cat = add_cat(cat, sec_obj.get('cat'))
        diss = add_diss(diss, sec_obj.get('diss'))

        for i in sec_enabled:
            if i != '':
                field_obj = req_data.get(i, {}).get('_sec', {})
                cat = add_cat(cat, field_obj.get('cat'))
                diss = add_diss(diss, field_obj.get('diss'))

        current_app.logger.debug('Object security categories required: {}'.format(cat))
        current_app.logger.debug('Object dissemination rules required: {}'.format(diss))
    except Exception as exc:
        current_app.logger.error('Error checking {} context: {}'.format(resource, exc))

    g._obj_permissions = []
    g._obj_permissions.extend(cat)
    g._obj_permissions.extend(diss)


def add_cat(cat, val):
    if val is not None:
        cat.append(val)
    return cat


def add_diss(diss, val):
    if val is not None:
        diss.extend(val)
    return diss


def check_insert_access(resource, request, lookup=None):
    method = 'insert' if request.method == 'POST' else 'patch'
    current_app.logger.info('Checking permission for user {} to {} {} object.'.format(g.username, method,
                                                                                      resource[:-6]))
    current_app.logger.info('Object permissions: {}'.format(g._obj_permissions))

    for i in g._obj_permissions:
        if str(i) not in (g._cat + g._diss):
            current_app.logger.info('Permission denied for user {} to {} {} object.'.format(g.username, method,
                                                                                            resource[:-6]))
            abort(403)
    return
