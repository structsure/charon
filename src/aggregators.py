from flask import g, current_app
from schema import get_schema


def handle_id_match_wildcard(pipeline):
    """
    If the ID match field in the pipeline is passed "*", or not set, treat it as a wildcard for ID match.
    TO DO - Eve is supposed to do this if the variable in the aggregation request == {} - why doesn't it?
    """
    for stage in pipeline:
        if stage.get('$match') is not None:
            for key, value in stage.get('$match', {}).items():
                if key == '_id' and (value == "*" or value == '$id'):  # '$id' is the value when the url query is blank
                    stage['$match'][key] = {"$exists": "true"}
    return pipeline


def before_agg(endpoint, pipeline):
    current_app.logger.debug('Setting up redaction pipeline for {}'.format(endpoint))
    if endpoint == 'fees_nested' or endpoint == 'fees':
        pipeline = handle_id_match_wildcard(pipeline)
        sec_fields = get_security_enabled_fields(endpoint)

        for field in sec_fields:
            pipeline = redact_field(field, pipeline)

        # Redact removes any item that contains "false" in cat_matches or diss_matches (including nested items)
        pipeline.append(redact_logical_AND("$cat_matches"))
        pipeline.append(redact_logical_AND("$diss_matches"))

        metadata_fields = []
        metadata_fields.append("cat_matches")
        metadata_fields.append("diss_matches")
        pipeline.append(remove_metadata_fields(metadata_fields))
    elif endpoint == 'signature':
        pipeline = handle_id_match_wildcard(pipeline)

    current_app.logger.debug('Pipeline: {}'.format(pipeline))


def get_security_enabled_fields(schema_name):
    schema = get_schema(schema_name)
    return parse(schema, [""])


def parse(current, fields):
    if type(current) == dict:
        for key, value in current.items():
            if type(value) == dict and value.get('schema') is not None:
                # Check if this schema includes security rules
                if value.get('schema').get('_sec') is not None:
                    print('adding field: {}'.format(key))
                    fields.append(key)
                # Recurse on any key that has schema fields
                fields = parse(value.get('schema'), fields)
    return fields


def redact_field(path, pipeline):
    """
        Register a field as security-labelled with the _sec tag. Path should be in the format TopField.SubField
        The first field should be at the top level of the schema, and the final field should contain the _sec tag.
    """
    if path is None:
        path = ""
    if path is not "":
        path = '{}.'.format(path)
    pipeline.append(add_match_field_non_array("{}cat_matches".format(path), "${}_sec.cat".format(path), "_cat"))
    pipeline.append(add_match_field("{}diss_matches".format(path), "${}_sec.diss".format(path), "_diss"))
    return pipeline


def add_match_field_non_array(new_field_name, rule_field_name, user_context_attrib):
    """
        Given a set of rules a user passes, checks a specified field with a list of rules and adds a new field
        with a boolean value representing whether all rules in the database field are present in the list of
        rules the user satisfies.

        NOTE - this is for a field in the DB that is an array (e.g. _sec.diss)

        new_field_name      - the field that will be added to the document to display which rules are satisfied
                            - e.g. "dist_matches"
        rule_field_name     - the field that contains the list of rules
                            - e.g. "$__ascl._diss.DISTRIBUTION"
        user_context_attrib - the attribute of user context to be checked against the list of rules in rule_field_name
                            - e.g. "_cat"
    """
    user_perms = getattr(g, user_context_attrib, [])
    stage = {
        "$addFields": {
            new_field_name: {
                "$map": {
                    "input": [[rule_field_name]],
                    "as": "rule",
                    "in": {
                        "$cond": {
                            "if": {
                                # Required permissions must all be in user's permission list
                                "$setIsSubset": [
                                    {"$ifNull": ["$$rule", []]},
                                    user_perms
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


def add_match_field(new_field_name, rule_field_name, user_context_attrib):
    """
        Given a set of rules a user passes, checks a specified field with a list of rules and adds a new field
        with a boolean value representing whether all rules in the database field are present in the list of
        rules the user satisfies.

        NOTE - this is for a field in the DB that is *not* an array (e.g. _sec.cat)

        new_field_name      - the field that will be added to the document to display which rules are satisfied
                            - e.g. "dist_matches"
        rule_field_name     - the field that contains the list of rules
                            - e.g. "$__ascl._diss.DISTRIBUTION"
        user_context_attrib - the attribute of user context to be checked against the list of rules in rule_field_name
                            - e.g. "_diss"
    """
    user_perms = getattr(g, user_context_attrib, [])
    stage = {
        "$addFields": {
            new_field_name: {
                "$map": {
                    "input": [rule_field_name],
                    "as": "rule",
                    "in": {
                        "$cond": {
                            "if": {
                                # Required permissions must all be in user's permission list
                                "$setIsSubset": [
                                    {"$ifNull": ["$$rule", []]},
                                    user_perms
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


def redact_logical_AND(field):
    """
    If all rules were satisfied, keep this element. Else, redact.
    Note - field must be prefixed with `$` (e.g. ""$dist_matches"")
    """
    stage = {
        "$redact": {
            "$cond": {
                "if": {
                    "$setIsSubset": [
                        ["false"],
                        {
                            "$ifNull": [field, ["true"]]  # if field is not set, don't redact
                        }
                    ]
                },
                "then": "$$PRUNE",
                "else": "$$DESCEND"
            }
        }
    }
    return stage


def redact_logical_OR(field):
    """
    If at least one ascl rule was satisfied, keep this element. Else, redact.
    Note - field must be prefixed with `$` (e.g. ""$dist_matches"")
    """
    stage = {
        "$redact": {
            "$cond": {
                "if": {
                    "$setIsSubset": [
                        ["true"],
                        {
                            "$ifNull": [field, ["true"]]  # if field is not set, don't redact
                        }
                    ]
                },
                "then": "$$DESCEND",
                "else": "$$PRUNE"
            }
        }
    }
    return stage


def remove_metadata_fields(fields):
    """ Strip out fields added during aggregation. """
    print('fields to remove: {}'.format(fields))
    stage = {"$project": {}}
    for field in fields:
        stage['$project'][field] = 0
    return stage
