from flask import g, current_app
from schema import get_security_enabled_fields


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


def add_ascl_redaction(endpoint, pipeline):
    """
    Adds a redaction step to the aggregation pipeline for each security enabled field.
    """
    current_app.logger.debug('Setting up redaction pipeline for {}'.format(endpoint))

    pipeline = handle_id_match_wildcard(pipeline)
    sec_fields = get_security_enabled_fields(endpoint)
    for field in sec_fields:
        pipeline = redact_field(field, pipeline)

    # Redact removes any item that contains "false" in cat_matches or diss_matches (including nested items)
    pipeline.append(redact_logical_AND("$cat_matches"))
    pipeline.append(redact_logical_AND("$diss_matches"))

    metadata_fields = []

    for field in sec_fields:
        # Add `.` as field separator for securitized fields. Don't add for object-level security label.
        if field != '':
            field = '{}.'.format(field)
        metadata_fields.append("{}cat_matches".format(field))
        metadata_fields.append("{}diss_matches".format(field))
    pipeline.append(remove_metadata_fields(metadata_fields))

    current_app.logger.debug('Pipeline: {}'.format(pipeline))


def redact_field(path, pipeline):
    """
        Adds a redaction step to the aggregation pipeline for a given security enabled field (fields that contain
        the _sec label).
    """
    if path != "" and path is not None:
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
    Note - field argument must start with `$` (e.g. ""$dist_matches"")
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


def remove_metadata_fields(fields):
    """ Strip out fields added during aggregation. """
    stage = {"$project": {}}
    for field in fields:
        stage['$project'][field] = 0
    return stage
