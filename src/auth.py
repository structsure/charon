import json

from pymongo import MongoClient
from eve.auth import BasicAuth
from flask import g, abort, current_app
from schema import get_security_enabled_fields


class CharonAuth(BasicAuth):
    def check_auth(self, username, password, allowed_roles, resource, method):
        """Validates user credentials and sets the Flask global security context variables."""
        current_app.logger.info('Checking auth for username %s'.format(username))

        if not self.authenticate_user(username, password):
            abort(403)

        g.user = username

        # Set security context in g.cat and g.diss
        set_context(username)

        return True

    def authenticate_user(self, username, password):
        """Add logic to authenticate user here."""
        return True


def set_context(username):
    current_app.logger.info('Setting security context for user {}'.format(g.user))

    client = MongoClient(current_app.config.get('MONGO_HOST'))
    db = client['admin']
    coll = db['charon_user_permissions']

    try:
        user = coll.find({'username': username})[0]
    except Exception as exc:
        current_app.logger.error('Failed to find user {}: {}'.format(username, exc))
        g._cat = []
        g._diss = []
        return

    g._cat = user.get('cat')
    g._diss = user.get('diss')


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
        current_app.logger.critical('Error checking {} context: {}'.format(resource, exc))
        # We don't know that the user is allowed access, so the request must be aborted
        abort(500)

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
    current_app.logger.info('Checking permission for user {} to {} {} object.'.format(g.user, method,
                                                                                      resource[:-6]))
    current_app.logger.info('Object permissions: {}'.format(g._obj_permissions))

    for i in g._obj_permissions:
        if str(i) not in (g._cat + g._diss):
            current_app.logger.info('Permission denied for user {} to {} {} object.'.format(g.user, method,
                                                                                            resource[:-6]))
            abort(403)
    return
