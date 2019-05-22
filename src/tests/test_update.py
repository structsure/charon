import unittest
import json
import os
import pytest
import base64

from eve import Eve
from pymongo import MongoClient
from auth import check_insert_access, check_insert_data_context, CharonAuth
from aggregators import add_ascl_redaction
from update import check_perms_in_db
from s3 import include_s3_data, generate_presigned_urls, include_presigned_urls

MONGO_DBNAME = 'dbz-mongo-test'
MONGO_HOST = '127.0.0.1'

US_CITIZEN_DISS = ['usg_noforn', 'usg_relfvey', 'usg_relgbr']
GBR_CITIZEN_DISS = ['usg_relfvey', 'usg_relgbr']
CAN_CITIZEN_DISS = ['usg_relfvey']


@pytest.fixture(scope='function', autouse=True)
def setup_fee_db():
    client = MongoClient(MONGO_HOST, 27017)
    coll = client[MONGO_DBNAME]['signature']

    print('\n\npopulating db\n\n')
    coll.remove({})
    current_path = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(current_path, 'fixtures/signature_sec.json')

    with open(path) as f:
        file_data = json.load(f)

    coll.insert_many(file_data)
    client.close()


@pytest.fixture(scope='module', autouse=True)
def setup_users():
    client = MongoClient(MONGO_HOST, 27017)
    db = client['admin']
    user_collection = db['charon_user_permissions']

    already_populated = user_collection.count_documents({}) > 0

    if not already_populated:
        current_path = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(current_path, 'fixtures/users.json')

        with open(path) as f:
            file_data = json.load(f)

        user_collection.insert_many(file_data)
        client.close()


def make_headers(username, password):
    """Add standard headers - Basic Authorization and JSON content type. Pass auth string as decoded base64."""
    cred_str = '{}:{}'.format(username, password).encode('utf-8')
    creds = base64.b64encode(cred_str).decode('utf-8')
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Basic {}'.format(creds)}
    return headers


class BasicTestCase(unittest.TestCase):
    def assert_cat_list(self, items, sec_list):
        """Asserts that security category listed in the db item is allowed for the user."""
        for item in items:
            if item.get('_sec').get('cat') not in sec_list:
                self.fail('Received document with forbidden security category: {}'.format(item.get('_sec').get('cat')))

    def assert_dist_list(self, items, dist_list):
        """Asserts that all dissemination controls listed in the db item are allowed for the user."""
        user_diss_set = set(dist_list)
        for item in items:
            item_diss_set = set(item.get('_sec').get('diss'))
            if not item_diss_set.issubset(user_diss_set):
                self.fail('Received document with forbidden distribution rule: {}'.format(item_diss_set))
        return True

    def get_id_for_name(self, name):
        """Get the ID for a signature item with a given name. ID is used in update URL"""
        client = MongoClient(MONGO_HOST, 27017)
        coll = client[MONGO_DBNAME]['signature']
        resp = coll.find({"name": name}).next()
        oid = str(resp.get("_id"))
        return oid

    def get_db_object_by_name(self, name):
        """Get the data from Mongo for a given ID"""
        client = MongoClient(MONGO_HOST, 27017)
        coll = client[MONGO_DBNAME]['signature']
        resp = coll.find({"name": name}).next()
        return resp

    def setUp(self):
        """Define test variables and initialize app."""
        test_settings = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.py')

        # Set Schema
        os.environ['TEST_SCHEMA'] = '{"signature": {"_sec": {"schema": {"cat": {"type": "string"},"diss": {"schema": {"type": "string"},"type": "list"}},"type": "dict"},"attachments": {"schema": {"_sec": {"schema": {"cat": {"type": "string"},"diss": {"schema": {"type": "string"},"type": "list"}},"type": "dict"},"documents": {"type": "list"}},"type": "dict"},"date": {"type": "string"},"field_ref_id": {"type": "string"},"name": {"type": "string"},"signature": {"schema": {"_sec": {"schema": {"cat": {"type": "string"},"diss": {"schema": {"type": "string"},"type": "list"}},"type": "dict"},"value": {"type": "string"}},"type": "dict"},"user_ref_id": {"type": "string"},"vars": {}}}'

        self.app = Eve(settings=test_settings, auth=CharonAuth)
        self.app.config['TESTING'] = True
        self.app.config['DEBUG'] = True
        self.app.config['MONGO_DBNAME'] = MONGO_DBNAME
        self.app.config['MONGO_HOST'] = MONGO_HOST
        self.app.config['IF_MATCH'] = False  # TO DO - update fixtures to include etags, then return in get_id_for_name

        self.app.on_pre_POST += check_insert_data_context
        self.app.on_pre_POST += check_insert_access
        self.app.on_pre_POST += generate_presigned_urls

        self.app.on_pre_PATCH += check_insert_data_context
        self.app.on_pre_PATCH += check_insert_access
        self.app.on_pre_PATCH += check_perms_in_db

        self.app.on_post_POST += include_presigned_urls

        self.app.before_aggregation += add_ascl_redaction
        self.app.after_aggregation += include_s3_data
        self.client = self.app.test_client()
        self.app.testing = True

    def test_update_field_success(self):
        """Tests that a user with adequate permission for a field update can perform update"""
        data = {"signature": {"value": "testing_updates_changes", "_sec": {"cat": "usg_unclassified", "diss": []}}}

        headers = make_headers('us_unclassified_only', 'password')

        oid = self.get_id_for_name('all_unclassified')  # Document and signature field have _sec.cat == unclassified

        res = self.client.patch('/signature_write/{}'.format(oid), headers=headers, data=json.dumps(data))
        # import pdb; pdb.set_trace()
        self.assertEqual(res.status_code, 200)
        # self.assert_200(res)  # TO DO - confirm this works
        resp_data = None
        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /signature_write: {}'.format(exc))

        self.assertTrue(resp_data.get('_status'), 'ok')

    def test_update_doc_level_failure(self):
        """Tests that a user with insufficient document-level permission for a field update cannot perform update"""
        headers = make_headers('us_unclassified_only', 'password')
        data = {"signature": {"value": "testing_updates_changes", "_sec": {"cat": "usg_unclassified", "diss": []}}}

        oid = self.get_id_for_name('doc_confidential')  # Document has _sec.cat == confidential

        res = self.client.patch('/signature_write/{}'.format(oid), headers=headers, data=json.dumps(data))
        self.assertEqual(res.status_code, 403)

    def test_update_field_level_failure_cat(self):
        """Tests that a user with insufficient field-level _cat for the updated field cannot perform update"""
        headers = make_headers('us_unclassified_only', 'password')
        data = {"signature": {"value": "testing_updates_changes", "_sec": {"cat": "usg_unclassified", "diss": []}}}

        oid = self.get_id_for_name('sig_confidential')  # Signature field has _sec.cat == confidential

        res = self.client.patch('/signature_write/{}'.format(oid), headers=headers, data=json.dumps(data))
        self.assertEqual(res.status_code, 403)

    def test_update_field_level_failure_diss(self):
        """Tests that a user with insufficient field-level _diss for the updated field cannot perform update"""
        headers = make_headers('us_unclassified_only', 'password')
        data = {"signature": {"value": "testing_updates_changes", "_sec": {"cat": "usg_unclassified", "diss": []}}}

        oid = self.get_id_for_name('sig_diss_controlled')  # Signature field has _sec.cat == confidential

        res = self.client.patch('/signature_write/{}'.format(oid), headers=headers, data=json.dumps(data))
        self.assertEqual(res.status_code, 403)

    def test_update_nonrestricted_field_success(self):
        """Test that an update on a non-secured field succeeds if document contains restricted but non-updated field"""
        headers = make_headers('us_unclassified_only', 'password')
        data = {"user_ref_id": "changed_for_testing"}

        oid = self.get_id_for_name('sig_confidential')  # Signature field has _sec.cat == confidential

        res = self.client.patch('/signature_write/{}'.format(oid), headers=headers, data=json.dumps(data))

        self.assertEqual(res.status_code, 200)

    def test_partial_failure_fails_atomically(self):
        """Test that if a single field fails the security check, the entire update is rejected - no changes are made"""
        headers = make_headers('us_unclassified_only', 'password')

        # The user_ref_id change passes security check, the signature change fails
        data = {
            "user_ref_id": "changed_for_testing",
            "signature": {"value": "testing_updates_changes", "_sec": {"cat": "usg_unclassified", "diss": []}}
        }

        oid = self.get_id_for_name('sig_confidential')  # Signature field has _sec.cat == confidential
        db_values_before = self.get_db_object_by_name('sig_confidential')

        res = self.client.patch('/signature_write/{}'.format(oid), headers=headers, data=json.dumps(data))

        self.assertEqual(res.status_code, 403)

        # Verify that no data was changed
        db_values_after = self.get_db_object_by_name('sig_confidential')
        self.assertEqual(db_values_after.get('user_ref_id'), db_values_before.get('user_ref_id'))
        self.assertEqual(db_values_after.get('signature'), db_values_before.get('signature'))

    def test_update_user_setting_higher_permission_fails(self):
        """Test that a user can't set a level higher than what they posess (even if they have perms to modify field)"""
        headers = make_headers('us_secret_cumul', 'password')

        change_perms_too_high = {
            "signature": {"value": "testing_updates_changes", "_sec": {"cat": "usg_topsecret", "diss": []}}
        }

        change_perms_allowed = {
            "signature": {"value": "testing_updates_changes", "_sec": {"cat": "usg_unclassified", "diss": []}}
        }

        oid = self.get_id_for_name('all_unclassified')  # Document and signature field are unclassified

        # Attempt to set higher level of security on field than user is allowed
        res = self.client.patch('/signature_write/{}'.format(oid), headers=headers,
                                data=json.dumps(change_perms_too_high))
        self.assertEqual(res.status_code, 403)

        # Attempt to set field security to a value user is granted
        res = self.client.patch('/signature_write/{}'.format(oid), headers=headers,
                                data=json.dumps(change_perms_allowed))
        self.assertEqual(res.status_code, 200)
