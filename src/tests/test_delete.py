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

        self.app.on_pre_DELETE += check_perms_in_db

        self.app.before_aggregation += add_ascl_redaction
        self.app.after_aggregation += include_s3_data
        self.client = self.app.test_client()
        self.app.testing = True

    def test_delete_success(self):
        """Tests that a user with adequate permission can delete an object."""
        headers = make_headers('us_unclassified_only', 'password')

        oid = self.get_id_for_name('all_unclassified')  # Document and signature field have _sec.cat == unclassified

        res = self.client.delete('/signature_write/{}'.format(oid), headers=headers)
        self.assertEqual(res.status_code, 204)

        # Verify object does not get returned (it's really deleted)
        url = '/signature?aggregate={"$id":"' + str(oid) + '"}'
        res = self.client.get(url, headers=headers)
        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /signature: {}'.format(exc))

        self.assertEqual(resp_data.get('_items'), [])

    def test_delete_doc_level_permission_fail(self):
        """Tests that a user without sufficient document-level permission cannot delete an object."""
        headers = make_headers('us_unclassified_only', 'password')
        verification_headers = make_headers('us_topsecret_cumul', 'password')

        oid = self.get_id_for_name('doc_confidential')  # Document has _sec.cat == confidential

        res = self.client.delete('/signature_write/{}'.format(oid), headers=headers)
        self.assertEqual(res.status_code, 403)

        # Verify object gets returned (it's not deleted)
        url = '/signature?aggregate={"$id":"' + str(oid) + '"}'
        res = self.client.get(url, headers=verification_headers)
        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /signature: {}'.format(exc))

        self.assertTrue(len(resp_data.get('_items')) > 0)

    def test_delete_field_level_cat_fail(self):
        """Tests that a user without sufficient field-level security category cannot delete an object."""
        headers = make_headers('us_unclassified_only', 'password')
        verification_headers = make_headers('us_topsecret_cumul', 'password')

        oid = self.get_id_for_name('sig_confidential')  # Signature field has _sec.cat == confidential

        res = self.client.delete('/signature_write/{}'.format(oid), headers=headers)
        self.assertEqual(res.status_code, 403)

        # Verify object gets returned (it's not deleted)
        url = '/signature?aggregate={"$id":"' + str(oid) + '"}'
        res = self.client.get(url, headers=verification_headers)
        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /signature: {}'.format(exc))

        self.assertTrue(len(resp_data.get('_items')) > 0)

    def test_delete_field_level_diss_fail(self):
        """Tests that a user without sufficient field-level dissemination controls cannot delete an object."""
        headers = make_headers('us_unclassified_only', 'password')
        verification_headers = make_headers('us_topsecret_cumul', 'password')

        oid = self.get_id_for_name('sig_diss_controlled')  # Signature field has _sec.diss == confidential

        res = self.client.delete('/signature_write/{}'.format(oid), headers=headers)
        self.assertEqual(res.status_code, 403)

        # Verify object gets returned (it's not deleted)
        url = '/signature?aggregate={"$id":"' + str(oid) + '"}'
        res = self.client.get(url, headers=verification_headers)
        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /signature: {}'.format(exc))

        self.assertTrue(len(resp_data.get('_items')) > 0)

    def test_delete_collection_fail(self):
        """Tests that a delete action cannot be taken on the entire collection (an object ID is required)."""
        headers = make_headers('us_unclassified_only', 'password')

        res = self.client.delete('/signature_write', headers=headers)
        self.assertEqual(res.status_code, 405)
