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

from .fixtures.schemas import fees_with_attachments

MONGO_DBNAME = 'dbz-mongo-test'
MONGO_HOST = '127.0.0.1'

US_CITIZEN_DISS = ['usg_noforn', 'usg_relfvey', 'usg_relgbr']
GBR_CITIZEN_DISS = ['usg_relfvey', 'usg_relgbr']
CAN_CITIZEN_DISS = ['usg_relfvey']


@pytest.fixture(scope='function', autouse=True)
def setup_fee_db():
    client = MongoClient(MONGO_HOST, 27017)
    db = client[MONGO_DBNAME]
    fee_collection = db['fees_with_attachments']

    already_populated = fee_collection.count_documents({}) > 0

    if not already_populated:
        print('\n\npopulating db\n\n')
        current_path = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(current_path, 'fixtures/fees_with_attachments.json')

        with open(path) as f:
            file_data = json.load(f)

        fee_collection.insert_many(file_data)
        client.close()
    else:
        print('\n\ndb is already populated\n\n')


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

    def setUp(self):
        """Define test variables and initialize app."""
        test_settings = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.py')

        # Set Schema
        os.environ['TEST_SCHEMA'] = json.dumps(fees_with_attachments)

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

    def test_strip_metadata(self):
        """Test that metadata fields used for redaction are removed."""
        headers = make_headers('us_topsecret_cumul', 'password')

        res = self.client.get('/fees_with_attachments', headers=headers)
        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /fees_with_attachments: {}'.format(exc))

        item = resp_data.get('_items')[0]

        # Assert that top-level metadata match fields were removed
        self.assertEqual(item.get('cat_matches'), None)
        self.assertEqual(item.get('diss_matches'), None)

        # Assert that nested metadata match fields were removed
        self.assertEqual(item.get('attachments').get('cat_matches'), None)
        self.assertEqual(item.get('attachments').get('diss_matches'), None)
