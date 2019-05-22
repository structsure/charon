import unittest
import json
import os
import pytest
import base64

import boto
# import boto3
# import botocore
# from botocore.stub import Stubber
# from moto import mock_s3

from eve import Eve
from pymongo import MongoClient
from auth import check_insert_access, check_insert_data_context, CharonAuth
from aggregators import add_ascl_redaction
from update import check_perms_in_db
from s3 import include_s3_data, generate_presigned_urls, include_presigned_urls

from .fixtures import mocks

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

    def WIP_test_insert_s3_presigned_urls(self):
        """Tests that sending IDs in the attachments field, w/ S3 attachments enabled, returns presigned urls """
        # Turn on S3_ATTACHMENTS feature
        self.app.config['S3_ATTACHMENTS'] = "True"
        attachments = ["11111", "22222", "33333"]

        headers = make_headers('us_secret_cumul', 'password')

        data = {
            "date": "1970-01-01T00:00:00Z",
            "name": "Test User",
            "user_ref_id": "1234565r4",
            "signature": {
                "value": "data:image/png;base64,iVBOtmz9[---REDACTED---]2/W+q8/8O2Zd",
                "_sec": {
                    "cat": "usg_unclassified",
                    "diss": []
                }
            },
            "field_ref_id": "1",
            "attachments": {
                "_sec": {
                    "cat": "usg_unclassified",
                    "diss": []
                },
                "documents": attachments
            },
            "_sec": {
                "cat": "usg_unclassified",
                "diss": []
            }
        }

        res = self.client.post('/signature_write', data=json.dumps(data), headers=headers)
        self.assertEqual(res.status_code, 201)
        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /fees: {}'.format(exc))

        # Check number of presigned urls == number of IDs in attachments.documents
        self.assertEqual(len(resp_data.get('_presigned_urls')), len(attachments))

        # Check the ID passed in attachments.documents is in the presigned url
        self.assertEqual(resp_data.get('_presigned_urls')[0].split('s3.amazonaws.com/')[1][:5], attachments[0])

    def test_insert_s3_not_enabled(self):
        """
        Tests that sending IDs in the attachments field, w/ S3 attachments disabled, does not generate presigned urls.
        """
        # Turn off S3_ATTACHMENTS feature
        self.app.config['S3_ATTACHMENTS'] = "False"
        attachments = ["11111", "22222", "33333"]

        headers = make_headers('us_secret_cumul', 'password')

        data = {
            "date": "1970-01-01T00:00:00Z",
            "name": "Test User",
            "user_ref_id": "1234565r4",
            "signature": {
                "value": "data:image/png;base64,iVBOtmz9[---REDACTED---]2/W+q8/8O2Zd",
                "_sec": {
                    "cat": "usg_unclassified",
                    "diss": []
                }
            },
            "field_ref_id": "1",
            "attachments": {
                "_sec": {
                    "cat": "usg_unclassified",
                    "diss": []
                },
                "documents": attachments
            },
            "_sec": {
                "cat": "usg_unclassified",
                "diss": []
            }
        }

        res = self.client.post('/signature_write', data=json.dumps(data), headers=headers)
        self.assertEqual(res.status_code, 201)
        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /signature: {}'.format(exc))

        # Confirm presigned urls were not created
        self.assertEqual(resp_data.get('_presigned_urls'), None)
        oid = resp_data.get('_id')

        # Query this object to make sure the values in documents.attachments were stored in the DB verbatim
        url = '/signature?aggregate={"$id":"' + str(oid) + '"}'
        res = self.client.get(url, headers=headers)
        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /signature: {}'.format(exc))
        self.assertEqual(resp_data.get('_items')[0].get('attachments').get('documents'), attachments)

    def WIP_test_include_s3_data(self):
        """
        Test that for read on an object that includes S3 attachments returns the data for those IDs is fetched from S3
        """
        os.environ['S3_ATTACHMENTS'] = "True"

        endpoint = 'signature'
        documents = mocks.sigs_pre_attachments
        post_documents = mocks.sigs_post_attachments

        conn = boto.connect_s3()
        conn.create_bucket('test_bucket')
        from s3 import include_s3_data
        resp = include_s3_data(documents, endpoint)
        import pdb; pdb.set_trace()

        print('done')

    def WIP_test_read_s3_enabled(self):
        """
        Test that data is fetched from S3 when the S3 Attachments feature is enabled.
        """
        self.app.config['S3_ATTACHMENTS'] = "True"

        oid = self.get_id_for_name('all_unclassified')  # Document and signature field are unclassified

        headers = make_headers('us_secret_cumul', 'password')

        # client = boto3.client('s3')
        # stubber = Stubber(client)
        # get_object_resp = {'ResponseMetadata': {'RequestId': '0B4CB4DA5CB5C10E', 'HostId': 'qlyBN484c40tq5Nn1aj40dze/xTCfKbTdiBiND5231hYlboDMeDh2wbNI4EfBRyh6mt5FsLrc4M=', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amz-id-2': 'qlyBN484c40tq5Nn1aj40dze/xTCfKbTdiBiND5231hYlboDMeDh2wbNI4EfBRyh6mt5FsLrc4M=', 'x-amz-request-id': '0B4CB4DA5CB5C10E', 'date': 'Tue, 30 Apr 2019 21:07:53 GMT', 'last-modified': 'Tue, 09 Apr 2019 20:22:34 GMT', 'etag': '"a579dc9b99a67f2a1d8893a9a9c7653e"', 'x-amz-server-side-encryption': 'AES256', 'content-encoding': 'utf-8', 'accept-ranges': 'bytes', 'content-type': 'binary/octet-stream', 'content-length': '3464', 'server': 'AmazonS3'}, 'RetryAttempts': 0}, 'AcceptRanges': 'bytes', 'LastModified': datetime.datetime(2019, 4, 9, 20, 22, 34, tzinfo=tzutc()), 'ContentLength': 3464, 'ETag': '"a579dc9b99a67f2a1d8893a9a9c7653e"', 'ContentEncoding': 'utf-8', 'ContentType': 'binary/octet-stream', 'ServerSideEncryption': 'AES256', 'Metadata': {}, 'Body': <botocore.response.StreamingBody object at 0x1124707b8>}
        # expected_params = {}
        # stubber.add_response('get_object', get_object_resp, expected_params)

        # with stubber:
        #     resp = client.get_object()
        # print(resp)
        # import pdb; pdb.set_trace()

        url = '/signature?aggregate={"$id":"' + str(oid) + '"}'
        res = self.client.get(url, headers=headers)

        try:
            resp_data = json.loads(res.data)
        except json.decoder.JSONDecodeError as exc:
            self.fail('Received invalid json from /signature: {}'.format(exc))

        # self.assertEqual(resp_data.get('_items')[0].get('attachments').get('documents'), attachments)
