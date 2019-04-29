import unittest
from eve import Eve
from aggregators import before_agg
import json

class BasicTestCase(unittest.TestCase):
    def setUp(self):
        """Define test variables and initialize app."""
        self.app = Eve(settings='settings.py')
        self.app.config['TESTING'] = True
        self.app.config['DEBUG'] = True
        self.app.config['MONGO_DBNAME'] = "dbz-mongo-test"
        self.app.config['MONGO_HOST'] = "127.0.0.1"
        self.client = self.app.test_client
        self.users = {"name": "John Smith"}

        with self.app.app_context():
            res = self.client().get('/')

    # def test_create_user(self):
    #     res = self.client().post('/users/', data=json.dumps(self.users), content_type='application/json')
    #     self.assertEqual(res.status_code, 201)
    #     self.assertIn("John Smith", str(res.data))

    def test_get_users(self):
        res = self.client().post('/users/', data=json.dumps(self.users), content_type='application/json')
        self.assertEqual(res.status_code, 201)
        res = self.client().get('/users/', data=json.dumps(self.users), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertIn("John Smith", str(res.data))

    def test_get_user_id(self):
        rv = self.client().post('/users/', data=json.dumps(self.users), content_type='application/json')
        self.assertEqual(rv.status_code, 201)
        result_in_json = json.loads(rv.data.decode('utf-8').replace("'", "\""))
        result = self.client().get(
            '/users/{}'.format(result_in_json['id']))
        self.assertEqual(result.status_code, 200)
        self.assertIn("John Smith", str(result.data))

    def test_edit_user(self):
        rv = self.client().post(
            '/users/',
            data={"name": "John Smith"})
        self.assertEqual(rv.status_code, 201)
        rv = self.client().put(
            '/users/1',
            data={
                "name": "John Smith Jr."
            })
        self.assertEqual(rv.status_code, 200)
        results = self.client().get('/users/1')
        self.assertIn('Jr.', str(results.data))

    def test_delete_user(self):
        """Test API can delete an existing user. (DELETE request)."""
        rv = self.client().post(
            '/users/',
            data={"name": "John Smith"})
        self.assertEqual(rv.status_code, 201)
        res = self.client().delete('/users/1')
        self.assertEqual(res.status_code, 200)
        # Test to see if it exists, should return a 404
        result = self.client().get('/users/1')
        self.assertEqual(result.status_code, 404)

    # def test_user_access():
    #     tester = app.test_client(self)
    #     response = tester.get('/scl', content_type='application/json')
    #     self.assertEqual(response.status_code, 200)

    def tearDown(self):
        """teardown all initialized variables."""
        with self.app.app_context():
            # drop all tables
            rv = self.client().delete('/', content_type='application/json')

    def test_index(self):
        tester = app.test_client(self)
        response = tester.get('/', content_type='html/text')
        self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
    unittest.main()
