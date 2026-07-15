import os
import unittest

from backend.app import app


class SecureWatchAppTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
        with app.app_context():
            from backend.database import db
            db.drop_all()
            db.create_all()
        self.client = app.test_client()

    def test_health_endpoint(self):
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['status'], 'healthy')

    def test_stats_api(self):
        response = self.client.get('/api/stats')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn('total_events', payload)
        self.assertIn('total_alerts', payload)


if __name__ == '__main__':
    unittest.main()
