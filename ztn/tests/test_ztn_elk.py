import unittest
import requests
from ztn import ztn_elk


class APITestCases(unittest.TestCase):
    def setUp(self):
        url = "https://172.25.125.101/api/"

        payload = {}
        headers = {
            'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
        }

        response = requests.request(
            "GET", url, headers=headers, data=payload, verify=False)

        self.assertEqual(response.status_code, 200)

    def test_address_exists(self):
        addr_id, status_code = ztn_elk.check_address_exists("24.0.0.1")
        self.assertEqual(status_code, 200)


if __name__ == '__main__':
    unittest.main()
