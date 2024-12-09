import unittest
import requests
import uuid

BASE_URL = "http://localhost:8080"

class TestServer(unittest.TestCase):
    def test_register_user(self):
        """Test registering a new user."""
        response = requests.post(f"{BASE_URL}/register", json={
            "username": f"testuser{uuid.uuid4()}",
            "email": f"test{uuid.uuid4()}@example.com"
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn("password", response.json())

    def test_register_existing_user(self):
        """Test registering an existing user."""
        username = f"testuser{uuid.uuid4()}"
        email = f"test{uuid.uuid4()}@example.com"

        # Register the user for the first time
        requests.post(f"{BASE_URL}/register", json={
            "username": username,
            "email": email
        })

        # Try registering the same user again
        response = requests.post(f"{BASE_URL}/register", json={
            "username": username,
            "email": email
        })
        self.assertEqual(response.status_code, 409)  # Conflict

    def test_auth_successful(self):
        """Test successful authentication."""
        username = f"testuser{uuid.uuid4()}"
        email = f"test{uuid.uuid4()}@example.com"

        # Register the user
        register_response = requests.post(f"{BASE_URL}/register", json={
            "username": username,
            "email": email
        })
        self.assertEqual(register_response.status_code, 201)
        password = register_response.json().get("password")

        # Authenticate the user with the correct password
        auth_response = requests.post(f"{BASE_URL}/auth", json={
            "username": username,
            "password": password
        })
        self.assertEqual(auth_response.status_code, 200)

    def test_auth_failed(self):
        """Test failed authentication with incorrect credentials."""
        response = requests.post(f"{BASE_URL}/auth", json={
            "username": "nonexistentuser",
            "password": "wrongpassword"
        })
        self.assertEqual(response.status_code, 401)

    def test_auth_rate_limited(self):
        """Test rate-limiting on the /auth endpoint."""
        global response
        username = f"ratelimituser{uuid.uuid4()}"
        email = f"ratelimit{uuid.uuid4()}@example.com"

        # Register the user
        register_response = requests.post(f"{BASE_URL}/register", json={
            "username": username,
            "email": email
        })
        self.assertEqual(register_response.status_code, 201)
        password = register_response.json().get("password")

        # Simulate 15 rapid authentication requests
        for i in range(15):
            response = requests.post(f"{BASE_URL}/auth", json={
                "username": username,
                "password": password
            })

        # Check that the final response is 429 Too Many Requests
        self.assertEqual(response.status_code, 429)

if __name__ == "__main__":
    unittest.main()
