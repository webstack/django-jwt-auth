from django.shortcuts import reverse
from django.test import TestCase
from django.test.client import Client
from jwt_auth import utils
from jwt_auth.core import User


class JSONWebTokenAuthMixinTestCase(TestCase):
    def setUp(self):
        self.email = "foo@example.com"
        self.username = "foo"
        self.password = "password"
        self.user = User.objects.create_user(self.username, self.email, self.password)
        self.data = {"username": self.username, "password": self.password}

        self.client = Client()
        self.protected_url = reverse("protected")

    def test_passing_jwt_auth(self):
        """
        Ensure getting form over JWT auth with correct credentials passes and
        does not require CSRF
        """
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        auth = "Bearer {0}".format(token)
        response = self.client.get(
            self.protected_url, content_type="application/json", HTTP_AUTHORIZATION=auth
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], self.username)

    def test_failing_jwt_auth(self):
        """
        Ensure POSTing json over JWT auth without correct credentials fails
        """
        response = self.client.get(self.protected_url, content_type="application/json")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["WWW-Authenticate"], 'JWT realm="api"')
        expected_error = ["Incorrect authentication credentials."]
        self.assertEqual(response.json()["errors"], expected_error)

    def test_no_jwt_header_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth without credentials fails
        """
        auth = "Bearer"
        response = self.client.get(
            self.protected_url, content_type="application/json", HTTP_AUTHORIZATION=auth
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["WWW-Authenticate"], 'JWT realm="api"')

        expected_error = ["Invalid Authorization header. No credentials provided."]
        self.assertEqual(response.json()["errors"], expected_error)

    def test_invalid_jwt_header_failing_jwt_auth(self):
        """
        Ensure getting over JWT auth without correct credentials fails
        """
        auth = "Bearer abc abc"
        response = self.client.post(
            self.protected_url, content_type="application/json", HTTP_AUTHORIZATION=auth
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["WWW-Authenticate"], 'JWT realm="api"')
        expected_error = [
            "Invalid Authorization header. Credentials string should not contain spaces."
        ]
        self.assertEqual(response.json()["errors"], expected_error)

    def test_expired_token_failing_jwt_auth(self):
        """
        Ensure getting over JWT auth with expired token fails
        """
        payload = utils.jwt_payload_handler(self.user)
        payload["exp"] = 1
        token = utils.jwt_encode_handler(payload)

        auth = "Bearer {0}".format(token)
        response = self.client.get(
            self.protected_url, content_type="application/json", HTTP_AUTHORIZATION=auth
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["WWW-Authenticate"], 'JWT realm="api"')
        expected_error = ["Signature has expired."]
        self.assertEqual(response.json()["errors"], expected_error)

    def test_invalid_token_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth with invalid token fails
        """
        auth = "Bearer abc123"
        response = self.client.get(
            self.protected_url, content_type="application/json", HTTP_AUTHORIZATION=auth
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["WWW-Authenticate"], 'JWT realm="api"')

        expected_error = ["Error decoding signature."]
        self.assertEqual(response.json()["errors"], expected_error)
