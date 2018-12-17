import json

from django.shortcuts import reverse
from django.test import TestCase, modify_settings
from django.test.client import Client
from jwt_auth import utils
from jwt_auth.core import User


class JWTAuthenticationMiddlewareTestCase(TestCase):
    def setUp(self):
        self.email = "foo@example.com"
        self.username = "foo"
        self.password = "password"
        self.user = User.objects.create_user(self.username, self.email, self.password)
        self.data = {"username": self.username, "password": self.password}

        self.client = Client()
        self.auth_token_url = reverse("auth_token")
        self.protected_url = reverse("protected")
        self.plain_url = reverse("plain")

    def test_access_allowed_no_middleware(self):
        response = self.client.get(self.plain_url)
        self.assertEqual(response.status_code, 200)

    def test_access_denied_to_protected_no_middleware(self):
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, 401)

    @modify_settings(
        MIDDLEWARE={"append": "jwt_auth.middleware.JWTAuthenticationMiddleware"}
    )
    def test_access_denied_with_middleware(self):
        response = self.client.get(self.plain_url)
        self.assertEqual(response.status_code, 401)

        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, 401)

    @modify_settings(
        MIDDLEWARE={"append": "jwt_auth.middleware.JWTAuthenticationMiddleware"}
    )
    def test_access_allowed_with_middleware(self):
        response = self.client.post(
            self.auth_token_url, json.dumps(self.data), content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        header_value = "Bearer {0}".format(content["token"])
        response = self.client.get(
            self.plain_url,
            content_type="application/json",
            HTTP_AUTHORIZATION=header_value,
        )
        self.assertEqual(response.status_code, 200)
