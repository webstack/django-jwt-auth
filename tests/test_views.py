import json

from calendar import timegm
from datetime import datetime, timedelta

from django.shortcuts import reverse
from django.test import TestCase
from django.test.client import Client
from jwt_auth import settings, utils
from jwt_auth.core import User


class JSONWebTokenTestCase(TestCase):
    def setUp(self):
        self.email = "foo@example.com"
        self.username = "foo"
        self.password = "password"
        self.user = User.objects.create_user(self.username, self.email, self.password)

        self.data = {"username": self.username, "password": self.password}

        self.client = Client()
        self.auth_token_url = reverse("auth_token")

    def test_login(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        response = self.client.post(
            self.auth_token_url, self.data, content_type="application/json"
        )
        response_content = response.json()
        expires_in = response_content["expires_in"]
        self.assertEqual(expires_in, settings.JWT_EXPIRATION_DELTA.total_seconds())
        decoded_payload = utils.jwt_decode_handler(response_content["token"])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(decoded_payload["username"], self.username)

    def test_bad_credentials(self):
        """
        Ensure JWT login view using JSON POST fails if bad credentials are used.
        """
        self.data["password"] = "wrong"

        response = self.client.post(
            self.auth_token_url, self.data, content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)

    def test_missing_fields(self):
        """
        Ensure JWT login view using JSON POST fails if missing fields.
        """
        response = self.client.post(
            self.auth_token_url,
            {"username": self.username},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_login_with_expired_token(self):
        """
        Ensure JWT login view works even if expired token is provided
        """
        payload = utils.jwt_payload_handler(self.user)
        payload["exp"] = 1
        token = utils.jwt_encode_handler(payload)

        auth = "Bearer {0}".format(token)

        response = self.client.post(
            self.auth_token_url,
            self.data,
            content_type="application/json",
            HTTP_AUTHORIZATION=auth,
        )
        response_content = response.json()
        decoded_payload = utils.jwt_decode_handler(response_content["token"])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(decoded_payload["username"], self.username)

    def test_invalid_payload(self):
        # Not JSON content
        response = self.client.post(self.auth_token_url, {"foo": "bar"})
        self.assertEqual(response.status_code, 400)


class RefreshJSONWebTokenTestCase(TestCase):
    def setUp(self):
        self.email = "jpueblo@example.com"
        self.username = "jpueblo"
        self.password = "password"
        self.user = User.objects.create_user(self.username, self.email, self.password)

        self.payload = utils.jwt_payload_handler(self.user)
        self.payload["orig_iat"] = timegm(datetime.utcnow().utctimetuple())

        self.client = Client()
        self.refresh_auth_token_url = reverse("refresh_token")

    def test_refresh(self):
        """
        Ensure JWT refresh view using JSON POST works.
        """
        data = {"token": utils.jwt_encode_handler(self.payload)}

        response = self.client.post(
            self.refresh_auth_token_url, data, content_type="application/json"
        )
        decoded_payload = utils.jwt_decode_handler(response.json()["token"])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(decoded_payload["username"], self.username)

    def test_inactive_user(self):
        """
        Ensure JWT refresh view using JSON POST fails
        if the user is inactive
        """

        self.user.is_active = False
        self.user.save()

        data = {"token": utils.jwt_encode_handler(self.payload)}
        response = self.client.post(
            self.refresh_auth_token_url, data, content_type="application/json"
        )

        self.assertEqual(response.status_code, 400)

    def test_no_orig_iat(self):
        """
        Ensure JWT refresh view using JSON POST fails
        if no orig_iat is present on the payload.
        """
        self.payload.pop("orig_iat")

        data = {"token": utils.jwt_encode_handler(self.payload)}
        response = self.client.post(
            self.refresh_auth_token_url, data, content_type="application/json"
        )

        self.assertEqual(response.status_code, 400)

    def test_refresh_with_expired_token(self):
        """
        Ensure JWT refresh view using JSON POST fails
        if the refresh has expired
        """

        # We make sure that the refresh token is not in the window
        # allowed by the expiration delta. This is much easier using
        # freezegun.
        orig_iat = (
            datetime.utcfromtimestamp(self.payload["orig_iat"])
            - settings.JWT_REFRESH_EXPIRATION_DELTA
            - timedelta(days=1)
        )
        self.payload["orig_iat"] = timegm(orig_iat.utctimetuple())
        data = {"token": utils.jwt_encode_handler(self.payload)}
        response = self.client.post(
            self.refresh_auth_token_url, data, content_type="application/json"
        )

        self.assertEqual(response.status_code, 400)
