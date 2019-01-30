from datetime import datetime, timedelta

from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext as _
from jwt_auth import settings as jwt_auth_settings
from jwt_auth.core import User
from jwt_auth.utils import jwt_get_user_id_from_payload_handler


class JSONWebTokenForm(forms.Form):
    password = forms.CharField()

    def __init__(self, *args, **kwargs):
        super(JSONWebTokenForm, self).__init__(*args, **kwargs)

        # Dynamically add the USERNAME_FIELD to self.fields.
        self.fields[self.username_field] = forms.CharField()

    @property
    def username_field(self):
        try:
            return User.USERNAME_FIELD
        except AttributeError:
            return "username"

    def clean(self):
        cleaned_data = super(JSONWebTokenForm, self).clean()
        credentials = {
            self.username_field: cleaned_data.get(self.username_field),
            "password": cleaned_data.get("password"),
        }

        if not all(credentials.values()):
            raise forms.ValidationError(_("Must include 'username' and 'password'."))

        user = authenticate(**credentials)

        if user:
            if not user.is_active:
                raise forms.ValidationError(_("User account is disabled."))
        else:
            raise forms.ValidationError(_("Unable to login with provided credentials."))

        cleaned_data["user"] = user


class JSONWebTokenRefreshForm(forms.Form):
    token = forms.CharField()

    def clean(self):
        cleaned_data = super(JSONWebTokenRefreshForm, self).clean()

        old_payload = jwt_auth_settings.JWT_DECODE_HANDLER(cleaned_data.get("token"))
        user_id = jwt_get_user_id_from_payload_handler(old_payload)

        # Verify user
        try:
            user = User.objects.get(id=user_id)
        except ObjectDoesNotExist:
            raise forms.ValidationError(_("Unable to login with provided credentials."))

        if not user.is_active:
            raise forms.ValidationError(_("User account is disabled."))

        # Verify orig_iat
        orig_iat = old_payload.get("orig_iat")
        if not orig_iat:
            raise forms.ValidationError(_("orig_iat was missing from payload."))

        # Verify expiration
        refresh_limit = jwt_auth_settings.JWT_REFRESH_EXPIRATION_DELTA

        if isinstance(refresh_limit, timedelta):
            refresh_limit = refresh_limit.days * 24 * 3600 + refresh_limit.seconds

        expiration_timestamp = orig_iat + int(refresh_limit)
        now_timestamp = datetime.utcnow().timestamp()

        if now_timestamp > expiration_timestamp:
            raise forms.ValidationError(_("Refresh has expired."))

        # Data to re-issue new token. Include original issued at time for a
        # brand new token, to allow token refresh.
        cleaned_data["user"] = user
        cleaned_data["orig_iat"] = orig_iat
