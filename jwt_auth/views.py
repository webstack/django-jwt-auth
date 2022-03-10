import json
from datetime import datetime

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from jwt_auth import settings as jwt_auth_settings
from jwt_auth.forms import JSONWebTokenForm, JSONWebTokenRefreshForm


def jwt_encode_token(user, orig_iat=None):
    payload = jwt_auth_settings.JWT_PAYLOAD_HANDLER(user)

    if orig_iat is None:
        if jwt_auth_settings.JWT_ALLOW_REFRESH:
            # Include original issued at time for a brand new token, to
            # allow token refresh
            payload["orig_iat"] = int(datetime.utcnow().timestamp())
    else:
        payload["orig_iat"] = orig_iat

    return jwt_auth_settings.JWT_ENCODE_HANDLER(payload)


def jwt_get_json_with_token(token):
    return {
        "token_type": jwt_auth_settings.JWT_AUTH_HEADER_PREFIX,
        "token": token,
        "expires_in": jwt_auth_settings.JWT_EXPIRATION_DELTA.total_seconds(),
    }


class JSONWebTokenViewBase(View):
    http_method_names = ["post"]

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(JSONWebTokenViewBase, self).dispatch(request, *args, **kwargs)

    def get_form(self, request_json):
        raise NotImplementedError()

    def post(self, request):
        try:
            request_json = json.loads(request.body.decode("utf-8"))
        except ValueError:
            return JsonResponse(
                {"errors": [_("Improperly formatted request")]}, status=400
            )

        form = self.get_form(request_json)
        if not form.is_valid():
            return JsonResponse({"errors": form.errors}, status=400)

        token = jwt_encode_token(
            form.cleaned_data["user"], form.cleaned_data.get("orig_iat")
        )
        return JsonResponse(jwt_get_json_with_token(token))


class JSONWebToken(JSONWebTokenViewBase):
    def get_form(self, request_json):
        return JSONWebTokenForm(request_json)


class RefreshJSONWebToken(JSONWebTokenViewBase):
    def get_form(self, request_json):
        return JSONWebTokenRefreshForm(request_json)


jwt_token = JSONWebToken.as_view()
refresh_jwt_token = RefreshJSONWebToken.as_view()
