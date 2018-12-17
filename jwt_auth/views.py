import json

from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from jwt_auth import settings as jwt_auth_settings
from jwt_auth.forms import JSONWebTokenForm, JSONWebTokenRefreshForm


class JSONWebTokenViewBase(View):
    http_method_names = ["post"]
    error_response_dict = {"errors": [_("Improperly formatted request")]}
    json_encoder_class = DjangoJSONEncoder

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(JSONWebTokenViewBase, self).dispatch(request, *args, **kwargs)

    def get_form(self, request_json):
        raise NotImplementedError()

    def post(self, request, *args, **kwargs):
        try:
            request_json = json.loads(request.body.decode("utf-8"))
        except ValueError:
            return self.render_bad_request_response()

        form = self.get_form(request_json)

        if not form.is_valid():
            return self.render_bad_request_response({"errors": form.errors})

        context_dict = {
            "token": form.object["token"],
            "expiresIn": jwt_auth_settings.JWT_EXPIRATION_DELTA.total_seconds(),
        }

        return self.render_response(context_dict)

    def render_response(self, context_dict):
        return JsonResponse(context_dict)

    def render_bad_request_response(self, error_dict=None):
        if error_dict is None:
            error_dict = self.error_response_dictx
        return JsonResponse(error_dict, status=400)


class ObtainJSONWebToken(JSONWebTokenViewBase):
    def get_form(self, request_json):
        return JSONWebTokenForm(request_json)


class RefreshJSONWebToken(JSONWebTokenViewBase):
    def get_form(self, request_json):
        return JSONWebTokenRefreshForm(request_json)


obtain_jwt_token = ObtainJSONWebToken.as_view()
refresh_jwt_token = RefreshJSONWebToken.as_view()
