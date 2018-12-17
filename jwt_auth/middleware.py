import json
import jwt
import logging

from django.conf import settings
from django.http import JsonResponse
from django.utils.translation import ugettext as _
from jwt_auth import settings as jwt_auth_settings, exceptions, mixins
from jwt_auth.core import User
from jwt_auth.utils import get_authorization_header

logger = logging.getLogger(__name__)

jwt_decode_handler = jwt_auth_settings.JWT_DECODE_HANDLER
jwt_get_user_id_from_payload = jwt_auth_settings.JWT_PAYLOAD_GET_USER_ID_HANDLER


class JWTAuthenticationMiddleware:
    """
    Token based authentication using the JSON Web Token standard. Clients should
    authenticate by passing the token key in the "Authorization" HTTP header,
    prepended with the string specified in the setting `JWT_AUTH_HEADER_PREFIX`.
    For example:

    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdW....
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path_info != settings.LOGIN_URL:
            try:
                token = mixins.get_token_from_request(request)
                payload = mixins.get_payload_from_token(token)
                user_id = mixins.get_user_id_from_payload(payload)
                request.user = mixins.get_user(user_id)
                if not request.user:
                    raise exceptions.AuthenticationFailed(_("Invalid user ID."))
            except exceptions.AuthenticationFailed as e:
                return JsonResponse({"error": str(e)}, status=401)

        return self.get_response(request)
