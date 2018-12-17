import jwt
import logging

from django.utils.translation import ugettext as _
from jwt_auth import settings, exceptions
from jwt_auth.compat import json, smart_text, User
from jwt_auth.utils import get_authorization_header

logger = logging.getLogger(__name__)

jwt_decode_handler = settings.JWT_DECODE_HANDLER
jwt_get_user_id_from_payload = settings.JWT_PAYLOAD_GET_USER_ID_HANDLER


class JWTAuthenticationMiddleware:
    """
    Token based authentication using the JSON Web Token standard. Clients should
    authenticate by passing the token key in the "Authorization" HTTP header,
    prepended with the string specified in the setting `JWT_AUTH_HEADER_PREFIX`.
    For example:

    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdW....
    """

    def __init__(self, get_response=None):
        self.get_response = get_response

    def process_request(self, request):
        try:
            auth = get_authorization_header(request).split()
            auth_header_prefix = settings.JWT_AUTH_HEADER_PREFIX.lower()
            if not auth or smart_text(auth[0].lower()) != auth_header_prefix:
                raise exceptions.AuthenticationFailed()
            if len(auth) == 1:
                raise exceptions.AuthenticationFailed(
                    _("Invalid Authorization header. No credentials provided.")
                )
            elif len(auth) > 2:
                raise exceptions.AuthenticationFailed(
                    _(
                        "Invalid Authorization header. Credentials string should not contain spaces."
                    )
                )

            try:
                payload = jwt_decode_handler(auth[1])
            except jwt.ExpiredSignature:
                raise exceptions.AuthenticationFailed(_("Signature has expired."))
            except jwt.DecodeError:
                raise exceptions.AuthenticationFailed(_("Error decoding signature."))

            try:
                user_id = jwt_get_user_id_from_payload(payload)
                if user_id:
                    user = User.objects.get(pk=user_id, is_active=True)
                else:
                    raise exceptions.AuthenticationFailed(_("Invalid payload"))
            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed(_("Invalid signature"))

            request.user = user

        except exceptions.AuthenticationFailed as e:
            logger.exception(e)

    def process_response(self, request, response):
        return response
