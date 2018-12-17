import json
import jwt
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt
from jwt_auth import exceptions, settings
from jwt_auth.core import User
from jwt_auth.utils import get_authorization_header

jwt_decode_handler = settings.JWT_DECODE_HANDLER
jwt_get_user_id_from_payload = settings.JWT_PAYLOAD_GET_USER_ID_HANDLER


class JSONWebTokenAuthMixin(object):
    """
    Token based authentication using the JSON Web Token standard.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:

        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """

    www_authenticate_realm = "api"

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        try:
            request.user, request.token = self.authenticate(request)
        except exceptions.AuthenticationFailed as e:
            response = HttpResponse(
                json.dumps({"errors": [str(e)]}),
                status=401,
                content_type="application/json",
            )

            response["WWW-Authenticate"] = self.authenticate_header(request)

            return response

        return super(JSONWebTokenAuthMixin, self).dispatch(request, *args, **kwargs)

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth or auth[0].lower().decode("utf-8") != auth_header_prefix:
            raise exceptions.AuthenticationFailed()

        if len(auth) == 1:
            raise exceptions.AuthenticationFailed(
                _("Invalid Authorization header. No credentials provided.")
            )
        elif len(auth) > 2:
            raise exceptions.AuthenticationFailed(
                _(
                    "Invalid Authorization header. Credentials string "
                    "should not contain spaces."
                )
            )

        try:
            payload = jwt_decode_handler(auth[1])
        except jwt.ExpiredSignature:
            raise exceptions.AuthenticationFailed(_("Signature has expired."))
        except jwt.DecodeError:
            raise exceptions.AuthenticationFailed(_("Error decoding signature."))

        user = self.authenticate_credentials(payload)

        return (user, auth[1])

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        try:
            user_id = jwt_get_user_id_from_payload(payload)

            if user_id:
                user = User.objects.get(pk=user_id, is_active=True)
            else:
                raise exceptions.AuthenticationFailed(_("Invalid payload"))
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed(_("Invalid signature"))

        return user

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return 'JWT realm="{0}"'.format(self.www_authenticate_realm)
