from django.utils.translation import ugettext as _


class AuthenticationFailed(Exception):
    status_code = 401
    detail = _("Incorrect authentication credentials.")

    def __init__(self, detail=None):
        super().__init__(self)
        self.detail = detail or self.detail

    def __str__(self):
        return self.detail
