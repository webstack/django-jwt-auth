import json

from django.http import HttpResponse
from django.views.generic import View
from jwt_auth.mixins import JSONWebTokenAuthMixin


class MockView(JSONWebTokenAuthMixin, View):
    def post(self, request):
        data = json.dumps({"username": request.user.username})
        return HttpResponse(data)
