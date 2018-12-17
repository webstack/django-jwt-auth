import json

from django.http import JsonResponse
from django.views.generic import View
from jwt_auth.mixins import JSONWebTokenAuthMixin


class MockView(JSONWebTokenAuthMixin, View):
    def post(self, request):
        return JsonResponse({"username": request.user.username})
