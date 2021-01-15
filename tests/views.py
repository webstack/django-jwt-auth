from django.http import JsonResponse
from django.views.generic import View
from jwt_auth.mixins import JSONWebTokenAuthMixin


class ProtectedView(JSONWebTokenAuthMixin, View):
    def get(self, request):
        return JsonResponse({"username": request.user.username})


def plain_view(request):
    return JsonResponse(
        {"username": request.user.username if getattr(request, "user", None) else None}
    )
