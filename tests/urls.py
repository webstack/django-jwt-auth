from django.urls import path

from jwt_auth import views
from tests.views import MockView


urlpatterns = [
    path("jwt/", MockView.as_view()),
    path("auth-token/", views.obtain_jwt_token),
    path("refresh-token/", views.refresh_jwt_token)
]
