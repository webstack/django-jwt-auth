from django.urls import path

from jwt_auth import views as jwt_auth_views
from tests.views import MockView


urlpatterns = [
    path("jwt/", MockView.as_view()),
    path("auth-token/", jwt_auth_views.obtain_jwt_token),
    path("refresh-token/", jwt_auth_views.refresh_jwt_token),
]
