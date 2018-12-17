from django.urls import path
from jwt_auth import views as jwt_auth_views

from tests.views import MockView

urlpatterns = [
    path("mock-jwt/", MockView.as_view(), name="mock_jwt"),
    path("token-auth/", jwt_auth_views.obtain_jwt_token, name="auth_token"),
    path("token-refresh/", jwt_auth_views.refresh_jwt_token, name="refresh_token"),
]
