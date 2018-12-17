from django.urls import path
from jwt_auth import views as jwt_auth_views

from tests import views

urlpatterns = [
    path("plain/", views.plain_view, name="plain"),
    path("protected/", views.ProtectedView.as_view(), name="protected"),
    path("token-auth/", jwt_auth_views.obtain_jwt_token, name="auth_token"),
    path("token-refresh/", jwt_auth_views.refresh_jwt_token, name="refresh_token"),
]
