from django.urls import path

urlpatterns = []

# adding jwt authentication url paths

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from .views import RegisterView, ProtectedTestView, ChangePasswordView

urlpatterns += [
    path('api/login/', TokenObtainPairView.as_view(), name='login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/user/changepass/', ChangePasswordView.as_view(), name='change_password'),
    path('api/test/protected/', ProtectedTestView.as_view(), name='protected_test'),
]
