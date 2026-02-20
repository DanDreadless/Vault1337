from django.contrib.auth.models import User
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated

from .serializers import UserCreateSerializer, UserProfileSerializer


class RegisterView(CreateAPIView):
    """
    POST /api/v1/auth/register/

    Public endpoint — creates a new user account.
    Returns the new user's id and username (no password fields).
    """

    queryset = User.objects.all()
    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]

    def get_serializer(self, *args, **kwargs):
        kwargs.setdefault('context', self.get_serializer_context())
        return UserCreateSerializer(*args, **kwargs)


class UserDetailView(RetrieveUpdateAPIView):
    """
    GET  /api/v1/auth/user/ — return the authenticated user's profile.
    PATCH /api/v1/auth/user/ — update email or profile fields.
    """

    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
