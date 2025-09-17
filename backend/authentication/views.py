
# Register view
from django.contrib.auth import get_user_model

User = get_user_model()

from rest_framework import generics, serializers, permissions


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "email", "password")
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer


# Protected API view ( for Testing )
from rest_framework.views import APIView
from rest_framework.response import Response


class ProtectedTestView(APIView):

    def get(self, request):
        return Response({"message": ["hello", request.user.id, request.user.username]})
