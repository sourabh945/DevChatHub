
# Register view
from django.contrib.auth import get_user_model

User = get_user_model()

from rest_framework import serializers, permissions, status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.core.exceptions import ValidationError

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "email", "password")
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.create(serializer.validated_data)
                if not user:
                    return Response({"error": "User registration failed"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    refresh = RefreshToken.for_user(user) #type: ignore
                    return Response({
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    }, status=status.HTTP_201_CREATED)
            except ValidationError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"error": "An error occurred during registration"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Protected API view ( for Testing )
from rest_framework.response import Response


class ProtectedTestView(APIView):

    def get(self, request):
        return Response({"message": ["hello", str(request.user.id), request.user.username]}, status.HTTP_200_OK)


# Protected API view for changing password
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def change_password(self, user, validated_data):
       user.change_password(validated_data["old_password"], validated_data["new_password"]) #type: ignore




class ChangePasswordView(APIView):

    serializer_class = ChangePasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = request.user
            try:
                serializer.change_password(user, serializer.validated_data) #type: ignore
                return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
            except ValidationError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
