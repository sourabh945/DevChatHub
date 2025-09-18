#file: ignore

from django.http.response import JsonResponse
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient, DjangoRequestFactory
from rest_framework import status
from django.contrib.auth import get_user_model
import time
import re

User = get_user_model()

USERNAME_REGEX = r'^(?![0-9_.-])(?![_.-])[a-z](?:[a-z0-9]|[_.-](?![_.-])){2,29}[a-z0-9]$'

class AuthenticationURLTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.valid_email = "testuser@example.com"
        cls.valid_username = "testuser"
        cls.valid_password = "TestPassword123"
        cls.user = User.objects.create_user(
            email=cls.valid_email,
            username=cls.valid_username,
            password=cls.valid_password
        )
        cls.client = APIClient()

    def get_tokens(self, email=None, password=None):
        data = {
            "email": email or self.valid_email,
            "password": password or self.valid_password
        }
        url = "/auth/api/login/"
        response = self.client.post(url, data, format="json")
        return response

    # --- Registration Tests ---
    def test_register_valid(self):
        url = "/auth/api/register/"
        data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "NewPass123"
        }
        start = time.time()
        response = self.client.post(url, data, format="json")
        elapsed = time.time() - start
        self.assertEqual(response.status_code, status.HTTP_201_CREATED) #type: ignore
        self.assertIn("access", response.data) #type: ignore
        self.assertIn("refresh", response.data) #type: ignore
        self.assertLess(elapsed, 1.5, "Registration is too slow")

    def test_register_duplicate_email(self):
        url = "/auth/api/register/"
        data = {
            "username": "anotheruser",
            "email": self.valid_email,
            "password": "AnotherPass123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) #type: ignore

    def test_register_duplicate_username(self):
        url = "/auth/api/register/"
        data = {
            "username": self.valid_username,
            "email": "uniqueemail@example.com",
            "password": "AnotherPass123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) #type: ignore

    def test_register_invalid_email(self):
        url = "/auth/api/register/"
        data = {
            "username": "validuser",
            "email": "notanemail",
            "password": "ValidPass123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) #type: ignore

    def test_register_invalid_username(self):
        url = "/auth/api/register/"
        data = {
            "username": "1invalid",
            "email": "validemail2@example.com",
            "password": "ValidPass123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) #type: ignore

    def test_register_missing_fields(self):
        url = "/auth/api/register/"
        data = {
            "username": "",
            "email": "",
            "password": ""
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) #type: ignore

    # --- Login Tests ---
    def test_login_valid(self):
        response = self.get_tokens()
        self.assertEqual(response.status_code, status.HTTP_200_OK) #type: ignore
        self.assertIn("access", response.data) #type: ignore
        self.assertIn("refresh", response.data) #type: ignore

    def test_login_invalid_password(self):
        response = self.get_tokens(password="WrongPassword")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED) #type: ignore

    def test_login_invalid_email(self):
        response = self.get_tokens(email="wrong@example.com")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # type: ignore

    def test_login_missing_fields(self):
        url = "/auth/api/login/"
        response = self.client.post(url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # type: ignore

    # --- Token Refresh Tests ---
    def test_token_refresh_valid(self):
        tokens = self.get_tokens().data #type: ignore
        url = "/auth/api/token/refresh/"
        response = self.client.post(url, {"refresh": tokens["refresh"]}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # type: ignore
        self.assertIn("access", response.data)  # type: ignore

    def test_token_refresh_invalid(self):
        url = "/auth/api/token/refresh/"
        response = self.client.post(url, {"refresh": "invalidtoken"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # type: ignore

    # --- Token Verify Tests ---
    def test_token_verify_valid(self):
        tokens = self.get_tokens().data #type: ignore
        url = "/auth/api/token/verify/"
        response = self.client.post(url, {"token": tokens["access"]}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # type: ignore

    def test_token_verify_invalid(self):
        url = "/auth/api/token/verify/"
        response = self.client.post(url, {"token": "invalidtoken"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # type: ignore

    # --- Change Password Tests ---
    def test_change_password_valid(self):
        tokens = self.get_tokens().data #type: ignore
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        url = "/auth/api/user/changepass/"
        data = {
            "old_password": self.valid_password,
            "new_password": "ChangedPass123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # type: ignore
        self.assertIn("message", response.data)  # type: ignore
        # Try logging in with new password
        self.client.credentials()
        login_response = self.get_tokens(password="ChangedPass123")
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)  # type: ignore

    def test_change_password_wrong_old(self):
        tokens = self.get_tokens().data #type: ignore
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        url = "/auth/api/user/changepass/"
        data = {
            "old_password": "WrongOldPass",
            "new_password": "AnotherPass123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # type: ignore

    def test_change_password_missing_fields(self):
        tokens = self.get_tokens().data #type: ignore
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        url = "/auth/api/user/changepass/"
        data = {
            "old_password": "",
            "new_password": ""
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # type: ignore

    def test_change_password_unauthenticated(self):
        url = "/auth/api/user/changepass/"
        data = {
            "old_password": self.valid_password,
            "new_password": "ShouldNotWork123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # type: ignore

    # --- Protected Test Endpoint ---
    def test_protected_test_authenticated(self):
        tokens = self.get_tokens().data #type: ignore
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        url = "/auth/api/test/protected/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # type: ignore
        self.assertIn("message", response.data)  # type: ignore
        self.assertEqual(response.data["message"][1], str(self.user.id))  # type: ignore
        self.assertEqual(response.data["message"][2], self.user.username)  # type: ignore

    def test_protected_test_unauthenticated(self):
        url = "/auth/api/test/protected/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # type: ignore

    def test_protected_test_invalid_token(self):
        self.client.credentials(HTTP_AUTHORIZATION="Bearer invalidtoken")
        url = "/auth/api/test/protected/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # type: ignore

    # --- Performance/Load Tests ---
    def test_register_performance_under_load(self):
        url = "/auth/api/register/"
        usernames = [f"user{i}" for i in range(10)]
        emails = [f"user{i}@example.com" for i in range(10)]
        times = []
        for i in range(10):
            data = {
                "username": usernames[i],
                "email": emails[i],
                "password": "LoadTestPass123"
            }
            start = time.time()
            response = self.client.post(url, data, format="json")
            elapsed = time.time() - start
            times.append(elapsed)
            self.assertIn(response.status_code, [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST])  # type: ignore
        avg_time = sum(times) / len(times)
        self.assertLess(avg_time, 2.0, "Average registration time under load is too high")

    def test_login_performance_under_load(self):
        url = "/auth/api/login/"
        times = []
        for _ in range(10):
            start = time.time()
            response = self.client.post(url, {"email": self.valid_email, "password": self.valid_password}, format="json")
            elapsed = time.time() - start
            times.append(elapsed)
            self.assertEqual(response.status_code, status.HTTP_200_OK)  # type: ignore
        avg_time = sum(times) / len(times)
        self.assertLess(avg_time, 1.5, "Average login time under load is too high")

    # --- Security/Strictness ---
    def test_username_regex_enforced(self):
        url = "/auth/api/register/"
        invalid_usernames = ["1bad", "-bad", "_bad", ".bad", "a"*32, "ab", "bad..user", "bad__user", "bad--user"]
        for uname in invalid_usernames:
            data = {
                "username": uname,
                "email": f"{uname}@example.com",
                "password": "ValidPass123"
            }
            response = self.client.post(url, data, format="json")
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # type: ignore

    def test_email_validator_enforced(self):
        url = "/auth/api/register/"
        invalid_emails = ["plainaddress", "@missingusername.com", "username@.com", "username@com", "username@domain..com"]
        for email in invalid_emails:
            data = {
                "username": "validuser",
                "email": email,
                "password": "ValidPass123"
            }
            response = self.client.post(url, data, format="json")
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # type: ignore
