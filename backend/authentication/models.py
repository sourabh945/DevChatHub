import re
import uuid
from django.db import models
from django.contrib.auth.models import BaseUserManager as _BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.core.exceptions import ValidationError, PermissionDenied
from django.core.validators import validate_email
from django.conf import settings

## globals
username_regex = settings.USERNAME_REGEX

# Create your models managers here.

class BaseUserManager(_BaseUserManager):

    """Base User Manager for the authentications"""

    def username_validator(self, username):
        """Validate the username of the user"""
        try:
            if not re.match(username_regex, username):
                raise ValidationError("Invalid username")
        except Exception as err:
            raise err

    def email_validator(self, email):
        """Validates the email address"""
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError("Invalid email address")
        except Exception as err:
            raise err


    def create_user(self, email, username, password, **extra_fields):
        """
        Create and return a regular user with email and password
        """

        if not email:
            raise ValidationError("Email address is required")
        if not username:
            raise ValidationError("Username is required")
        if not password:
            raise ValidationError("Password is required")

        self.username_validator(username)
        self.email_validator(email)
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, **extra):
        raise PermissionDenied("No one can create the super user.")




# Create your models here.

class User(AbstractBaseUser, PermissionsMixin):
    """
    custom user model using email and the unique identitier
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True)
    username = models.CharField(max_length=50, unique=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)

    # Set email as the username field
    USERNAME_FIELD = 'email'

    # Required fields when creating user
    REQUIRED_FIELDS = ['username']

    # Assign the custom manager
    objects = BaseUserManager()

    class Meta: #type:ignore
        db_table = 'auth_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self): #type:ignore
        return self.email

    def change_password(self, old_password, new_password):
        if self.check_password(old_password):
            self.set_password(new_password)
            self.save()
        else:
            raise ValidationError("Old password is incorrect")
