
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from jwtauthentication import settings
from django.utils.text import slugify
from django.utils.crypto import get_random_string

# Create your models here.

ADMIN_ROLE_VALUE = 1
USER_ROLE_VALUE = 2

ROLE_CHOICES = ((ADMIN_ROLE_VALUE, "ADMIN_USER"), (USER_ROLE_VALUE, "NORMAL_USER"))


class CustomUserManager(BaseUserManager):
    """
    Class for customizing the User Model objects manager class
    """

    def create_superuser(self, email, password, **other_fields):

        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)
        other_fields.setdefault('user_role', settings.ADMIN_ROLE_VALUE)

        return self.create_user(email, password, **other_fields)

    def create_user(self, email, password=None, **other_fields):
        other_fields.setdefault('user_role', settings.USER_ROLE_VALUE)
        if not email:
            raise ValueError('You must provide an email address')

        email = self.normalize_email(email)
        user = self.model(email=email, **other_fields)
        if password:
            user.set_password(password)
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin):
    """
    Model class for User Table
    """
    email = models.EmailField(unique=True, blank=False)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    phone_number = models.CharField(max_length=50, blank=True, unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    slug_value = models.SlugField(blank=True, null=True, unique=True)
    user_role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        ordering = ['-id']

    def _get_unique_slug(self):
        slug = slugify(get_random_string(length=32))
        unique_slug = slug
        num = 1
        while User.objects.filter(slug_value=unique_slug).exists():
            unique_slug = '{}-{}'.format(slug, num)
            num += 1
        return unique_slug

    def save(self, *args, **kwargs):
        # Checking if model instance is created (new entry)
        if not self.slug_value:
            self.slug_value = self._get_unique_slug()
            # Check for user if created as superuser directly
            if self.is_superuser:
                self.is_staff = True
            else:
                self.is_staff = False
            # Checking if the user is an admin
            if self.user_role == settings.ADMIN_ROLE_VALUE:
                self.is_staff = True
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email
