import uuid

from django.db import models
from django.contrib.auth.models import User

# Create your models here.
from django.utils import timezone


class LoginTrackerModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    session_id = models.UUIDField(default=uuid.uuid4, editable=False, null=True)
    date_created = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return str(self.session_id)