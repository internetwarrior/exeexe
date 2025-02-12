# C:\Users\user\Desktop\config\user\models.py
from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    email_verified = models.BooleanField(default=False)
