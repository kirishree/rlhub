from django.db import models

# Create your models here.
# yourapp/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = (
        ('org-admin', 'Org Admin'),
        ('org-user', 'Org User'),
        ('admin', 'ADMIN'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='org-user')
    onboarding_org_name = models.CharField(max_length=100, blank=True, null=True, default='NA')
    onboarding_org_id = models.CharField(max_length=50, blank=True, null=True, default='NA')
    onboarding_user_id = models.CharField(max_length=100, blank=True, null=True, default='NA')
    onboarding_first_name = models.CharField(max_length=50, blank=True, null=True, default='NA')
    onboarding_last_name = models.CharField(max_length=100, blank=True, null=True, default='NA')
    subscription_till = models.CharField(max_length=100, blank=True, null=True, default='NA')
    REQUIRED_FIELDS = ['role', 'onboarding_org_name', 'onboarding_org_id', 'onboarding_user_id', 'onboarding_first_name', 'onboarding_last_name', 'subscription_till']




