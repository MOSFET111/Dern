from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
# Custom User Manager
class UsersManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(username, email, password, **extra_fields)

# User Model
class Users(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UsersManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username

# Technician Model
class Technetion(models.Model):
    ROLES = (
        ('technician', 'Technician'),
        ('admin', 'Admin'),
    )
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=20, choices=ROLES, default='technician')
    is_active = models.BooleanField(default=True)

    # Add this property
    @property
    def is_authenticated(self):
        return True  # Always return True for authenticated technicians

    def __str__(self):
        return self.name

# Custom Token Model for Technetion
class TechnetionToken(models.Model):
    technician = models.OneToOneField(Technetion, on_delete=models.CASCADE, related_name='auth_token')
    key = models.CharField(max_length=40, unique=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.key


class BusinessToken(models.Model):
    business = models.OneToOneField('Business', on_delete=models.CASCADE, related_name='auth_token')
    key = models.CharField(max_length=40, unique=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.key


class Business(models.Model):
    business_name = models.CharField(max_length=255, unique=True)
    business_address = models.CharField(max_length=255)
    business_email = models.EmailField(unique=True)
    business_phone = models.CharField(max_length=15, unique=True)
    password = models.CharField(max_length=128)  # Store hashed passwords
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.business_name

    def set_password(self, password):
        self.password = make_password(password)  # Hash the password

    def check_password(self, password):
        return check_password(password, self.password)  # Verify the password

    # Add this property
    @property
    def is_authenticated(self):
        return True  # Always return True for authenticated businesses


# Requests Model

class Requests(models.Model):
    REQUEST_TYPES = (
        ('user', 'User'),
        ('business', 'Business'),
    )
    REQUEST_STATES = (
        ('pending', 'Pending'),
        ('on_progress', 'On Progress'),
        ('finished', 'Finished'),
    )

    user = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='user_requests', null=True, blank=True)  # Optional for businesses
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name='business_requests', null=True, blank=True)  # Optional for regular users
    description = models.TextField()
    pickup_address = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now)
    when_available = models.DateTimeField(default=timezone.now)
    is_done = models.BooleanField(default=False)
    technician = models.ManyToManyField(Technetion, blank=True, related_name='assigned_requests')
    repair_completion_date = models.DateTimeField(null=True, blank=True)
    email = models.EmailField(blank=True, null=True)  # Optional field
    phone = models.CharField(max_length=15, blank=True, null=True)  # Optional field
    request_type = models.CharField(max_length=10, choices=REQUEST_TYPES, default='user')  # New field
    # New field to store the state
    request_state = models.CharField(max_length=20, choices=REQUEST_STATES, default='pending')


    def save(self, *args, **kwargs):
        # Save the instance first to generate an ID before checking the ManyToMany relationship
        super().save(*args, **kwargs)

        # Now you can check the ManyToMany field safely
        if self.technician.exists():
            self.request_state = 'on_progress'
        elif not self.is_done:
            self.request_state = 'pending'
        else:
            self.request_state = 'finished'

        # Save again if request_state is updated
        super().save(update_fields=['request_state'])

    def __str__(self):
        return f"Request: {self.description} by {self.user.username if self.user else self.business.business_name}"


# History Model
class History(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='request_history', null=True, blank=True)
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name='request_history', null=True, blank=True)
    request = models.ForeignKey(Requests, on_delete=models.CASCADE, related_name='history_entry')
    completion_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Request: {self.request.description}, User: {self.user.username if self.user else 'None'}, Business: {self.business.business_name if self.business else 'None'}"

    class Meta:
        verbose_name = "History Entry"
        verbose_name_plural = "History Entries"
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['business']),
            models.Index(fields=['request']),
        ]
        ordering = ['-completion_date']
