from django.db import models

class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name

class Permission(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name

class User(models.Model):
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    roles = models.ManyToManyField(Role, related_name="users")
    permissions = models.ManyToManyField(Permission, related_name="users", blank=True)

    def __str__(self):
        return self.username

# Define Role model
class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

# Define Permission model
class Permission(models.Model):
    action = models.CharField(max_length=100)
    resource = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.action} on {self.resource}"

# Define User model
class User(models.Model):
    username = models.CharField(max_length=50, unique=True)
    roles = models.ManyToManyField(Role, related_name="users")

    def __str__(self):
        return self.username

# Define AuditLog model
class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=100)
    resource = models.CharField(max_length=100)
    outcome = models.BooleanField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} attempted {self.action} on {self.resource}"
