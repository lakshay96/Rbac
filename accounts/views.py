from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from .models import User, Role, Permission, AuditLog
from .serializers import UserSerializer, RoleSerializer, PermissionSerializer, AuditLogSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication

from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import Role, Permission, User
from .serializers import RoleSerializer, PermissionSerializer, UserSerializer

class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def assign_roles(self, request, pk=None):
        user = self.get_object()
        roles = request.data.get('roles', [])
        user.roles.set(Role.objects.filter(id__in=roles))
        user.save()
        return Response({"status": "roles assigned"}, status=status.HTTP_200_OK)

    def assign_permissions(self, request, pk=None):
        user = self.get_object()
        permissions = request.data.get('permissions', [])
        user.permissions.set(Permission.objects.filter(id__in=permissions))
        user.save()
        return Response({"status": "permissions assigned"}, status=status.HTTP_200_OK)


# Role Management: Retrieve and create roles
class RoleView(APIView):
    authentication_classes = [TokenAuthentication]  # Add TokenAuthentication
    permission_classes = [IsAuthenticated]  # Restrict access to authenticated users

    def get(self, request):
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "message": "Role created successfully"}, status=status.HTTP_201_CREATED)
        return Response({"success": False, "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# Permission Management: Create and list permissions
class PermissionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "message": "Permission created successfully"}, status=status.HTTP_201_CREATED)
        return Response({"success": False, "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# User Management: Create users and list users
class UserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.prefetch_related('roles').all()
        serializer = UserSerializer(users, many=True)
        return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "message": "User created successfully"}, status=status.HTTP_201_CREATED)
        return Response({"success": False, "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# Assign roles to a user
class UserRoleAssignmentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        roles = request.data.get("roles", [])
        if not roles:
            return Response({"success": False, "message": "Roles are required"}, status=status.HTTP_400_BAD_REQUEST)

        user.roles.set(roles)
        user.save()
        return Response({"success": True, "message": "Roles assigned successfully"}, status=status.HTTP_200_OK)


# Access Validation: Check if a user has permission to perform an action on a resource
class AccessValidationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = request.data.get("user_id")
        action = request.data.get("action")
        resource = request.data.get("resource")

        try:
            user = User.objects.get(id=user_id)
            has_permission = any(
                perm.action == action and perm.resource == resource
                for role in user.roles.all()
                for perm in role.permissions.all()
            )

            AuditLog.objects.create(user=user, action=action, resource=resource, outcome=has_permission)
            return Response({"success": has_permission}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"success": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)


# Audit Log Management: Retrieve access logs
class AuditLogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logs = AuditLog.objects.all()
        serializer = AuditLogSerializer(logs, many=True)
        return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)


# Assign permissions to roles (only Admin should have permission to assign)
class RolePermissionAssignmentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, role_id):
        role = get_object_or_404(Role, id=role_id)
        permissions = request.data.get("permissions", [])
        if not permissions:
            return Response({"success": False, "message": "Permissions are required"}, status=status.HTTP_400_BAD_REQUEST)

        role.permissions.set(permissions)
        role.save()
        return Response({"success": True, "message": "Permissions assigned successfully"}, status=status.HTTP_200_OK)


# Role-based Access Control Views
class AdminRolePermissionAssignmentView(RolePermissionAssignmentView):
    def post(self, request, role_id):
        user = request.user
        if not user.roles.filter(name="Admin").exists():
            return Response({"success": False, "message": "Permission denied. Only Admin can assign permissions."}, status=status.HTTP_403_FORBIDDEN)
        
        return super().post(request, role_id)


# Example of permission validation
class ExampleAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.has_perm("view_example"):
            return Response({"success": True, "message": "Access granted."}, status=status.HTTP_200_OK)
        return Response({"success": False, "message": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
