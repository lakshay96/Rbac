from django.urls import path
from .views import RoleView, PermissionView, UserView, UserRoleAssignmentView, AccessValidationView, AuditLogView, RolePermissionAssignmentView, AdminRolePermissionAssignmentView, ExampleAPI
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RoleViewSet, PermissionViewSet, UserViewSet

router = DefaultRouter()
router.register(r'roles', RoleViewSet)
router.register(r'permissions', PermissionViewSet)
router.register(r'users', UserViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('users/<int:pk>/assign-roles/', UserViewSet.as_view({'post': 'assign_roles'})),
    path('users/<int:pk>/assign-permissions/', UserViewSet.as_view({'post': 'assign_permissions'})),
    path('roles/', RoleView.as_view(), name='role-list'),
    path('permissions/', PermissionView.as_view(), name='permission-list'),
    path('users/', UserView.as_view(), name='user-list'),
    path('users/<int:user_id>/assign-roles/', UserRoleAssignmentView.as_view(), name='user-assign-roles'),
    path('validate-access/', AccessValidationView.as_view(), name='access-validation'),
    path('audit-logs/', AuditLogView.as_view(), name='audit-logs'),
    path('roles/<int:role_id>/assign-permissions/', RolePermissionAssignmentView.as_view(), name='role-assign-permissions'),
    path('admin/roles/<int:role_id>/assign-permissions/', AdminRolePermissionAssignmentView.as_view(), name='admin-role-assign-permissions'),
    path('example-api/', ExampleAPI.as_view(), name='example-api'),
]
