from rest_framework.permissions import BasePermission


class IsStaffUser(BasePermission):
    """Allows access only to staff/admin users. Mirrors @staff_member_required."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_staff)


def vault_perm(codename):
    """
    Return a DRF permission *class* that requires a specific vault permission.

    Usage in permission_classes:
        permission_classes = [IsAuthenticated, vault_perm('upload_sample')]

    Usage in get_permissions():
        return [IsAuthenticated(), vault_perm('view_sample')()]

    Django superusers bypass all has_perm() checks automatically.
    The three-role model:
      ReadOnly  — view_sample + view_ioc + view_yara only
      Analyst   — all permissions except delete_sample / manage_yara
      Admin     — all permissions + is_staff=True (management page access)
    """
    class _VaultPerm(BasePermission):
        _perm = f'vault.{codename}'
        message = f'You do not have the "{codename}" permission required for this action.'

        def has_permission(self, request, view):
            return bool(
                request.user
                and request.user.is_authenticated
                and request.user.has_perm(self._perm)
            )

    _VaultPerm.__name__ = f'VaultPerm_{codename}'
    _VaultPerm.__qualname__ = f'VaultPerm_{codename}'
    return _VaultPerm
