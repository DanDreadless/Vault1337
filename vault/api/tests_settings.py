"""
Tests for the staff-only Settings API endpoints and default role seeding.
  GET/POST/PATCH/DELETE /api/v1/admin/users/
  GET/POST/PATCH/DELETE /api/v1/admin/roles/
  GET                   /api/v1/admin/permissions/
"""
from django.contrib.auth.models import Group, Permission, User
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken


def _jwt(user: User) -> dict:
    """Return Authorization header for a given user."""
    token = RefreshToken.for_user(user)
    return {'HTTP_AUTHORIZATION': f'Bearer {str(token.access_token)}'}


class SettingsUserAPITests(TestCase):
    """Tests for /api/v1/admin/users/"""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username='staffuser', password='staffpass1', is_staff=True
        )
        self.regular = User.objects.create_user(
            username='regularuser', password='regularpass1', is_staff=False
        )
        self.list_url = '/api/v1/admin/users/'

    # --- Access control ---

    def test_list_users_requires_auth(self):
        resp = self.client.get(self.list_url)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_users_requires_staff(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.regular).access_token)}')
        resp = self.client.get(self.list_url)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_users_staff_ok(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.get(self.list_url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIsInstance(resp.data, list)
        usernames = [u['username'] for u in resp.data]
        self.assertIn('staffuser', usernames)
        self.assertIn('regularuser', usernames)

    def test_list_users_response_shape(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.get(self.list_url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIsInstance(resp.data, list)
        user = next(u for u in resp.data if u['username'] == 'regularuser')
        for field in ('id', 'username', 'email', 'is_staff', 'is_active', 'roles'):
            self.assertIn(field, user, f"Missing field: {field}")

    # --- Create ---

    def test_create_user(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.post(self.list_url, {
            'username': 'newuser', 'email': 'new@example.com',
            'password': 'newpassword1', 'is_staff': False,
        }, format='json')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data['username'], 'newuser')
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_create_user_duplicate_username(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.post(self.list_url, {
            'username': 'regularuser', 'password': 'anotherpass1',
        }, format='json')
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_user_short_password(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.post(self.list_url, {
            'username': 'shortpw', 'password': 'abc',
        }, format='json')
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    # --- Update ---

    def test_update_user(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        url = f'{self.list_url}{self.regular.id}/'
        resp = self.client.patch(url, {'is_active': False}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.regular.refresh_from_db()
        self.assertFalse(self.regular.is_active)

    # --- Delete ---

    def test_delete_user(self):
        target = User.objects.create_user(username='todelete', password='deletepass1')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.delete(f'{self.list_url}{target.id}/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(username='todelete').exists())

    def test_delete_self_rejected(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.delete(f'{self.list_url}{self.staff.id}/')
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    # --- Set password ---

    def test_set_password(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        url = f'{self.list_url}{self.regular.id}/set_password/'
        resp = self.client.post(url, {'password': 'newpassword99'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.regular.refresh_from_db()
        self.assertTrue(self.regular.check_password('newpassword99'))

    def test_set_password_too_short(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        url = f'{self.list_url}{self.regular.id}/set_password/'
        resp = self.client.post(url, {'password': 'short'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


class SettingsRoleAPITests(TestCase):
    """Tests for /api/v1/admin/roles/"""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username='staffuser', password='staffpass1', is_staff=True
        )
        self.regular = User.objects.create_user(
            username='regularuser', password='regularpass1', is_staff=False
        )
        self.list_url = '/api/v1/admin/roles/'

    def test_list_roles_requires_staff(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.regular).access_token)}')
        resp = self.client.get(self.list_url)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_roles_staff_ok(self):
        Group.objects.create(name='Analysts')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.get(self.list_url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIsInstance(resp.data, list)
        names = [r['name'] for r in resp.data]
        self.assertIn('Analysts', names)

    def test_list_roles_response_shape(self):
        Group.objects.create(name='TestRole')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.get(self.list_url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIsInstance(resp.data, list)
        role = next(r for r in resp.data if r['name'] == 'TestRole')
        for field in ('id', 'name', 'permissions', 'user_count'):
            self.assertIn(field, role, f"Missing field: {field}")

    def test_create_role(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.post(self.list_url, {'name': 'NewRole', 'permission_ids': []}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data['name'], 'NewRole')
        self.assertTrue(Group.objects.filter(name='NewRole').exists())

    def test_create_role_user_count_zero(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.post(self.list_url, {'name': 'EmptyRole', 'permission_ids': []}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data['user_count'], 0)

    def test_update_role_name(self):
        group = Group.objects.create(name='OldName')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.patch(f'{self.list_url}{group.id}/', {'name': 'NewName'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        group.refresh_from_db()
        self.assertEqual(group.name, 'NewName')

    def test_delete_role(self):
        group = Group.objects.create(name='ToDelete')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.delete(f'{self.list_url}{group.id}/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Group.objects.filter(name='ToDelete').exists())

    def test_user_count_reflects_members(self):
        group = Group.objects.create(name='WithMember')
        self.regular.groups.add(group)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.get(f'{self.list_url}{group.id}/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data['user_count'], 1)


class DefaultRoleTests(TestCase):
    """Verify the default Staff and User roles are seeded correctly."""

    # The migration runs automatically as part of test database setup,
    # so both groups should already exist when these tests run.

    def test_staff_role_exists(self):
        self.assertTrue(Group.objects.filter(name='Staff').exists())

    def test_user_role_exists(self):
        self.assertTrue(Group.objects.filter(name='User').exists())

    _ALL_CUSTOM = frozenset({
        'upload_sample', 'download_sample', 'delete_sample', 'run_tools',
        'manage_tags', 'manage_iocs', 'enrich_iocs', 'manage_yara',
        'use_intel', 'export_stix', 'vt_enrich', 'mb_lookup', 'add_comments',
    })
    _USER_EXCLUDED = frozenset({'delete_sample', 'manage_yara'})

    def test_staff_role_has_all_custom_permissions(self):
        staff = Group.objects.get(name='Staff')
        codenames = set(staff.permissions.values_list('codename', flat=True))
        self.assertEqual(codenames, self._ALL_CUSTOM)

    def test_staff_role_has_no_django_crud_permissions(self):
        staff = Group.objects.get(name='Staff')
        codenames = set(staff.permissions.values_list('codename', flat=True))
        for auto in ('add_file', 'change_file', 'delete_file', 'view_file'):
            self.assertNotIn(auto, codenames)

    def test_user_role_excludes_admin_permissions(self):
        user_group = Group.objects.get(name='User')
        codenames = set(user_group.permissions.values_list('codename', flat=True))
        self.assertNotIn('delete_sample', codenames)
        self.assertNotIn('manage_yara', codenames)

    def test_user_role_has_analyst_permissions(self):
        user_group = Group.objects.get(name='User')
        codenames = set(user_group.permissions.values_list('codename', flat=True))
        expected = self._ALL_CUSTOM - self._USER_EXCLUDED
        self.assertEqual(codenames, expected)

    def test_user_role_permission_count(self):
        user_group = Group.objects.get(name='User')
        # 13 total minus 2 excluded = 11
        self.assertEqual(
            user_group.permissions.filter(codename__in=self._ALL_CUSTOM).count(), 11
        )


class SettingsPermissionsAPITests(TestCase):
    """Tests for GET /api/v1/admin/permissions/"""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username='staffuser', password='staffpass1', is_staff=True
        )
        self.regular = User.objects.create_user(
            username='regularuser', password='regularpass1', is_staff=False
        )
        self.url = '/api/v1/admin/permissions/'

    def test_requires_staff(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.regular).access_token)}')
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_returns_list(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIsInstance(resp.data, list)

    def test_response_shape(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        # Only vault-app permissions should be returned
        for perm in resp.data:
            self.assertIn('id', perm)
            self.assertIn('codename', perm)
            self.assertIn('name', perm)

    def test_only_custom_permissions_returned(self):
        """Endpoint returns only our 13 custom permissions, not Django CRUD ones."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(RefreshToken.for_user(self.staff).access_token)}')
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        returned_codenames = {p['codename'] for p in resp.data}
        # None of Django's auto-generated permissions should appear
        for auto in ('add_file', 'change_file', 'delete_file', 'view_file',
                     'add_ioc', 'change_ioc', 'delete_ioc', 'view_ioc'):
            self.assertNotIn(auto, returned_codenames)
        # All our custom permissions should be present
        self.assertEqual(len(resp.data), 13)
