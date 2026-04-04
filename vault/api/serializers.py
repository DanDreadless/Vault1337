from django.conf import settings
from django.contrib.auth.models import Group, Permission as AuthPermission, User
from rest_framework import serializers
from vault.models import AnalysisResult, AuditLog, File, IOC, Comment, Profile


class TagListSerializerField(serializers.Field):
    """Reads/writes taggit tags as a plain list of tag name strings."""

    def to_representation(self, value):
        return list(value.values_list('name', flat=True))

    def to_internal_value(self, data):
        if not isinstance(data, list):
            raise serializers.ValidationError('Expected a list of tag strings.')
        if not all(isinstance(item, str) for item in data):
            raise serializers.ValidationError('All tag values must be strings.')
        return data


class UserSerializer(serializers.ModelSerializer):
    """Read-only serializer for the Django User model."""

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'is_staff')
        read_only_fields = ('id', 'username', 'email', 'is_staff')


class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for user self-registration."""

    password = serializers.CharField(write_only=True, min_length=8)
    password2 = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'password2')
        read_only_fields = ('id',)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({'password2': 'Passwords do not match.'})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password'],
        )
        return user


class IOCSerializer(serializers.ModelSerializer):
    """Serializer for IOC indicators."""

    class Meta:
        model = IOC
        fields = (
            'id', 'type', 'value', 'true_or_false', 'manually_overridden',
            'enriched', 'enriched_at', 'created_date',
        )
        read_only_fields = ('enriched', 'enriched_at')


class FileSerializer(serializers.ModelSerializer):
    """List-view serializer for File objects."""

    uploaded_by = serializers.StringRelatedField(read_only=True)
    tags = TagListSerializerField(source='tag', read_only=True)

    class Meta:
        model = File
        fields = (
            'id', 'name', 'size', 'magic', 'mime',
            'md5', 'sha1', 'sha256', 'sha512',
            'created_date', 'uploaded_by', 'tags',
            'simhash', 'simhash_input_size',
        )


class CommentSerializer(serializers.ModelSerializer):
    """Serializer for file comments."""

    author = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Comment
        fields = ('id', 'title', 'text', 'comment_type', 'author', 'created_date', 'file')
        read_only_fields = ('id', 'file', 'author', 'created_date')


class FileDetailSerializer(FileSerializer):
    """Detail-view serializer for File objects — includes nested IOCs, comments and VT data."""

    iocs = IOCSerializer(many=True, read_only=True)
    comments = CommentSerializer(many=True, read_only=True, source='comment_set')

    class Meta(FileSerializer.Meta):
        fields = FileSerializer.Meta.fields + ('iocs', 'comments', 'vt_data', 'mb_data', 'attack_mapping')


class ProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile data."""

    class Meta:
        model = Profile
        fields = ('job_role', 'department', 'profile_image')


class UserProfileSerializer(serializers.ModelSerializer):
    """Combined user + profile serializer for the /auth/user/ endpoint."""

    profile = ProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'is_staff', 'profile')
        read_only_fields = ('id', 'username', 'is_staff')


class FileUploadSerializer(serializers.Serializer):
    """Serializer for the file upload endpoint."""

    file = serializers.FileField()
    tags = serializers.CharField(required=False, allow_blank=True, default='')
    unzip = serializers.BooleanField(default=False)
    password = serializers.CharField(required=False, allow_blank=True, default='', write_only=True)

    def validate_file(self, value):
        max_bytes = getattr(settings, 'MAX_UPLOAD_SIZE_BYTES', 200 * 1024 * 1024)
        if value.size > max_bytes:
            max_mb = max_bytes // (1024 * 1024)
            raise serializers.ValidationError(
                f'File too large. Maximum upload size is {max_mb} MB.'
            )
        return value


class FetchURLSerializer(serializers.Serializer):
    """Serializer for the fetch-URL endpoint."""

    url = serializers.URLField()
    tags = serializers.CharField(required=False, allow_blank=True, default='')


class AnalysisResultSerializer(serializers.ModelSerializer):
    """Serializer for persisted tool run results."""

    ran_by = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = AnalysisResult
        fields = ('id', 'tool', 'sub_tool', 'output', 'ran_at', 'ran_by')
        read_only_fields = fields


class ToolRunSerializer(serializers.Serializer):
    """Serializer for the run-tool endpoint."""

    _VALID_TOOLS = {
        'hex-viewer', 'exiftool', 'extract-ioc', 'run-yara',
        'zip_extractor', 'disassembler', 'shellcode', 'view-image',
        'lief-parser', 'oletools', 'email-parser', 'strings',
        'pdf-parser', 'pefile', 'macho-tool', 'decode', 'dotnet', 'apk-tool',
    }

    # Per-tool allowlist of valid sub_tool values.  Tools not listed here do
    # not accept a sub_tool (passing one is rejected).
    _VALID_SUB_TOOLS: dict[str, frozenset[str]] = {
        'disassembler': frozenset({'x86', 'x64', 'arm32', 'arm64'}),
        'shellcode':    frozenset({'x86', 'x64', 'arm32', 'arm64'}),
        'lief-parser':  frozenset({
            'dos_header', 'rich_header', 'pe_header', 'entrypoint', 'sections',
            'imports', 'sigcheck', 'checkentropy', 'exports', 'imphash',
            'overlay', 'rich_hash', 'elf_header', 'elf_sections', 'elf_symbols',
            'elf_suspicious', 'elf_packer', 'elf_segments', 'elf_info',
        }),
        'oletools':     frozenset({'olevba', 'oleid', 'olemeta', 'oleobj', 'rtfobj', 'oledump'}),
        'email-parser': frozenset({'email_headers', 'email_body', 'download_attachments', 'url_extractor'}),
        'strings':      frozenset({'ascii', 'utf-8', 'latin-1', 'utf-16', 'utf-32', 'wide'}),
        'pdf-parser':   frozenset({'metadata', 'render', 'content', 'images', 'urls', 'js', 'embedded', 'suspicious', 'structure'}),
        'pefile':       frozenset({
            'imphash', 'rich_hash', 'resources', 'version_info', 'overlay',
            'suspicious_imports', 'section_entropy', 'packer', 'timestamp',
            'anti_vm', 'codesign',
        }),
        'macho-tool':   frozenset({'header', 'load_commands', 'dylibs', 'exports', 'symbols', 'sections', 'codesig', 'entitlements', 'encryption'}),
        'decode':       frozenset({'base64', 'base64_url', 'hex', 'rot13', 'xor_brute'}),
        'dotnet':       frozenset({'metadata', 'imports', 'strings', 'resources', 'obfuscator'}),
        'apk-tool':     frozenset({'manifest', 'components', 'intents', 'certificate', 'strings', 'urls', 'suspicious'}),
    }

    tool = serializers.CharField()
    sub_tool = serializers.CharField(required=False, allow_blank=True, default='')
    password = serializers.CharField(required=False, allow_blank=True, default='', write_only=True)

    def validate_tool(self, value):
        if value not in self._VALID_TOOLS:
            raise serializers.ValidationError(f"Unknown tool '{value}'.")
        return value

    def validate(self, attrs):
        tool = attrs.get('tool', '')
        sub_tool = attrs.get('sub_tool', '')
        if not sub_tool:
            return attrs
        valid = self._VALID_SUB_TOOLS.get(tool)
        if valid is None:
            raise serializers.ValidationError(
                {'sub_tool': f"Tool '{tool}' does not accept a sub_tool."}
            )
        if sub_tool not in valid:
            raise serializers.ValidationError(
                {'sub_tool': f"Unknown sub_tool '{sub_tool}' for tool '{tool}'. Valid options: {', '.join(sorted(valid))}."}
            )
        return attrs


# ---------------------------------------------------------------------------
# Settings / user management (staff-only)
# ---------------------------------------------------------------------------

# The group whose membership is kept in sync with User.is_staff.
# Change this if the Admin group is named differently in your database.
_ADMIN_GROUP_NAME = 'Admin'


def _sync_staff_with_admin_group(user, groups_being_set):
    """
    Bidirectional sync between User.is_staff and membership in the Admin group.

    Called after the groups (or is_staff) of a user are changed.
    Superusers are never demoted — their is_staff is left untouched.

    groups_being_set:
      list/queryset — the new group set was just applied; derive is_staff from it.
      None          — groups were not changed; is_staff was changed; sync the group.
    """
    if user.is_superuser:
        return

    admin_grp = Group.objects.filter(name=_ADMIN_GROUP_NAME).first()
    if admin_grp is None:
        return  # No Admin group exists yet — nothing to sync.

    if groups_being_set is not None:
        should_be_staff = any(
            (g.pk if hasattr(g, 'pk') else g) == admin_grp.pk
            for g in groups_being_set
        )
        if should_be_staff != user.is_staff:
            user.is_staff = should_be_staff
            user.save(update_fields=['is_staff'])
    else:
        # is_staff changed; make group membership match.
        if user.is_staff:
            user.groups.add(admin_grp)
        else:
            user.groups.remove(admin_grp)

class PermissionSerializer(serializers.ModelSerializer):
    """Read-only serializer for auth.Permission objects."""

    class Meta:
        model = AuthPermission
        fields = ('id', 'codename', 'name')


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for Group objects used as roles."""

    permissions = PermissionSerializer(many=True, read_only=True)
    permission_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        write_only=True,
        queryset=AuthPermission.objects.filter(content_type__app_label='vault'),
        source='permissions',
        required=False,
    )
    user_count = serializers.SerializerMethodField()

    class Meta:
        model = Group
        fields = ('id', 'name', 'permissions', 'permission_ids', 'user_count')

    def get_user_count(self, obj):
        return obj.user_set.count()

    def create(self, validated_data):
        perms = validated_data.pop('permissions', [])
        group = Group.objects.create(**validated_data)
        group.permissions.set(perms)
        return group

    def update(self, instance, validated_data):
        perms = validated_data.pop('permissions', None)
        instance.name = validated_data.get('name', instance.name)
        instance.save()
        if perms is not None:
            instance.permissions.set(perms)
        return instance


class UserAdminSerializer(serializers.ModelSerializer):
    """Staff-only serializer for full user management."""

    roles = RoleSerializer(many=True, read_only=True, source='groups')
    role_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        write_only=True,
        queryset=Group.objects.all(),
        source='groups',
        required=False,
    )
    profile = ProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'is_staff', 'is_active',
            'date_joined', 'last_login', 'roles', 'role_ids', 'profile',
        )
        read_only_fields = ('id', 'username', 'date_joined', 'last_login')

    def to_representation(self, instance):
        """
        For staff users not yet explicitly in the Admin group (e.g. the original
        superuser or users promoted via the Django admin), inject the Admin group
        into the roles list so the management UI reflects their actual privilege.
        The context key 'admin_group' is populated by UserManagementViewSet to
        avoid a per-user database query.
        """
        data = super().to_representation(instance)
        if not instance.is_staff:
            return data
        admin_grp = self.context.get('admin_group')
        if admin_grp and not any(r['id'] == admin_grp.pk for r in data.get('roles', [])):
            data['roles'] = [RoleSerializer(admin_grp, context=self.context).data] + list(data['roles'])
        return data

    def update(self, instance, validated_data):
        groups = validated_data.pop('groups', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if groups is not None:
            instance.groups.set(groups)
            # Groups were updated — derive is_staff from Admin group membership.
            _sync_staff_with_admin_group(instance, groups)
        else:
            # No group change — but is_staff may have been toggled; sync the group.
            _sync_staff_with_admin_group(instance, None)
        return instance


class CreateUserAdminSerializer(serializers.Serializer):
    """Serializer for staff-initiated user creation."""

    username = serializers.CharField(max_length=150)
    email = serializers.EmailField(required=False, allow_blank=True, default='')
    password = serializers.CharField(write_only=True, min_length=8)
    is_staff = serializers.BooleanField(default=False)
    role_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Group.objects.all(), required=False,
    )

    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError('A user with that username already exists.')
        return value

    def create(self, validated_data):
        roles = validated_data.pop('role_ids', [])
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password'],
            is_staff=validated_data.get('is_staff', False),
        )
        user.groups.set(roles)
        # Sync is_staff ↔ Admin group on creation.
        _sync_staff_with_admin_group(user, roles)
        return user


class SetPasswordSerializer(serializers.Serializer):
    """Serializer for staff-initiated password reset."""

    password = serializers.CharField(write_only=True, min_length=8)


class AuditLogSerializer(serializers.ModelSerializer):
    """Read-only serializer for AuditLog entries."""

    class Meta:
        model = AuditLog
        fields = ('id', 'timestamp', 'username', 'action', 'target_type',
                  'target_id', 'detail', 'ip_address')
        read_only_fields = fields
