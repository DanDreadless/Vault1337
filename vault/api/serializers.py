from django.conf import settings
from django.contrib.auth.models import Group, Permission as AuthPermission, User
from rest_framework import serializers
from vault.models import AnalysisResult, File, IOC, Comment, Profile


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

    tool = serializers.CharField()
    sub_tool = serializers.CharField(required=False, allow_blank=True, default='')
    password = serializers.CharField(required=False, allow_blank=True, default='', write_only=True)

    def validate_tool(self, value):
        if value not in self._VALID_TOOLS:
            raise serializers.ValidationError(f"Unknown tool '{value}'.")
        return value


# ---------------------------------------------------------------------------
# Settings / user management (staff-only)
# ---------------------------------------------------------------------------

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

    def update(self, instance, validated_data):
        groups = validated_data.pop('groups', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if groups is not None:
            instance.groups.set(groups)
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
        return user


class SetPasswordSerializer(serializers.Serializer):
    """Serializer for staff-initiated password reset."""

    password = serializers.CharField(write_only=True, min_length=8)
