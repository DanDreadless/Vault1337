from django.contrib.auth.models import User
from rest_framework import serializers
from vault.models import File, IOC, Comment, Profile


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
        fields = ('id', 'type', 'value', 'true_or_false', 'description', 'created_date')


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
        )


class FileDetailSerializer(FileSerializer):
    """Detail-view serializer for File objects — includes nested IOCs."""

    iocs = IOCSerializer(many=True, read_only=True)

    class Meta(FileSerializer.Meta):
        fields = FileSerializer.Meta.fields + ('iocs',)


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


class CommentSerializer(serializers.ModelSerializer):
    """Serializer for file comments."""

    class Meta:
        model = Comment
        fields = ('id', 'title', 'text', 'file')


class FileUploadSerializer(serializers.Serializer):
    """Serializer for the file upload endpoint."""

    file = serializers.FileField()
    tags = serializers.CharField(required=False, allow_blank=True, default='')
    unzip = serializers.BooleanField(default=False)
    password = serializers.CharField(required=False, allow_blank=True, default='', write_only=True)


class FetchURLSerializer(serializers.Serializer):
    """Serializer for the fetch-URL endpoint."""

    url = serializers.URLField()
    tags = serializers.CharField(required=False, allow_blank=True, default='')


class ToolRunSerializer(serializers.Serializer):
    """Serializer for the run-tool endpoint."""

    tool = serializers.CharField()
    sub_tool = serializers.CharField(required=False, allow_blank=True, default='')
    password = serializers.CharField(required=False, allow_blank=True, default='', write_only=True)
