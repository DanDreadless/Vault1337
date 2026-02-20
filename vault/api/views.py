import logging
import os
import re
import tempfile

import py7zr
import requests
from django.conf import settings
from django.db.models import Q
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework import mixins, status
from rest_framework.decorators import action
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet

from vault.models import File, IOC
from vault.utils import hash_sample
from vault.views import (
    get_file_path_from_sha256,
    is_safe_url,
    run_sub_tool as _run_sub_tool,
    run_tool as _run_tool,
    validate_sha256,
)
from vault.workbench.save_sample import SaveSample

from .serializers import (
    FetchURLSerializer,
    FileDetailSerializer,
    FileSerializer,
    FileUploadSerializer,
    IOCSerializer,
    ToolRunSerializer,
    UserCreateSerializer,
    UserProfileSerializer,
)

logger = logging.getLogger(__name__)


class RegisterView(CreateAPIView):
    """
    POST /api/v1/auth/register/

    Public endpoint — creates a new user account.
    Returns the new user's id and username (no password fields).
    """

    queryset = File.objects.none()
    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]

    def get_serializer(self, *args, **kwargs):
        kwargs.setdefault('context', self.get_serializer_context())
        return UserCreateSerializer(*args, **kwargs)


class UserDetailView(RetrieveUpdateAPIView):
    """
    GET  /api/v1/auth/user/ — return the authenticated user's profile.
    PATCH /api/v1/auth/user/ — update email or profile fields.
    """

    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class FileViewSet(ModelViewSet):
    """
    ViewSet for File objects.

    list:   GET  /api/v1/files/
    create: POST /api/v1/files/
    retrieve: GET  /api/v1/files/{id}/
    destroy:  DELETE /api/v1/files/{id}/

    Extra actions:
      download   GET  /api/v1/files/{id}/download/
      run_tool   POST /api/v1/files/{id}/run_tool/
      add_tag    POST /api/v1/files/{id}/add_tag/
      remove_tag POST /api/v1/files/{id}/remove_tag/
      fetch_url  POST /api/v1/files/fetch_url/
    """

    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'post', 'delete', 'head', 'options']

    def get_queryset(self):
        queryset = File.objects.all()
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(tag__name__icontains=search)
            ).distinct()
        return queryset

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return FileDetailSerializer
        if self.action == 'create':
            return FileUploadSerializer
        return FileSerializer

    def create(self, request, *args, **kwargs):
        """POST /api/v1/files/ — upload a new sample."""
        serializer = FileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        file = serializer.validated_data['file']
        tags = serializer.validated_data.get('tags', '')
        unzip = 'on' if serializer.validated_data.get('unzip', False) else ''
        password = serializer.validated_data.get('password', '') or None

        save_file = SaveSample(file, tags, unzip, password, request.user)
        result = save_file.save_file_and_update_model()

        if result == 'File already exists':
            return Response({'detail': 'File already exists.'}, status=status.HTTP_409_CONFLICT)

        if not isinstance(result, tuple) or result[0] != 'success':
            return Response({'detail': str(result)}, status=status.HTTP_400_BAD_REQUEST)

        sha256 = result[1]
        try:
            instance = File.objects.get(sha256=sha256)
        except File.DoesNotExist:
            return Response(
                {'detail': 'File not found after upload.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        out_serializer = FileSerializer(instance, context={'request': request})
        return Response(out_serializer.data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        """DELETE /api/v1/files/{id}/ — delete a sample and its file on disk."""
        instance = self.get_object()

        try:
            clean_sha256 = validate_sha256(str(instance.sha256))
        except ValueError:
            return Response({'detail': 'Invalid SHA256 hash.'}, status=status.HTTP_400_BAD_REQUEST)

        file_path = os.path.join(settings.SAMPLE_STORAGE_DIR, clean_sha256)
        if os.path.exists(file_path):
            os.remove(file_path)

        tags_to_check = list(instance.tag.all())
        instance.tag.clear()
        instance.delete()
        for tag in tags_to_check:
            if not tag.taggit_taggeditem_items.exists():
                tag.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """GET /api/v1/files/{id}/download/ — download sample as password-protected 7z."""
        file_instance = self.get_object()
        storage_location = settings.SAMPLE_STORAGE_DIR
        original_file_path = os.path.join(storage_location, file_instance.sha256)

        if not os.path.exists(original_file_path):
            return Response({'detail': 'File not found on disk.'}, status=status.HTTP_404_NOT_FOUND)

        tmp = tempfile.NamedTemporaryFile(suffix='.7z', delete=False)
        tmp_path = tmp.name
        tmp.close()

        try:
            with py7zr.SevenZipFile(tmp_path, 'w', password='infected') as zf:
                zf.write(original_file_path, arcname=file_instance.sha256)

            f = open(tmp_path, 'rb')
            response = FileResponse(
                f,
                as_attachment=True,
                filename=f'{file_instance.sha256}.7z',
                content_type='application/x-7z-compressed',
            )
            response._resource_closers.append(lambda p=tmp_path: os.unlink(p))
            return response
        except Exception as e:
            os.unlink(tmp_path)
            logger.error("Error creating 7z archive for file %s: %s", file_instance.sha256, e)
            return Response(
                {'detail': f'Error creating archive: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=True, methods=['post'])
    def run_tool(self, request, pk=None):
        """POST /api/v1/files/{id}/run_tool/ — run an analysis tool against a sample."""
        file_instance = self.get_object()

        serializer = ToolRunSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tool = serializer.validated_data['tool']
        sub_tool = serializer.validated_data.get('sub_tool', '')
        password = serializer.validated_data.get('password', '') or None

        file_path = get_file_path_from_sha256(file_instance.sha256)
        if not file_path:
            return Response({'detail': 'File not found on disk.'}, status=status.HTTP_404_NOT_FOUND)

        if sub_tool:
            output = _run_sub_tool(tool, sub_tool, file_path)
        else:
            output = _run_tool(tool, file_path, password, request.user)

        if output.endswith("' not supported."):
            return Response({'detail': output}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'tool': tool, 'sub_tool': sub_tool, 'output': output})

    @action(detail=True, methods=['post'])
    def add_tag(self, request, pk=None):
        """POST /api/v1/files/{id}/add_tag/ — add a tag to a file."""
        file_instance = self.get_object()
        tag_name = request.data.get('tag')
        if not tag_name:
            return Response({'detail': 'No tag provided.'}, status=status.HTTP_400_BAD_REQUEST)

        file_instance.tag.add(tag_name)
        tags = list(file_instance.tag.values_list('name', flat=True))
        return Response({'tags': tags})

    @action(detail=True, methods=['post'])
    def remove_tag(self, request, pk=None):
        """POST /api/v1/files/{id}/remove_tag/ — remove a tag from a file."""
        file_instance = self.get_object()
        tag_name = request.data.get('tag')
        if not tag_name:
            return Response({'detail': 'No tag provided.'}, status=status.HTTP_400_BAD_REQUEST)

        if tag_name not in file_instance.tag.values_list('name', flat=True):
            return Response(
                {'detail': f'Tag "{tag_name}" not found on this file.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        file_instance.tag.remove(tag_name)
        file_instance.save()
        tags = list(file_instance.tag.values_list('name', flat=True))
        return Response({'tags': tags})

    @action(detail=False, methods=['post'])
    def fetch_url(self, request):
        """POST /api/v1/files/fetch_url/ — fetch a URL and store the response as a sample."""
        serializer = FetchURLSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        url = serializer.validated_data['url']
        tags_str = serializer.validated_data.get('tags', '')
        tags = tags_str.split(',') if tags_str else []
        tags.append('URL')

        if not is_safe_url(url):
            return Response(
                {'detail': 'Invalid or disallowed URL.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            resp = requests.get(url, stream=True, timeout=5)
        except Exception as e:
            logger.error("Error fetching URL %s: %s", url, e)
            return Response({'detail': 'Error fetching URL.'}, status=status.HTTP_400_BAD_REQUEST)

        if resp.status_code != 200:
            return Response(
                {'detail': f'Remote server returned {resp.status_code}.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        samples_dir = settings.SAMPLE_STORAGE_DIR
        filename = ''
        content_type_header = resp.headers.get('Content-Type', 'application/octet-stream')

        if 'Content-Disposition' in resp.headers:
            content_disposition = resp.headers['Content-Disposition']
            if 'filename' in content_disposition:
                filename = content_disposition.split('filename=')[1]
                filename_pattern = re.compile(r'[^a-zA-Z0-9-_]')
                safe_filename = filename_pattern.sub('', filename)
                file_path = os.path.join(samples_dir, safe_filename)
                with open(file_path, 'wb') as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)
        else:
            source_code = resp.text
            filename_pattern = re.compile(r'[^a-zA-Z0-9-_]')
            safe_filename = filename_pattern.sub('', url)
            if not safe_filename:
                return Response(
                    {'detail': 'Error: Invalid URL produces empty filename.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            file_path = os.path.join(samples_dir, f'webpage_{safe_filename}.html')
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(source_code)

        md5, sha1, sha256, sha512, magic_byte, size, mime = hash_sample(file_path)
        name = filename if filename else url
        if filename:
            mime = content_type_header

        if File.objects.filter(sha256=sha256).exists():
            os.remove(file_path)
            return Response({'detail': 'File already exists.'}, status=status.HTTP_409_CONFLICT)

        os.rename(file_path, os.path.join(samples_dir, sha256))

        vault_item = File(
            name=name,
            size=size,
            magic=magic_byte,
            mime=mime,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sha512=sha512,
            uploaded_by=request.user,
        )
        vault_item.save()
        for tag in tags:
            vault_item.tag.add(tag.strip())
        vault_item.save()

        out_serializer = FileSerializer(vault_item, context={'request': request})
        return Response(out_serializer.data, status=status.HTTP_201_CREATED)


class IOCViewSet(mixins.ListModelMixin, mixins.UpdateModelMixin, GenericViewSet):
    """
    ViewSet for IOC indicators.

    list:   GET   /api/v1/iocs/
    update: PATCH /api/v1/iocs/{id}/
    """

    permission_classes = [IsAuthenticated]
    serializer_class = IOCSerializer
    http_method_names = ['get', 'patch', 'head', 'options']

    def get_queryset(self):
        filter_option = self.request.query_params.get('filter', 'true')
        search = self.request.query_params.get('search')

        if filter_option == 'false':
            queryset = IOC.objects.filter(true_or_false=False)
        elif filter_option == 'both':
            queryset = IOC.objects.all()
        else:
            queryset = IOC.objects.filter(true_or_false=True)

        if search:
            queryset = queryset.filter(
                Q(value__icontains=search) | Q(files__name__icontains=search)
            ).distinct()

        return queryset.order_by('id')
