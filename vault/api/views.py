import logging
import os
import re
import tempfile

import py7zr
import pyzipper
import requests
from django.conf import settings
from django.db.models import Q
from django.http import FileResponse
from dotenv import load_dotenv, set_key
from rest_framework import mixins, status
from rest_framework.decorators import action
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet, ModelViewSet, ViewSet

from vault.models import File, IOC
from vault.utils import (
    get_abuseipdb_data,
    get_file_path_from_sha256,
    get_shodan_data,
    get_spur_data,
    get_vt_data,
    hash_sample,
    is_safe_url,
    run_sub_tool as _run_sub_tool,
    run_tool as _run_tool,
    validate_sha256,
)
from vault.workbench.save_sample import SaveSample

from .permissions import IsStaffUser
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
        # For update/partial_update we need the full queryset so any IOC can
        # be found by pk regardless of its current true_or_false value.
        if self.action != 'list':
            return IOC.objects.all()

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


# -------------------- YARA RULES --------------------

class YaraViewSet(ViewSet):
    """
    CRUD for YARA rule files on disk.

    list:    GET  /api/v1/yara/
    create:  POST /api/v1/yara/
    retrieve: GET  /api/v1/yara/{pk}/
    update:  PUT  /api/v1/yara/{pk}/
    destroy: DELETE /api/v1/yara/{pk}/

    Rules are stored as plain .yar files in settings.YARA_RULES_DIR.
    The {pk} lookup value is the rule filename without the .yar extension.
    """

    permission_classes = [IsAuthenticated]

    def _rules_dir(self):
        return settings.YARA_RULES_DIR

    def _rule_path(self, name):
        """Return the absolute path for a rule given its bare name (no extension)."""
        safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', name)
        return os.path.join(self._rules_dir(), f'{safe_name}.yar')

    def list(self, request, *args, **kwargs):
        """Return a list of all .yar rule names and their content."""
        rules_dir = self._rules_dir()
        if not os.path.isdir(rules_dir):
            return Response([], status=status.HTTP_200_OK)

        rules = []
        for fname in sorted(os.listdir(rules_dir)):
            if not fname.endswith('.yar'):
                continue
            full_path = os.path.join(rules_dir, fname)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='replace') as fh:
                    content = fh.read()
            except OSError as e:
                logger.warning("Could not read YARA rule %s: %s", fname, e)
                content = ''
            rules.append({'name': fname[:-4], 'filename': fname, 'content': content})

        return Response(rules)

    def retrieve(self, request, *args, **kwargs):
        """GET /api/v1/yara/{name}/ — return name + content of one rule."""
        name = kwargs.get('pk', '')
        rule_path = self._rule_path(name)
        if not os.path.isfile(rule_path):
            return Response({'detail': 'Rule not found.'}, status=status.HTTP_404_NOT_FOUND)

        with open(rule_path, 'r', encoding='utf-8', errors='replace') as fh:
            content = fh.read()

        return Response({'name': name, 'filename': f'{name}.yar', 'content': content})

    def create(self, request, *args, **kwargs):
        """POST /api/v1/yara/ — create a new .yar file. Body: {name, content}."""
        name = request.data.get('name', '').strip()
        content = request.data.get('content', '')

        if not name:
            return Response({'detail': 'name is required.'}, status=status.HTTP_400_BAD_REQUEST)

        safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', name)
        if not safe_name:
            return Response({'detail': 'Invalid rule name.'}, status=status.HTTP_400_BAD_REQUEST)

        rule_path = self._rule_path(safe_name)
        if os.path.isfile(rule_path):
            return Response(
                {'detail': f'Rule "{safe_name}" already exists.'},
                status=status.HTTP_409_CONFLICT,
            )

        os.makedirs(self._rules_dir(), exist_ok=True)
        with open(rule_path, 'w', encoding='utf-8') as fh:
            fh.write(content)

        return Response(
            {'name': safe_name, 'filename': f'{safe_name}.yar', 'content': content},
            status=status.HTTP_201_CREATED,
        )

    def update(self, request, *args, **kwargs):
        """PUT /api/v1/yara/{name}/ — overwrite an existing rule's content."""
        name = kwargs.get('pk', '')
        rule_path = self._rule_path(name)

        if not os.path.isfile(rule_path):
            return Response({'detail': 'Rule not found.'}, status=status.HTTP_404_NOT_FOUND)

        content = request.data.get('content', '')
        with open(rule_path, 'w', encoding='utf-8') as fh:
            fh.write(content)

        return Response({'name': name, 'filename': f'{name}.yar', 'content': content})

    def destroy(self, request, *args, **kwargs):
        """DELETE /api/v1/yara/{name}/ — delete a .yar file."""
        name = kwargs.get('pk', '')
        rule_path = self._rule_path(name)

        if not os.path.isfile(rule_path):
            return Response({'detail': 'Rule not found.'}, status=status.HTTP_404_NOT_FOUND)

        os.remove(rule_path)
        return Response(status=status.HTTP_204_NO_CONTENT)


# -------------------- IP INTELLIGENCE --------------------

class IPCheckView(APIView):
    """
    POST /api/v1/intel/ip/

    Body: { "ip": "1.2.3.4" }
    Returns aggregated data from AbuseIPDB, Spur, VirusTotal, and Shodan.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        ip = request.data.get('ip', '').strip()
        if not ip:
            return Response({'detail': 'ip is required.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'ip': ip,
            'abuseipdb': get_abuseipdb_data(ip),
            'spur': get_spur_data(ip),
            'virustotal': get_vt_data(ip),
            'shodan': get_shodan_data(ip),
        })


# -------------------- API KEY MANAGER --------------------

_ENV_PATH = os.path.join(settings.BASE_DIR, '.env')
_API_KEY_NAMES = ('VT_KEY', 'MALWARE_BAZAAR_KEY', 'ABUSEIPDB_KEY', 'SPUR_KEY', 'SHODAN_KEY')


class APIKeyView(APIView):
    """
    GET  /api/v1/admin/keys/ — return masked API key values (staff only).
    POST /api/v1/admin/keys/ — update a single key. Body: {key, value}.
    """

    permission_classes = [IsStaffUser]

    def _mask(self, value):
        """Show only the last 4 characters of a key."""
        if not value or value == 'paste_your_api_key_here':
            return '(not set)'
        return f'{"*" * (len(value) - 4)}{value[-4:]}' if len(value) > 4 else '****'

    def get(self, request):
        keys = {name: self._mask(os.getenv(name, '')) for name in _API_KEY_NAMES}
        return Response(keys)

    def post(self, request):
        key = request.data.get('key', '').strip()
        value = request.data.get('value', '').strip()

        if not key or not value:
            return Response(
                {'detail': 'Both key and value are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if key not in _API_KEY_NAMES:
            return Response(
                {'detail': f'Unknown key "{key}". Allowed: {", ".join(_API_KEY_NAMES)}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        set_key(_ENV_PATH, key, value)
        load_dotenv(dotenv_path=_ENV_PATH, override=True)
        return Response({'status': 'updated', 'key': key})


# -------------------- VT DOWNLOAD --------------------

class VTDownloadView(APIView):
    """
    POST /api/v1/files/vt-download/

    Body: { "sha256": "<64-char hex>", "tags": "optional,csv" }
    Downloads the file from VirusTotal and stores it in sample storage.
    Requires a VirusTotal Enterprise API key.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        sha256_raw = request.data.get('sha256', '').strip()
        tags_raw = request.data.get('tags', '')

        if not sha256_raw:
            return Response({'detail': 'sha256 is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            clean_sha256 = validate_sha256(sha256_raw)
        except ValueError:
            return Response({'detail': 'Invalid SHA256 hash.'}, status=status.HTTP_400_BAD_REQUEST)

        vtkey = os.getenv('VT_KEY')
        if not vtkey or vtkey == 'paste_your_api_key_here':
            return Response(
                {'detail': 'VirusTotal API key not configured.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        url = f"https://www.virustotal.com/api/v3/files/{clean_sha256}/download"
        headers = {"accept": "application/json", "x-apikey": vtkey}
        try:
            vt_response = requests.get(url, headers=headers, timeout=30)
        except Exception as e:
            logger.error("VT download request failed for %s: %s", clean_sha256, e)
            return Response({'detail': 'Error contacting VirusTotal.'}, status=status.HTTP_502_BAD_GATEWAY)

        if vt_response.status_code == 403:
            return Response(
                {'detail': 'VirusTotal Enterprise licence required to download files.'},
                status=status.HTTP_403_FORBIDDEN,
            )
        if vt_response.status_code != 200:
            return Response(
                {'detail': f'VirusTotal returned {vt_response.status_code}.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        dest = os.path.join(settings.SAMPLE_STORAGE_DIR, clean_sha256)
        if os.path.isfile(dest):
            if File.objects.filter(sha256=clean_sha256).exists():
                return Response({'detail': 'File already exists.'}, status=status.HTTP_409_CONFLICT)

        try:
            with open(dest, 'wb') as fh:
                fh.write(vt_response.content)
        except OSError as e:
            logger.error("Could not write VT download for %s: %s", clean_sha256, e)
            return Response({'detail': 'Error saving file.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        tags = [t.strip() for t in tags_raw.split(',') if t.strip()]
        tags.append('virustotal')

        if not File.objects.filter(sha256=clean_sha256).exists():
            from vault.utils import hash_sample
            md5, sha1, sha256_hash, sha512, magic_byte, size, mime = hash_sample(dest)
            file_obj = File(
                name=clean_sha256,
                size=size,
                magic=magic_byte,
                mime=mime,
                md5=md5,
                sha1=sha1,
                sha256=clean_sha256,
                sha512=sha512,
                uploaded_by=request.user,
            )
            file_obj.save()
            for tag in tags:
                file_obj.tag.add(tag)
            file_obj.save()

        instance = File.objects.get(sha256=clean_sha256)
        return Response(
            FileSerializer(instance, context={'request': request}).data,
            status=status.HTTP_201_CREATED,
        )


# -------------------- MB DOWNLOAD --------------------

class MBDownloadView(APIView):
    """
    POST /api/v1/files/mb-download/

    Body: { "sha256": "<64-char hex>", "tags": "optional,csv" }
    Downloads the file from MalwareBazaar and stores it in sample storage.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        sha256_raw = request.data.get('sha256', '').strip()
        tags_raw = request.data.get('tags', '')

        if not sha256_raw:
            return Response({'detail': 'sha256 is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            clean_sha256 = validate_sha256(sha256_raw)
        except ValueError:
            return Response({'detail': 'Invalid SHA256 hash.'}, status=status.HTTP_400_BAD_REQUEST)

        if File.objects.filter(sha256=clean_sha256).exists():
            return Response({'detail': 'File already exists.'}, status=status.HTTP_409_CONFLICT)

        mbkey = os.getenv('MALWARE_BAZAAR_KEY', '')
        samples_dir = settings.SAMPLE_STORAGE_DIR
        zip_dest = os.path.join(samples_dir, f'zip_{clean_sha256}')

        try:
            headers = {'API-KEY': mbkey} if mbkey else {}
            data = {'query': 'get_file', 'sha256_hash': clean_sha256}
            mb_response = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data=data,
                timeout=30,
                headers=headers,
                allow_redirects=True,
            )
        except Exception as e:
            logger.error("MB download request failed for %s: %s", clean_sha256, e)
            return Response({'detail': 'Error contacting MalwareBazaar.'}, status=status.HTTP_502_BAD_GATEWAY)

        if mb_response.status_code != 200:
            return Response(
                {'detail': f'MalwareBazaar returned {mb_response.status_code}.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        try:
            with open(zip_dest, 'wb') as fh:
                fh.write(mb_response.content)

            with pyzipper.AESZipFile(zip_dest) as zf:
                extracted = zf.filelist[0]
                unzipped_name = extracted.filename
                zf.extract(extracted, path=samples_dir, pwd=b'infected')
            os.remove(zip_dest)
        except Exception as e:
            logger.error("MB unzip failed for %s: %s", clean_sha256, e)
            if os.path.isfile(zip_dest):
                os.remove(zip_dest)
            return Response({'detail': f'Error extracting archive: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Fetch metadata from MB
        filename = clean_sha256
        content_type = 'application/octet-stream'
        try:
            info_resp = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data={'query': 'get_info', 'hash': clean_sha256},
                timeout=15,
                headers=headers,
            )
            if info_resp.status_code == 200:
                info = info_resp.json()
                filename = info['data'][0]['file_name']
                content_type = info['data'][0]['file_type_mime']
        except Exception as e:
            logger.warning("Could not fetch MB metadata for %s: %s", clean_sha256, e)

        full_path = os.path.join(samples_dir, unzipped_name)
        from vault.utils import hash_sample
        md5, sha1, sha256_hash, sha512, magic_byte, size, mime = hash_sample(full_path)

        final_path = os.path.join(samples_dir, sha256_hash)
        os.rename(full_path, final_path)

        tags = [t.strip() for t in tags_raw.split(',') if t.strip()]
        tags.append('malwarebazaar')

        file_obj = File(
            name=filename,
            size=size,
            magic=magic_byte,
            mime=content_type,
            md5=md5,
            sha1=sha1,
            sha256=sha256_hash,
            sha512=sha512,
            uploaded_by=request.user,
        )
        file_obj.save()
        for tag in tags:
            file_obj.tag.add(tag)
        file_obj.save()

        return Response(
            FileSerializer(file_obj, context={'request': request}).data,
            status=status.HTTP_201_CREATED,
        )
