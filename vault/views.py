# Other Imports
import os
import re
import vt
import pyzipper
import py7zr
import datetime
import requests
import json
import shodan
from dotenv import load_dotenv
# Vault imports
from .models import File
from vault.workbench import lief_parser_tool, ole_tool, strings, display_hex, pdftool, exif, save_sample, extract_ioc, runyara, mail_handler
from .utils import hash_sample
from .forms import ToolForm, UserCreationForm, LoginForm, YaraRuleForm
# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth import authenticate, login
from django.http import HttpResponse, Http404
from django.db.models import Q, Count
from django.http import JsonResponse
from django.contrib import messages
from taggit.models import Tag



# Load environment variables from .env file
load_dotenv()

# -------------------- BASIC PAGE VIEWS --------------------
def index(request):
    # Render the HTML template index.html with the data in the context variable
    vault = File.objects.all()  # Example queryset
    num_entries = vault.count()
    return render(request, 'vault/index.html', {'num_entries': num_entries})

def home(request):
    # Render the HTML template home.html with the data in the context variable
    return render(request, 'vault/home.html')

def about(request):
    # Render the HTML template about.html with the data in the context variable
    return render(request, 'vault/about.html')

def upload(request):
    # Render the HTML template upload.html with the data in the context variable
    return render(request, 'vault/upload.html')

# -------------------- TAG VIEWS --------------------
@csrf_protect
@require_POST
def add_tag(request, item_id):
    try:
        data = json.loads(request.body)
        tag_name = data.get('tag')
        item = get_object_or_404(File, id=item_id)
        tag, created = Tag.objects.get_or_create(name=tag_name)
        item.tag.add(tag)
        tags = list(item.tag.values_list('name', flat=True))
        return JsonResponse({'success': True, 'tags': tags})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@csrf_protect
@require_POST
def remove_tag(request, item_id):
    try:
        import json
        data = json.loads(request.body)
        tag_to_remove = data.get('tag')

        if not tag_to_remove:
            return JsonResponse({'success': False, 'error': 'No tag provided'}, status=400)

        # Retrieve the item by ID
        item = get_object_or_404(File, id=item_id)

        # Check if the tag exists and remove it
        if tag_to_remove in item.tag.values_list('name', flat=True):
            item.tag.remove(tag_to_remove)
            item.save()
            # Return updated list of tags
            updated_tags = item.tag.values_list('name', flat=True)
            return JsonResponse({'success': True, 'tags': list(updated_tags)})
        else:
            return JsonResponse({'success': False, 'error': f'{tag_to_remove} tag not found'}, status=404)

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
# -------------------- YARA RULE VIEWS --------------------
rules_path = 'vault/yara-rules/'

def yara(request):
    if request.method == 'POST':
        form = YaraRuleForm(request.POST)
        if form.is_valid():
            file_name = form.cleaned_data['file_name']
            sanitized_name = re.sub(r'[^\w\-_\. ]', '_', file_name)
            file_name = sanitized_name  + '.yar'
            rule_content = form.cleaned_data['rule_content'].replace('\r\n', '\n')
            file_path = os.path.join(rules_path, file_name)
            
            # Save the YARA rule to the specified path
            with open(file_path, 'w', newline='\n') as f:
                f.write(rule_content)
            
            messages.success(request, f'YARA rule "{file_name}" saved successfully!')
            return redirect('yara')
    else:
        form = YaraRuleForm()

    # Get the list of YARA files in the directory
    yara_files = []
    if os.path.exists(rules_path):
        yara_files = [f for f in os.listdir(rules_path) if f.endswith('.yar')]

    return render(request, 'vault/yara.html', {'form': form, 'yara_files': yara_files})

def edit_yara_rule(request, file_name):
    file_path = os.path.join(rules_path, file_name)
    
    if request.method == 'POST':
        form = YaraRuleForm(request.POST)
        if form.is_valid():
            rule_content = form.cleaned_data['rule_content'].replace('\r\n', '\n')
            with open(file_path, 'w', newline='\n') as f:
                f.write(rule_content)
            messages.success(request, f'YARA rule "{file_name}" updated successfully!')
            return redirect('yara')
    else:
        with open(file_path, 'r') as f:
            rule_content = f.read()
        form = YaraRuleForm(initial={'file_name': file_name.replace('.yar', ''), 'rule_content': rule_content})

    # Get the list of YARA files in the directory
    yara_files = []
    if os.path.exists(rules_path):
        yara_files = [f for f in os.listdir(rules_path) if f.endswith('.yar')]

    return render(request, 'vault/edit_yara_rule.html', {'form': form, 'file_name': file_name, 'yara_files': yara_files})

def delete_yara_rule(request, file_name):
    file_path = os.path.join(rules_path, file_name)
    if os.path.exists(file_path):
        os.remove(file_path)
        messages.success(request, f'YARA rule "{file_name}" deleted successfully!')
    else:
        messages.error(request, f'YARA rule "{file_name}" not found!')
    return redirect('yara')



# -------------------- VAULT VIEWS --------------------
def vault_table(request):
    if request.method == 'GET':
        search_query = request.GET.get('search')
        
        if search_query:
            # Filter items by filename or tags
            vault_items = File.objects.filter(
                Q(name__icontains=search_query) | Q(tag__name__icontains=search_query)
            ).distinct()
        else:
            # Fetch all items if no search query is provided
            vault_items = File.objects.all()
        
        # Calculate tag frequencies across all files
        tag_frequencies = File.tag.through.objects.values('tag_id', 'tag__name').annotate(count=Count('tag_id')).order_by('-count')

        return render(request, 'vault/vault.html', {'vault': vault_items, 'tag_frequencies': tag_frequencies})
    else:
        return render(request, 'vault/vault.html', {'vault': File.objects.all()})

def delete_item(request, item_id):
    # Fetch the item from the database
    item = get_object_or_404(File, id=item_id)

    # TODO: Add permission check - will involve changes to File table to add owner field
    # Check if the user has permission to delete the item (optional)
    # Example: Check if the user is the owner of the item
    # if request.user != item.owner:
        # You can customize the permission logic according to your requirements
        # return redirect('vault_table')
    # Delete the associated file from the server
    
    # sanitize sha256
    sha256_pattern = re.compile(r'[^[a-fA-F0-9]{64}$]')
    clean_sha256 = sha256_pattern.sub('', str(item.sha256))

    file_path = f'vault/samples/{clean_sha256}'
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Get the tags associated with the item before clearing
    tags_to_check = list(item.tag.all())
    # Remove associated tags
    item.tag.clear()
    # Perform the deletion
    item.delete()
    # Check if any of the tags are no longer associated with any items
    for tag in tags_to_check:
        if not tag.taggit_taggeditem_items.exists():
            tag.delete()
    # Redirect to the vault table page after deletion
    return redirect('vault_table')

def download_zipped_sample(request, item_id):
    # Fetch the file from the database using the provided item_id
    try:
        file_instance = File.objects.get(id=item_id)
    except File.DoesNotExist:
        raise Http404("File does not exist")

    # Define the storage location and file paths
    storage_location = './vault/samples/'
    original_file_path = os.path.join(storage_location, file_instance.sha256)
    zipped_file_path = os.path.join(storage_location, f"{file_instance.sha256}.zip")

    # Check if the original file exists
    if not os.path.exists(original_file_path):
        raise Http404("Original file does not exist")

    # Zip the file with the password 'infected'
    with py7zr.SevenZipFile(zipped_file_path, 'w', password='infected') as zf:
        zf.write(original_file_path, arcname=file_instance.sha256)

    # Serve the zipped file as a download
    with open(zipped_file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/7z')
        response['Content-Disposition'] = f'attachment; filename="{file_instance.sha256}.7z"'
    
    # Optionally, clean up the zipped file after serving it
    os.remove(zipped_file_path)

    return response


# -------------------- TOOL VIEWS --------------------
def tool_view(request, item_id):
    item = get_object_or_404(File, pk=item_id)
    form_output = None
    if request.method == 'POST':
        form = ToolForm(request.POST)
        if form.is_valid():
            selected_tool = form.cleaned_data['tool']
            sub_tool = form.cleaned_data['sub_tool']

            # Retrieve SHA256 value from the selected item
            sha256_value = item.sha256

            # Use the SHA256 value to locate the corresponding file on the server
            file_path = get_file_path_from_sha256(sha256_value)

            if file_path:
                # Run the selected tool against the file
                if sub_tool:
                    output = run_sub_tool(selected_tool, sub_tool, file_path)
                    form_output = f"Output of '{selected_tool} / {sub_tool}' tool:\n\n{output}"
                else:
                    output = run_tool(selected_tool, file_path)
                    form_output = f"Output of '{selected_tool}' tool:\n\n{output}"
            else:
                form_output = f"File corresponding to SHA256 value not found on the server."

            # Redirect back to the same page with the fragment identifier
            # deepcode ignore ServerInformationExposure: <please specify a reason of ignoring this>, deepcode ignore XSS: <please specify a reason of ignoring this>
            return HttpResponse(form_output)
    else:
        form = ToolForm()
        form_output = None
    return HttpResponse(form_output)

def sample_detail(request, item_id):
    form_output = None
    form = ToolForm()
    item = get_object_or_404(File, pk=item_id)

    return render(request, 'sample.html', {'item': item, 'form': form})

def get_file_path_from_sha256(sha256_value):
    # sanitize sha256
    sha256_pattern = re.compile(r'[^[a-fA-F0-9]{64}$]')
    clean_sha256 = sha256_pattern.sub('', sha256_value)
    
    file_path = f'vault/samples/{clean_sha256}'
    # Check if the file exists
    if os.path.exists(file_path):
        return file_path
    else:
        return None

def run_tool(tool, file_path):
    
    if tool == 'hex-viewer':
        # Call the display_hex function to get hex output from the file
        try:
            output = display_hex.display_hex_with_ascii(file_path)
            return output
        except Exception as e:
            return f"Error getting hex output: {str(e)}"
    elif tool == 'pdf-parser':
        # Call the parse_pdf function to get PDF information from the file
        try:
            output = pdftool.extract_objects_from_pdf(file_path)
            return output
        except Exception as e:
            return f"Error getting PDF information: {str(e)}"
    elif tool == 'exiftool':
        # Call the get_exif_data function to get EXIF information from the file
        try:
            output = exif.get_exif_data(file_path)
            return output
        except Exception as e:
            return f"Error getting EXIF information: {str(e)}"
    elif tool == 'extract-ioc':
        # Call the extract_ioc function to get IOCs from the file
        try:
            output = extract_ioc.extract_iocs_from_file(file_path)
            return output
        except Exception as e:
            return f"Error extracting IOCs: {str(e)}"
    elif tool == 'run-yara':
        # Call the run_yara function to run YARA rules against the file
        try:
            output = runyara.run_yara(file_path)
            return output
        except Exception as e:
            return f"Error running YARA rules: {str(e)}"

    else:
        return f"Tool '{tool}' not supported."

def run_sub_tool(tool, sub_tool, file_path):
    # Example: Run the tool against the file
    if tool == 'lief-parser':
        # Call the lief_parser_tool function to get PE header information from the file
        try:
            output = lief_parser_tool.lief_parse_subtool(sub_tool, file_path)
            return output
        except Exception as e:
            return f"Error getting PE header information: {str(e)}"
    elif tool == 'oletools':
        # Call the ole_tool function to get OLE information from the file
        try:
            output = ole_tool.oletools_subtool_parser(sub_tool, file_path)
            return output
        except Exception as e:
            return f"Error checking for macros: {str(e)}"
    elif tool == 'email-parser':
        # Call the extract_email_headers function to get email headers from the file
        try:
            output = mail_handler.email_subtool_parser(sub_tool, file_path)
            return output
        except Exception as e:
            return f"Error parsing email: {str(e)}"
    elif tool == 'strings':
        # Call the get_strings function to get strings from the file
        try:
            output = strings.get_strings(file_path, sub_tool)
            return output
        except Exception as e:
            return f"Error getting strings: {str(e)}"
    else:
        return f"Tool '{tool}' not supported."
    
# -------------------- INDEX VIEWS --------------------
# todo: tidy this up and maybe move it to the utils.py file
# todo: include ability to unzip other archive types
def upload_file(request):
    if request.method == 'POST' and request.FILES['file']:
        uploaded_file = request.FILES['file']
        tags = request.POST.get('tags', '')
        if not tags:
            tags = None
        unzip = request.POST.get('unzip', '')  # Check if the 'unzip' checkbox is checked
        if not unzip:
            unzip = False
        password = request.POST.get('password', '')  # Get the password entered by the user
        if not password:
            password = None
        save_file = save_sample.SaveSample(uploaded_file, tags, unzip, password)
        message = save_file.save_file_and_update_model()
        if len(message) == 64:  # Check if the message is a SHA256 hash
            instance = File.objects.get(sha256=message)
            # Retrieve the id field from the instance
            id_value = instance.id
            return render(request, 'upload_success.html', {'file_name': message, 'id': id_value})
        else:
            return render(request, 'upload_error.html', {'error_message': message})
        # return render(request, 'upload_success.html', message)
    return render(request, 'index.html')

def get_webpage(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        tags = request.POST.get('tags', '')
        tags = tags = tags.split(',') if tags else []
        filename = ''
        if url:
            # Fetch the webpage
            try:
                # deepcode ignore Ssrf: <please specify a reason of ignoring this>
                response = requests.get(url, stream=True, timeout=5)
            except:
                return render(request, 'upload_error.html', {'error_message': 'Error fetching webpage'})
            
            if response.status_code != 200:
                return render(request, 'upload_error.html', {'error_message': f'response code: {response.status_code} - Error fetching webpage'})
            
            if 'Content-Disposition' in response.headers:
                content_disposition = response.headers['Content-Disposition']
                file_mime = response.headers['Content-Type']
                if 'filename' in content_disposition:
                    filename = content_disposition.split('filename=')[1]
                    # Define a regular expression pattern to match allowed characters
                    filename_pattern = re.compile(r'[^a-zA-Z0-9-_]')
                    # Sanitize the filename to create a safe filename
                    safe_filename = filename_pattern.sub('', filename)
                    # Path to save the downloaded file
                    file_path = f'vault/samples/{safe_filename}'
                    with open(file_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
            else:
                source_code = response.text
                # Save source code to a file

                # Define a regular expression pattern to match allowed characters
                filename_pattern = re.compile(r'[^a-zA-Z0-9-_]')

                # Sanitize the URL to create a safe filename
                safe_filename = filename_pattern.sub('', url)

                # Ensure that the filename is not empty
                if not safe_filename:
                    # Handle empty filename error
                    print("Error: Invalid URL")
                else:
                    # Construct the file path
                    file_path = f'vault/samples/webpage_{safe_filename}.html'

                    # Write the source code to the file
                    with open(file_path, 'w', encoding='utf-8') as file:
                        file.write(source_code)

            # Calculate hash values using a utility function
            md5, sha1, sha256, sha512, magic_byte, size, mime = hash_sample(file_path)

            # rename file to sha256
            final_file_name = sha256
            
            if filename:
                url = filename
                mime = file_mime

            os.rename(file_path, f'vault/samples/{final_file_name}')
            # Create a new VaultItem instance and save it to the database
            vault_item = File(
                name=url,
                size=size,
                magic=magic_byte,
                mime=mime,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                sha512=sha512,
            )
            if File.objects.filter(sha256=sha256).exists():
                return render(request, 'upload_error.html', {'error_message': 'File already exists'})
            else:
                vault_item.save()
                for tag in tags:
                    vault_item.tag.add(tag.strip())
                vault_item.save()
            instance = File.objects.get(sha256=sha256)
            # Retrieve the id field from the instance
            id_value = instance.id
            return render(request, 'upload_success.html', {'file_name': final_file_name, 'webpage': url, 'id': id_value})

    return render(request, 'index.html')

# -------------------- API VIEWS --------------------
# vt_download likely does not work as I need a premium account to download files from VirusTotal and check the code
def vt_download(request):
    sha256 = request.POST.get('sha256')
    tags = request.POST.get('tags', '')
    tags = tags = tags.split(',') if tags else []
    if sha256:
        # Load the VirusTotal API key from the .env file
        vtkey = os.getenv('VT_KEY')
        client = vt.Client(vtkey)

        file_path = f'vault/samples/{sha256}'
        if file_path:
            # Download the file from VirusTotal requires a premium account
            try:
                with open(file_path, 'wb') as f:
                    client.download_file(sha256, f)
                instance = File.objects.get(sha256=sha256)
                # Retrieve the id field from the instance
                id_value = instance.id
                return render(request, 'upload_success.html', {'file_name': sha256, 'id': id_value})
            except Exception as e:
                return render(request, 'upload_error.html', {'error_message': f'Error downloading file: {str(e)}'})
        else:
            return render(request, 'upload_error.html', {'error_message': f'File corresponding to SHA256 value not found on the server.'})

def mb_download(request):
    sha256 = request.POST.get('sha256')
    tags = request.POST.get('tags', '')
    tags = tags = tags.split(',') if tags else []
    if sha256:
        sha256_pattern = re.compile(r'[^[a-fA-F0-9]{64}$]')
        clean_sha256 = sha256_pattern.sub('', sha256)
        # Load the MalwareBazaar API key from the .env file
        mbkey = os.getenv('MALWARE_BAZAAR_KEY')
        downloaded_file = f'vault/samples/zip_{clean_sha256}'
        file_path = f'vault/samples/'
        if file_path:
            # Download the file from MalwareBazaar
            try:
                headers={'API-KEY': mbkey}
                data={'query': 'get_file', 'sha256_hash': sha256}
                response = requests.post(f'https://mb-api.abuse.ch/api/v1/', data=data, timeout=15, headers=headers, allow_redirects=True)
                if response.status_code == 200:
                    with open(downloaded_file, 'wb') as f:
                        f.write(response.content)
                    try:
                        with pyzipper.AESZipFile(downloaded_file) as zf:
                            extracted_file = zf.filelist[0]
                            unzipped_file = extracted_file.filename
                            zf.extract(extracted_file, path=file_path, pwd='infected'.encode())
                        os.remove(downloaded_file)
                    except Exception as e:
                        return render(request, 'upload_error.html', {'error_message': f'Error unzipping file2: {str(e)}'})
                    data={'query': 'get_info', 'hash': sha256}
                    try:
                        response = requests.post(f'https://mb-api.abuse.ch/api/v1/', data=data, timeout=15, headers=headers, allow_redirects=True)
                        if response.status_code == 200:
                            data = response.json()
                            filename = data['data'][0]['file_name']
                            content_type = data['data'][0]['file_type_mime']
                    except requests.exceptions.RequestException as e:
                        return render(request, 'upload_error.html', {'error_message': f'Error: {e}'})
                    
                    full_path = os.path.join(file_path, unzipped_file)
                    md5, sha1, sha256, sha512, magic_byte, size, mime = hash_sample(full_path)

                    file_obj = File(
                        name=filename,
                        size=size,
                        magic=magic_byte,
                        mime=content_type,
                        md5=md5,
                        sha1=sha1,
                        sha256=sha256,
                        sha512=sha512,
                    )
                    file_obj.save()
                    for tag in tags:
                        file_obj.tag.add(tag.strip())
                    file_obj.save()
                    # rename file to sha256
                    final_file_name = os.path.join(file_path, sha256)

                    os.rename(full_path, final_file_name)
                    instance = File.objects.get(sha256=sha256)
                    # Retrieve the id field from the instance
                    id_value = instance.id
                    return render(request, 'upload_success.html', {'file_name': sha256, 'id': id_value})
                else:
                    return render(request, 'upload_error.html', {'error_message': f'Error downloading file: {response.text}'})
            except Exception as e:
                return render(request, 'upload_error.html', {'error_message': f'Error downloading file: {str(e)}'})
        else:
            return render(request, 'upload_error.html', {'error_message': f'File corresponding to SHA256 value not found on the server.'})

def ip_check(request):
    if request.method == 'POST':
        ip = request.POST.get('ip')
        if ip:
            try:
                abuseip = get_abuseipdb_data(ip)
                spur = get_spur_data(ip)
                vt = get_vt_data(ip)
                shodan = get_shodan_data(ip)
                return render(request, 'vault/ip_check.html', {'ip': ip, 'ip_data': abuseip, 'spur_data': spur, 'vt_data': vt, 'shodan_data': shodan})
            except requests.exceptions.RequestException as e:
                return render(request, 'upload_error.html', {'error_message': f'Error: {e}'})
        else:
            return render(request, 'upload_error.html', {'error_message': 'No IP address provided'})
    return render(request, 'vault/ip_check.html')

def get_abuseipdb_data(ip):
    # Load the AbuseIPDB API key from the .env file
    abusekey = os.getenv('ABUSEIPDB_KEY')
    headers = {'Key': abusekey, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None

def get_spur_data(ip):
    # Load the Spur API key from the .env file
    spurkey = os.getenv('SPUR_KEY')
    headers = {'TOKEN': spurkey}
    response = requests.get(f'https://api.spur.us/v2/context/{ip}', headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None
    
def get_vt_data(ip):
    # Load the VirusTotal API key from the .env file
    vtkey = os.getenv('VT_KEY')
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": vtkey}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None
    
def get_shodan_data(ip):
    # Load the Shodan API key from the .env file
    shodankey = os.getenv('SHODAN_KEY')
    api = shodan.Shodan(shodankey)
    try:
        data = api.host(ip)
        return data
    except shodan.APIError as e:
        return f'Error: {e}'
    
# -------------------- USER VIEWS --------------------
# signup page
def user_signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('index')
    else:
        form = UserCreationForm()
    return render(request, 'registration/signup.html', {'form': form})

# login page
def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)    
                return redirect('home')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})
