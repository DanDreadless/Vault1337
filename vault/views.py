# Other Imports
import os
import re
import pyzipper
import py7zr
import datetime
import requests
import json
import shodan
from dotenv import load_dotenv, set_key
import base64
from io import BytesIO
# Vault imports
from .models import File, Profile, IOC
from vault.workbench import lief_parser_tool, ole_tool, strings, display_hex, pdftool, exif, save_sample, extract_ioc, runyara, mail_handler, extract, qr_decode
from .utils import hash_sample
from .forms import ToolForm, UserCreationForm, LoginForm, YaraRuleForm, APIKeyForm, UserForm, ProfileForm
# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth import authenticate, login
from django.http import HttpResponse, Http404
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.http import JsonResponse
from django.contrib import messages
from django.db.models import Sum
from django.conf import settings
from taggit.models import Tag



# Load environment variables from .env file
load_dotenv()
# -------------------- BASIC PAGE VIEWS --------------------   
def index(request):
    # Render the HTML template index.html with the data in the context variable
    vault = File.objects.all()  # Example queryset
    num_entries = vault.count()

    # Calculate the total size of all samples in the vault
    total_size_bytes = File.objects.aggregate(Sum('size'))['size__sum'] or 0
    total_size_mb = total_size_bytes / (1024 * 1024)  # Convert to megabytes
    
    context = {
        'num_entries': num_entries,
        'total_size_mb': total_size_mb,
    }
    
    return render(request, 'vault/index.html', context)

def home(request):
    # Render the HTML template home.html with the data in the context variable
    return render(request, 'vault/home.html')

def about(request):
    # Render the HTML template about.html with the data in the context variable
    return render(request, 'vault/about.html')

def upload(request):
    # Render the HTML template upload.html with the data in the context variable
    return render(request, 'vault/upload.html')

@login_required
def profile_view(request):
    # Get or create the user profile
    profile, created = Profile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=request.user)
        profile_form = ProfileForm(request.POST, request.FILES, instance=profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()  # Save user fields (first name, last name, email)
            profile_form.save()  # Save profile fields (job role, department, profile image)
            return redirect('profile_view')  # Make sure this is the correct URL name
        else:
            # Debugging: Print form errors
            print(user_form.errors)
            print(profile_form.errors)
    else:
        # Display the forms with the current user/profile data
        user_form = UserForm(instance=request.user)
        profile_form = ProfileForm(instance=profile)

    return render(request, 'vault/profile.html', {
        'user_form': user_form,
        'profile_form': profile_form
    })

# -------------------- API KEY VIEWS --------------------
ENV_PATH = os.path.join(settings.BASE_DIR, '.env')
load_dotenv(dotenv_path=ENV_PATH, override=True)

@require_POST
def update_api_key(request):
    key = request.POST.get('key')
    value = request.POST.get('value')
    if key and value:
        set_key(ENV_PATH, key, value)
        load_dotenv(dotenv_path=ENV_PATH, override=True)
        return JsonResponse({'status': 'success', 'key': key})
    return JsonResponse({'status': 'error', 'message': 'Missing key or value'}, status=400)

def api_key_manager(request):
    keys = {
        'VT_KEY': os.getenv('VT_KEY', 'paste_your_api_key_here'),
        'MALWARE_BAZAAR_KEY': os.getenv('MALWARE_BAZAAR_KEY', 'paste_your_api_key_here'),
        'ABUSEIPDB_KEY': os.getenv('ABUSEIPDB_KEY', 'paste_your_api_key_here'),
        'SPUR_KEY': os.getenv('SPUR_KEY', 'paste_your_api_key_here'),
        'SHODAN_KEY': os.getenv('SHODAN_KEY', 'paste_your_api_key_here'),
    }
    return render(request, 'vault/updatekeys/update_keys.html', {'keys': keys})
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
    # Handle form submission for creating a new YARA rule
    if request.method == 'POST':
        form = YaraRuleForm(request.POST)
        if form.is_valid():
            file_name = form.cleaned_data['file_name']
            sanitized_name = re.sub(r'[^\w\-_\. ]', '_', file_name)
            file_name = sanitized_name + '.yar'
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
    search_query = request.GET.get('search', '')
    yara_files = []
    if os.path.exists(rules_path):
        # Filter files based on the search query
        yara_files = [f for f in os.listdir(rules_path) if f.endswith('.yar') and search_query.lower() in f.lower()]

    # Set up pagination: Show 8 rules per page
    paginator = Paginator(yara_files, 8)  # 8 rules per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'vault/yara.html', {
        'form': form,
        'yara_files': page_obj,  # Pass the paginated object
        'search_query': search_query,  # Pass the search query to the template
    })


def edit_yara_rule(request, file_name):
    file_path = os.path.join(rules_path, file_name)
    
    # Handle form submission for editing the YARA rule
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

    # Implement search functionality
    search_query = request.GET.get('search', '')
    yara_files = []
    
    if os.path.exists(rules_path):
        # Filter files based on the search query
        yara_files = [f for f in os.listdir(rules_path) if f.endswith('.yar') and search_query.lower() in f.lower()]

    # Set up pagination: Show 8 rules per page
    paginator = Paginator(yara_files, 8)  # 8 rules per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'vault/edit_yara_rule.html', {
        'form': form,
        'file_name': file_name,
        'yara_files': page_obj,  # Pass the paginated object
        'search_query': search_query,  # Pass the search query to the template
    })

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
        
        # Paginate the vault items with 10 items per page
        paginator = Paginator(vault_items, 10)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        # Calculate tag frequencies across all files
        tag_frequencies = File.tag.through.objects.values('tag_id', 'tag__name').annotate(count=Count('tag_id')).order_by('-count')

        return render(request, 'vault/vault.html', {
            'vault': page_obj,  # Pass the paginated object to the template
            'tag_frequencies': tag_frequencies
        })
    else:
        # Handle the case when the request is not GET
        vault_items = File.objects.all()
        paginator = Paginator(vault_items, 10)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        return render(request, 'vault/vault.html', {
            'vault': page_obj,
            'tag_frequencies': File.tag.through.objects.values('tag_id', 'tag__name').annotate(count=Count('tag_id')).order_by('-count')
        })

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
# -------------------- IOC VIEWS --------------------
def ioc_table(request):
    if request.method == 'GET':
        search_query = request.GET.get('search')
        filter_option = request.GET.get("filter", "true")  # Default: Show only True positives

        # Filtering logic
        if filter_option == "false":
            iocs = IOC.objects.filter(true_or_false=False)
        elif filter_option == "both":
            iocs = IOC.objects.all()
        else:  # Default case (True positives only)
            iocs = IOC.objects.filter(true_or_false=True)

        # Apply search filtering if a search query exists
        if search_query:
            iocs = iocs.filter(
                Q(value__icontains=search_query) | Q(files__name__icontains=search_query)
            ).distinct()

        # Paginate results (10 items per page)
        paginator = Paginator(iocs, 10)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        return render(request, 'vault/ioc.html', {
            'iocs': page_obj,
            'filter_option': filter_option,  # Pass the current filter option to the template
            'search_query': search_query  # Maintain search input in template
        })

@csrf_protect
@require_POST
def update_true_false(request):
    try:
        data = json.loads(request.body)
        ioc_id = data.get("id")
        new_value = data.get("true_or_false")

        ioc = get_object_or_404(IOC, id=ioc_id)
        ioc.true_or_false = new_value
        ioc.save()

        return JsonResponse({"success": True})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

# -------------------- TOOL VIEWS --------------------
def tool_view(request, item_id):
    item = get_object_or_404(File, pk=item_id)
    user = request.user
    form_output = None
    if request.method == 'POST':
        form = ToolForm(request.POST)
        if form.is_valid():
            selected_tool = form.cleaned_data['tool']
            sub_tool = form.cleaned_data['sub_tool']
            password = form.cleaned_data['zipExtractor']
            if not password:
                password = None

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
                    output = run_tool(selected_tool, file_path, password, user)
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

def sample_detail(request, sha256):
    form_output = None
    form = ToolForm()
    item = get_object_or_404(File, sha256=sha256)
    iocs = json.dumps(list(item.iocs.values("type", "value")))

    return render(request, 'sample.html', {'item': item, 'iocs': iocs, 'form': form})

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

def run_tool(tool, file_path, password, user):
    
    if tool == 'hex-viewer':
        # Call the display_hex function to get hex output from the file
        try:
            output = display_hex.display_hex_with_ascii(file_path)
            return output
        except Exception as e:
            return f"Error getting hex output: {str(e)}"
    # elif tool == 'pdf-parser':
    #     # Call the parse_pdf function to get PDF information from the file
    #     try:
    #         output = pdftool.extract_forensic_data(file_path)
    #         formatted_output = pdftool.get_formatted_forensic_report(output)
    #         return formatted_output
    #     except Exception as e:
    #         return f"Error getting PDF information: {str(e)}"
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
            output = extract_ioc.extract_and_save_iocs(file_path)
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
    elif tool == 'zip_extractor':
        try:
            # Retrieve the password from the form
            unzip = 'on'
            tags = 'unzipped'
            save_file = extract.ExtractZip(file_path, tags, unzip, password, user)
            message = save_file.extract_file_and_update_model()
            sha256 = message[1]
            output = f"File unzipped successfully: {sha256}"
            return output
        except Exception as e:
            return f"Error unzipping file: {str(e)}"
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
    elif tool == 'pdf-parser':
        # Call the extract_pdf_content function to get PDF content from the file
        try:
            output = pdftool.extract_forensic_data(file_path, sub_tool)
            return output
        except Exception as e:
            return f"Error extracting PDF content: {str(e)}"
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
        qr = request.POST.get('qr', '')  # Check if the 'qr' checkbox is checked
        if qr:
            try:
                data = qr_decode.decode_qr(uploaded_file)
                return render(request, 'upload_success.html', {'QR_Data': data})
            except:
                return render(request, 'upload_error.html', {'error_message': 'File not found', 'message': 'Something Went Wrong'})
        else:
            qr = False
        uploaded_by=request.user  # Capture the logged-in user who uploaded the file
        save_file = save_sample.SaveSample(uploaded_file, tags, unzip, password, uploaded_by)
        message = save_file.save_file_and_update_model()
        sha256 = message[1]
        if len(sha256) == 64:  # Check if the message is a SHA256 hash
            try:
                instance = File.objects.get(sha256=sha256)
                # Retrieve the id field from the instance
                id_value = instance.id
            except File.DoesNotExist:
                return render(request, 'upload_error.html', {'error_message': 'File not found', 'message': 'sometext'})
            return render(request, 'upload_success.html', {'file_name': sha256})            
        else:
            return render(request, 'upload_error.html', {'error_message': message})
        # return render(request, 'upload_success.html', message)
    return render(request, 'index.html')

def get_webpage(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        tags = request.POST.get('tags', '')
        tags = tags = tags.split(',') if tags else []
        tags.append('URL')
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
                uploaded_by=request.user,
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
def enterprise_check(vtkey):
    # Check if the API key is for VirusTotal Enterprise
    url = f"https://www.virustotal.com/api/v3/intelligence/search?query=domain:google.com&limit=10"
    headers = {"accept": "application/json", "x-apikey": vtkey}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return True
    elif response.status_code == 403:
        return False
    
def vt_download(request):
    sha256 = request.POST.get('sha256')
    tags = request.POST.get('tags', '')
    tags = tags = tags.split(',') if tags else []
    tags.append('virustotal')
    if sha256:
        # Load the VirusTotal API key from the .env file
        vtkey = os.getenv('VT_KEY')
        is_enterprise = enterprise_check(vtkey)
        if vtkey is None or vtkey == 'paste_your_api_key_here':
            return render(request, 'upload_error.html', {'error_message': '[!] VirusTotal API key not set in .env file'})
 
        elif is_enterprise is False:
            return render(request, 'upload_error.html', {'error_message': '[-] You don\'t have an Enterprise Virus Total License. Please use a valid API key.'})
        else:
            # sanitize sha256
            sha256_pattern = re.compile(r'[^[a-fA-F0-9]{64}$]')
            clean_sha256 = sha256_pattern.sub('', sha256)
            file_path = f'vault/samples/{clean_sha256}'
            if file_path:
                # Download the file from VirusTotal requires a premium account
                try:
                    url = f"https://www.virustotal.com/api/v3/files/{sha256}/download"
                    headers = {"accept": "application/json", "x-apikey": vtkey}
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                        with open(file_path, 'wb') as f:
                            f.write(response.content)
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
    tags.append('malwarebazaar')
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
                        uploaded_by=request.user,
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
    if abusekey is None or abusekey == 'paste_your_api_key_here':
        data = '[!] AbuseIPDB API key not set in .env file'
        return data
    headers = {'Key': abusekey, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        return data
    if response.status_code == 401:
        data = '[!] Unauthorized: Invalid API key'
        return data
    if response.status_code == 403:
        data = '[!] Forbidden: Access denied - check your API key'
        return data
    if response.status_code == 404:
        data = '[?] Not Found: IP address not found'
        return data
    else:
        data = f'[!] Error: {response.status_code} - {response.text}'
        return data

def get_spur_data(ip):
    # Load the Spur API key from the .env file
    spurkey = os.getenv('SPUR_KEY')
    if spurkey is None or spurkey == 'paste_your_api_key_here':
        data = '[!] Spur API key not set in .env file'
        return data
    headers = {'TOKEN': spurkey}
    response = requests.get(f'https://api.spur.us/v2/context/{ip}', headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    if response.status_code == 401:
        data = '[!] Unauthorized: Invalid API key'
        return data
    if response.status_code == 403:
        data = '[!] Forbidden: Access denied - check your API key'
        return data
    if response.status_code == 404:
        data = '[?] Not Found: IP address not found'
        return data
    else:
        data = f'[!] Error: {response.status_code} - {response.text}'
        return data
    
def get_vt_data(ip):
    # Load the VirusTotal API key from the .env file
    vtkey = os.getenv('VT_KEY')
    if vtkey is None or vtkey == 'paste_your_api_key_here':
        data = '[!] Virus Total API key not set in .env file'
        return data
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": vtkey}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    if response.status_code == 401:
        data = '[!] Unauthorized: Invalid API key'
        return data
    if response.status_code == 403:
        data = '[!] Forbidden: Access denied - check your API key'
        return data
    if response.status_code == 404:
        data = '[?] Not Found: IP address not found'
        return data
    else:
        data = f'[!] Error: {response.status_code} - {response.text}'
        return data
    
def get_shodan_data(ip):
    # Load the Shodan API key from the .env file
    shodankey = os.getenv('SHODAN_KEY')
    if shodankey is None or shodankey == 'paste_your_api_key_here':
        data = '[!] Shodan API key not set in .env file'
        return data
    api = shodan.Shodan(shodankey)
    try:
        data = api.host(ip)
        return data
    except shodan.APIError as e:
        if 'no information' in str(e).lower():
            return f'[?] Not Found: {ip}'
        if 'invalid' in str(e).lower():
            return '[!] Invalid API Key'
        if 'rate limit' in str(e).lower():
            return '[!] Rate Limit Exceeded'
        else:
            return f'[!] Not Found: {e}'
    
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
