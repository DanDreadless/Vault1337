# Other Imports
import os
import vt
import hashlib
import zipfile
import pyzipper
import requests
from dotenv import load_dotenv
from urllib.parse import urlparse
# Vault imports
from .models import File
from vault.workbench import lief_parser_tool, ole_tool, strings, display_hex, pdftool, exif, save_sample
from .utils import hash_sample
from .forms import ToolForm, UserCreationForm, LoginForm
# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth import authenticate, login

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


# -------------------- VAULT VIEWS --------------------
def vault_table(request):
    # Fetch all items from the VaultItem model
    vault_items = File.objects.all()

    # Search functionality
    search_query = request.GET.get('search', '')
    if search_query:
        vault_items = vault_items.filter(
            name__icontains=search_query
            # Add more fields as needed for your search
        )

    # Pass the data to the template
    context = {
        'vault': vault_items,
        'search_query': search_query,
    }

    # Render the template with the context data
    return render(request, 'vault/vault.html', context)

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
    file_path = f'vault/samples/{str(item.sha256)}'
    if os.path.exists(file_path):
        os.remove(file_path)
    # Perform the deletion
    item.delete()

    # Redirect to the vault table page after deletion
    return redirect('vault_table')

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
    # Customize this function based on your file storage structure
    # This example assumes files are stored in a 'files' directory with names as their SHA256 values
    file_path = f'vault/samples/{sha256_value}'
    # Check if the file exists
    if os.path.exists(file_path):
        return file_path
    else:
        return None

def run_tool(tool, file_path):
    # Example: Run the tool against the file
    if tool == 'strings':
        # Call the get_strings function to get strings from the file
        try:
            output = strings.get_strings(file_path)
            return output
        except Exception as e:
            return f"Error getting strings: {str(e)}"
    
    elif tool == 'hex-viewer':
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
        if url:
            # Fetch the webpage
            try:
                # deepcode ignore Ssrf: <please specify a reason of ignoring this>
                response = requests.get(url, timeout=5)
            except:
                return render(request, 'upload_error.html', {'error_message': 'Error fetching webpage'})
            if response.status_code != 200:
                return render(request, 'upload_error.html', {'error_message': f'response code: {response.status_code} - Error fetching webpage'})
            else:
                source_code = response.text

            # Save source code to a file
            file_path = f'vault/samples/webpage_{url.replace("http://", "").replace("https://", "").replace("/", "_").replace("?", "-")}.html'
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(source_code)

            # Calculate hash values using a utility function
            md5, sha1, sha256, sha512, magic_byte, size, mime = hash_sample(file_path)

            # rename file to sha256
            final_file_name = sha256

            os.rename(file_path, f'vault/samples/{final_file_name}')
            # Create a new VaultItem instance and save it to the database
            # TODO: generate proper mimetype
            vault_item = File(
                name=url,
                size=size,
                magic=magic_byte,
                mime=mime,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                sha512=sha512,
                tag=tags,
            )
            if File.objects.filter(sha256=sha256).exists():
                return render(request, 'upload_error.html', {'error_message': 'File already exists'})
            else:
                vault_item.save()
            instance = File.objects.get(sha256=sha256)
            # Retrieve the id field from the instance
            id_value = instance.id
            return render(request, 'upload_success.html', {'file_name': final_file_name, 'webpage': url, 'id': id_value})

    return render(request, 'index.html')

def vt_download(request):
    sha256 = request.POST.get('sha256')
    tags = request.POST.get('tags', '')
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
    if sha256:
        # Load the MalwareBazaar API key from the .env file
        mbkey = os.getenv('MALWARE_BAZAAR_KEY')
        downloaded_file = f'vault/samples/zip_{sha256}'
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
                        tag=tags,
                    )
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
