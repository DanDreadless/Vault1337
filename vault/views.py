# Other Imports
import os
import vt
import zipfile
import requests
from dotenv import load_dotenv
from urllib.parse import urlparse
# Vault imports
from .models import File
from vault.workbench import lief_parser_tool, strings, display_hex, pdftool, oletools
from .utils import add_file, url_hashing
from .forms import ToolForm, UserCreationForm, LoginForm
# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from django.core.files.storage import FileSystemStorage

# Load environment variables from .env file
load_dotenv()

# -------------------- BASIC PAGE VIEWS --------------------
def index(request):
    # Render the HTML template index.html with the data in the context variable
    return render(request, 'vault/index.html')

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
        # Call the check_for_macros function to check for macros in the file
        try:
            output = oletools.oletools_subtool_parser(sub_tool, file_path)
            return output
        except Exception as e:
            return f"Error checking for macros: {str(e)}"
    else:
        return f"Tool '{tool}' not supported."
    
# -------------------- INDEX VIEWS --------------------
# todo: make zip files work
def upload_file(request):
    if request.method == 'POST' and request.FILES['file']:
        uploaded_file = request.FILES['file']
        tags = request.POST.get('tags', '')
        unzip = request.POST.get('unzip', '')  # Check if the 'unzip' checkbox is checked
        password = request.POST.get('password', '')  # Get the password entered by the user

        # Calculate hash values using a utility function
        # file deepcode ignore PT: Temp ignoring to focus on getting the base code put together
        md5, sha1, sha256, sha512, magic_byte, size = add_file(uploaded_file)

        # Create a new VaultItem instance and save it to the database
        vault_item = File(
            name=uploaded_file.name,
            size=size,
            magic=magic_byte,
            mime=uploaded_file.content_type,
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

        # Set filename to the sha256 hash
        final_file_name = sha256

        # Set the location for FileSystemStorage
        storage_location = 'vault/samples/'
        fs = FileSystemStorage(location=storage_location)

        # Save the file with the new name
        fs.save(final_file_name, uploaded_file)

        # If unzip checkbox is checked, unzip the file
        if unzip:
            try:
                with zipfile.ZipFile(uploaded_file, 'r') as zip_ref:
                    if password:  # Check if a password is provided
                        zip_ref.extractall(storage_location, pwd=password.encode())
                    else:
                        zip_ref.extractall(storage_location)
            except Exception as e:
                return render(request, 'upload_error.html', {'error_message': f'Error unzipping file: {str(e)}'})

        # messages.success(request, 'File uploaded successfully.')
        # return redirect('upload_file')
        return render(request, 'upload_success.html', {'file_name': final_file_name})

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
            md5, sha1, sha256, sha512, magic_byte, size = url_hashing(file_path)

            # rename file to sha256
            final_file_name = sha256

            os.rename(file_path, f'vault/samples/{final_file_name}')
            # Create a new VaultItem instance and save it to the database
            # TODO: generate proper mimetype
            vault_item = File(
                name=url,
                size=size,
                magic=magic_byte,
                mime='text/html',
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

            return render(request, 'upload_success.html', {'file_name': final_file_name, 'webpage': url})

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
                return render(request, 'upload_success.html', {'file_name': sha256})
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
