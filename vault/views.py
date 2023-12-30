from django.shortcuts import render, redirect, get_object_or_404
from .utils import add_file  # Create a utility function for hash calculation
from django.core.files.storage import FileSystemStorage
# from django.http import HttpResponse
# Create your views here.
from .models import File, Comment, User, Session

def index(request):
    # Render the HTML template index.html with the data in the context variable
    return render(request, 'vault/index.html')

def about(request):
    # Render the HTML template about.html with the data in the context variable
    return render(request, 'vault/about.html')

def upload(request):
    # Render the HTML template upload.html with the data in the context variable
    return render(request, 'vault/upload.html')

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

def upload_file(request):
    if request.method == 'POST' and request.FILES['file']:
        uploaded_file = request.FILES['file']
        tags = request.POST.get('tags', '')

        size = 30
        magic= "insert magic here"

        # Calculate hash values using a utility function
        # file deepcode ignore PT: Temp ignoring to focus on getting the base code put together
        md5, sha1, sha256, sha512 = add_file(uploaded_file)

        # magic = get_magic_bytes(uploaded_file)

        # size = get_file_size(uploaded_file)
        
        # Create a new VaultItem instance and save it to the database
        vault_item = File(
            name=uploaded_file.name,
            size=size,
            magic=magic,
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
        # messages.success(request, 'File uploaded successfully.')
        # return redirect('upload_file')
        return render(request, 'upload_success.html', {'file_name': final_file_name})
    
    return render(request, 'index.html')

def sample_detail(request, item_id):
    item = get_object_or_404(File, pk=item_id)
    return render(request, 'sample.html', {'item': item})