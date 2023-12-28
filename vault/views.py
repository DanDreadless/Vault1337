from django.shortcuts import render, redirect
from .utils import calculate_hashes  # Create a utility function for hash calculation
# from django.http import HttpResponse
# Create your views here.
from .models import File, Tag, Comment, User, Session, FileSession, FileTag, FileComment, FileUser

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
    try:
        if request.method == 'POST':
            # Get the uploaded file and tags from the form
            uploaded_file = request.FILES.get('file')
            tags = request.POST.get('tags', '')

            # Calculate hash values using a utility function
            # file deepcode ignore PT: <please specify a reason of ignoring this>
            size, magic, mime, md5, sha1, sha256, sha512 = calculate_hashes(uploaded_file)

            # Create a new VaultItem instance and save it to the database
            vault_item = File(
                name=uploaded_file.name,
                size=size,
                magic=magic,
                mime=mime,
                # type=uploaded_file.content_type,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                sha512=sha512,
            )
            vault_item.save()

            # Redirect to a success page or render a success message
            return redirect('upload_success')
    except Exception as e:
        print(f"An error occurred: {e}")

    return render(request, 'vault/index.html')