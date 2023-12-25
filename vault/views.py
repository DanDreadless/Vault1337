from django.shortcuts import render, redirect
# from django.http import HttpResponse
# Create your views here.
from .models import File, Tag, Comment, User, Session, FileSession, FileTag, FileComment, FileUser

def index(request):
    # Render the HTML template index.html with the data in the context variable
    return render(request, 'vault/index.html')

def about(request):
    # Render the HTML template about.html with the data in the context variable
    return render(request, 'vault/about.html')


def vault_table(request):
    # Assuming you want to fetch all items from the VaultItem model
    vault_items = File.objects.all()

    # Pass the data to the template
    context = {'vault': vault_items}

    # Render the template with the context data
    return render(request, 'vault/vault.html', context)


