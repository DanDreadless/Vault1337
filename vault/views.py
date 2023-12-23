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

def login(request):
    # Render the HTML template login.html with the data in the context variable
    return render(request, 'vault/login.html')

def logout(request):
    # Render the HTML template logout.html with the data in the context variable
    return render(request, 'vault/index.html')

