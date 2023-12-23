from django.shortcuts import render
# from django.http import HttpResponse
# Create your views here.
from .models import File, Tag, Comment, User, Session, FileSession, FileTag, FileComment, FileUser

def index(request):
    # Render the HTML template index.html with the data in the context variable
    return render(request, 'vault/index.html')
