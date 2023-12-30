from django.contrib import admin
from .models import File, Comment, User, Session
# Register your models here.
admin.site.register(File)
admin.site.register(Comment)
admin.site.register(User)
admin.site.register(Session)