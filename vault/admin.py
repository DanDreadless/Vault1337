from django.contrib import admin
from .models import File, Comment, CustomUser, Session
# Register your models here.
admin.site.register(File)
admin.site.register(Comment)
admin.site.register(CustomUser)
admin.site.register(Session)