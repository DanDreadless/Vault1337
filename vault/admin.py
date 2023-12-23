from django.contrib import admin
from .models import File, Tag, Comment, User, Session, FileSession, FileTag, FileComment, FileUser
# Register your models here.
admin.site.register(File)
admin.site.register(Tag)
admin.site.register(Comment)
admin.site.register(User)
admin.site.register(Session)
admin.site.register(FileSession)
admin.site.register(FileTag)
admin.site.register(FileComment)
admin.site.register(FileUser)