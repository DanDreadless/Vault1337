import datetime
from django.db import models

# Create your models here.
class File(models.Model):
    name = models.CharField(max_length=200)
    size = models.IntegerField()
    magic = models.CharField(max_length=200)
    mime = models.CharField(max_length=200)
    md5 = models.CharField(max_length=200)
    sha1 = models.CharField(max_length=200)
    sha256 = models.CharField(max_length=200)
    sha512 = models.CharField(max_length=200)
    created_date = models.DateTimeField(default=datetime.datetime.now)
    parent = models.ForeignKey("self", null=True, on_delete=models.CASCADE)

class Tag(models.Model):
    name = models.CharField(max_length=200)
    file = models.ForeignKey(File, on_delete=models.CASCADE)

class Comment(models.Model):
    title = models.CharField(max_length=200)
    text = models.CharField(max_length=200)
    file = models.ForeignKey(File, on_delete=models.CASCADE)

class User(models.Model):
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    file = models.ForeignKey(File, on_delete=models.CASCADE)

class Session(models.Model):
    token = models.CharField(max_length=200)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

class FileSession(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    session = models.ForeignKey(Session, on_delete=models.CASCADE)

class FileTag(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)

class FileComment(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE)

class FileUser(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

