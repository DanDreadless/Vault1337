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
    tag = models.CharField(max_length=200, null=True)
    created_date = models.DateTimeField(default=datetime.datetime.now)
    parent = models.ForeignKey("self", null=True, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

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