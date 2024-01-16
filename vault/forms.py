# forms.py
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

class ToolForm(forms.Form):
    tool_choices = [
        ('strings', 'Strings'),
        ('pe-heder', 'PE Header')
        # Add more tool choices as needed
    ]

    tool = forms.ChoiceField(choices=tool_choices, label='Select a Tool')

class SignupForm(UserCreationForm):
    class Meta:
        model = User 
        fields = ['username', 'password1', 'password2']

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)