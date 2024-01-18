# forms.py
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

class ToolForm(forms.Form):
    TOOL_CHOICES = [
        ('strings', 'Strings'),
        ('lief-parser', 'LIEF Parser'),
        # Add more tool choices as needed
    ]

    SUB_TOOL_CHOICES = [
        ('dos_header', 'DOS Header'),
        ('rich_header', 'Rich Header'),
        ('pe_header', 'PE Header'),
        ('entrypoint', 'Entrypoint')
    ]

    tool = forms.ChoiceField(choices=TOOL_CHOICES, label='Select a Tool')
    sub_tool = forms.ChoiceField(choices=SUB_TOOL_CHOICES, label='Select a Subtool', required=False)

class SignupForm(UserCreationForm):
    class Meta:
        model = User 
        fields = ['username', 'password1', 'password2']

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)