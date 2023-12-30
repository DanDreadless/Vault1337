# forms.py
from django import forms
from .models import CustomUser
from django.contrib.auth.forms import UserCreationForm

class ToolForm(forms.Form):
    tool_choices = [
        ('strings', 'Strings'),
        # Add more tool choices as needed
    ]

    tool = forms.ChoiceField(choices=tool_choices, label='Select a Tool')

class SignUpForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password1', 'password2')