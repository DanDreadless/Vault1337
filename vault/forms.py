# forms.py
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

class ToolForm(forms.Form):
    TOOL_CHOICES = [
        ('strings', 'Strings'),
        ('extract-ioc', 'Extract IOCs'),
        ('lief-parser', 'LIEF Parser'),
        ('hex-viewer', 'Hex Viewer'),
        ('pdf-parser', 'PDF Parser'),
        ('oletools', 'OLETools'),
        ('exiftool', 'ExifTool'),
        ('run-yara', 'Run YARA Rules')
        # Add more tool choices as needed
    ]
    
    SUB_TOOL_CHOICES = {
        'LIEF Parser': [
            ('dos_header', 'DOS Header'),
            ('rich_header', 'Rich Header'),
            ('pe_header', 'PE Header'),
            ('entrypoint', 'Entrypoint'),
            ('sections', 'Sections')
        ],
        'OLETools': [
            ('oleid', 'OLEID'),
            ('olemeta', 'OLEMETA'),
            ('oledump', 'OLEDUMP'),
            ('olevba', 'OLEVBA'),
            ('rtfobj', 'RTFOBJ'),
            ('oleobj', 'OLEOBJ')
        ]
    }

    tool = forms.ChoiceField(choices=TOOL_CHOICES, label='Select a Tool')
    sub_tool = forms.ChoiceField(choices=SUB_TOOL_CHOICES, label='Select a Subtool', required=False)

class SignupForm(UserCreationForm):
    class Meta:
        model = User 
        fields = ['username', 'password1', 'password2']

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

class YaraRuleForm(forms.Form):
    file_name = forms.CharField(
        max_length=100,
        help_text="Enter the file name for the YARA rule (without extension).",
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    rule_content = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 15}),
        help_text="Enter the YARA rule content."
    )