# forms.py
import os
from django import forms
from .models import Profile
from dotenv import dotenv_values
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
        ('run-yara', 'Run YARA Rules'), 
        ('email-parser', 'Email Parser'),
        ('zip_extractor', 'Zip Extractor')
        # Add more tool choices as needed
    ]
    
    SUB_TOOL_CHOICES = {
        'LIEF Parser': [
            ('dos_header', 'DOS Header'),
            ('rich_header', 'Rich Header'),
            ('pe_header', 'PE Header'),
            ('entrypoint', 'Entrypoint'),
            ('sections', 'Sections'),
            ('imports', 'Imports'),
            ('sigcheck', 'Signature Check'),
            ('checkentropy', 'Check Entropy')
        ],
        'OLETools': [
            ('oleid', 'OLEID'),
            ('olemeta', 'OLEMETA'),
            ('oledump', 'OLEDUMP'),
            ('olevba', 'OLEVBA'),
            ('rtfobj', 'RTFOBJ'),
            ('oleobj', 'OLEOBJ')
        ],
        'Email Parser': [
            ('email_headers', 'Email Headers'),
            ('email_body', 'Email Body'),
            ('download_attachments', 'Download Attachments'),
            ('url_extractor', 'URL Extractor')
        ],
        'strings': [
            ('utf-8', 'utf-8'),
            ('latin-1', 'latin-1'),
            ('utf-16', 'utf-16'),
            ('utf-32', 'utf-32'),
            ('ascii', 'ascii')
        ],
        'PDF Parser': [
            ('metadata', 'Extract Metadata'),
            ('content', 'Extract Content'),
            ('images', 'Extract Images'),
            ('urls', 'Extract URLs')
        ]
    }

    tool = forms.ChoiceField(choices=TOOL_CHOICES, label='Select a Tool')
    sub_tool = forms.ChoiceField(choices=SUB_TOOL_CHOICES, label='Select a Subtool', required=False)
    zipExtractor = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'infected'})
    )

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



class APIKeyForm(forms.Form):

    def __init__(self, *args, initial_keys=None, **kwargs):
        super().__init__(*args, **kwargs)

        API_KEYS = [
        ('VIRUS_TOTAL_API_KEY', 'VirusTotal'),
        ('ABUSEIPDB_API_KEY', 'AbuseIPDB'),
        ('MALWARE_BAZAAR_API_KEY', 'MalwareBazaar'),
        ('SHODAN_API_KEY', 'Shodan'),
        ('SPUR_API_KEY', 'Spur'),
        ]
        
        for key, label in API_KEYS:
            value = initial_keys.get(key, "paste_your_key_here") if initial_keys else "paste_your_key_here"
            self.fields[key] = forms.CharField(
                label=label,
                required=False,
                widget=forms.PasswordInput(render_value=True, attrs={'class': 'form-control', 'placeholder': 'Enter API key'}),
                initial=value
            )

# # Load the .env file
# load_dotenv()

# class APIKeyForm(forms.Form):
#     OBFUSCATED_VALUE = 'API_KEY_OBFUSCATED'

#     VT_KEY = forms.CharField(
#         label='VirusTotal API Key',
#         max_length=255,
#         widget=forms.TextInput(attrs={
#             'class': 'form-control',
#             'placeholder': 'Enter VirusTotal API Key'
#         }),
#         required=False  # Allow the field to be left blank if the user doesn't want to change it
#     )
#     MALWARE_BAZAAR_KEY = forms.CharField(
#         label='Malware Bazaar API Key',
#         max_length=255,
#         widget=forms.TextInput(attrs={
#             'class': 'form-control',
#             'placeholder': 'Enter Malware Bazaar API Key'
#         }),
#         required=False
#     )
#     ABUSEIPDB_KEY = forms.CharField(
#         label='AbuseIPDB API Key',
#         max_length=255,
#         widget=forms.TextInput(attrs={
#             'class': 'form-control',
#             'placeholder': 'Enter AbuseIPDB API Key'
#         }),
#         required=False
#     )
#     SPUR_KEY = forms.CharField(
#         label='Spur API Key',
#         max_length=255,
#         widget=forms.TextInput(attrs={
#             'class': 'form-control',
#             'placeholder': 'Enter Spur API Key'
#         }),
#         required=False
#     )
#     SHODAN_KEY = forms.CharField(
#         label='Shodan API Key',
#         max_length=255,
#         widget=forms.TextInput(attrs={
#             'class': 'form-control',
#             'placeholder': 'Enter Shodan API Key'
#         }),
#         required=False
#     )

#     def __init__(self, *args, **kwargs):
#         super(APIKeyForm, self).__init__(*args, **kwargs)

#         # Load the keys from the environment
#         self.fields['VT_KEY'].initial = self.obfuscate_key(os.getenv('VT_KEY'))
#         self.fields['MALWARE_BAZAAR_KEY'].initial = self.obfuscate_key(os.getenv('MALWARE_BAZAAR_KEY'))
#         self.fields['ABUSEIPDB_KEY'].initial = self.obfuscate_key(os.getenv('ABUSEIPDB_KEY'))
#         self.fields['SPUR_KEY'].initial = self.obfuscate_key(os.getenv('SPUR_KEY'))
#         self.fields['SHODAN_KEY'].initial = self.obfuscate_key(os.getenv('SHODAN_KEY'))

#     # Helper function to obfuscate keys
#     def obfuscate_key(self, key_value):
#         return self.OBFUSCATED_VALUE if key_value else ''

#     # Custom clean method to handle obfuscated values
#     def clean(self):
#         cleaned_data = super().clean()
#         api_keys = {
#             'VT_KEY': 'VT_KEY',
#             'MALWARE_BAZAAR_KEY': 'MALWARE_BAZAAR_KEY',
#             'ABUSEIPDB_KEY': 'ABUSEIPDB_KEY',
#             'SPUR_KEY': 'SPUR_KEY',
#             'SHODAN_KEY': 'SHODAN_KEY',
#         }

#         # Loop through each key, preserve the existing key if the field contains the obfuscated value
#         for key, field_name in api_keys.items():
#             if cleaned_data[field_name] == self.OBFUSCATED_VALUE:
#                 cleaned_data[field_name] = os.getenv(key)

#         return cleaned_data




class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']

class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['job_role', 'department', 'profile_image']