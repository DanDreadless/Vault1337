# forms.py
from django import forms

class ToolForm(forms.Form):
    tool_choices = [
        ('strings', 'Strings'),
        # Add more tool choices as needed
    ]

    tool = forms.ChoiceField(choices=tool_choices, label='Select a Tool')
