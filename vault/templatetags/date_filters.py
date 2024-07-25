# myapp/templatetags/date_filters.py
from django import template
from datetime import datetime

register = template.Library()

@register.filter
def format_date(value):
    if isinstance(value, int):
        # If it's an integer, treat it as a Unix timestamp
        return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(value, str):
        # If it's a string, try to parse it
        try:
            # Handle Unix timestamp as string
            return datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            # Handle invalid timestamp
            return "Invalid date format"
    else:
        return "Invalid date type"
