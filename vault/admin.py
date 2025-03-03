from django.contrib import admin
from .models import File, Comment, IOC
# Register your models here.
admin.site.register(File)
admin.site.register(Comment)

@admin.register(IOC)
class IOCAdmin(admin.ModelAdmin):
    list_display = ('type', 'value', 'created_date')  # Customize columns in the admin panel
    search_fields = ('value',)  # Allow searching by IOC value
    list_filter = ('type',)  # Filter options by type
    date_hierarchy = ('created_date')
    ordering = ('-created_date',)  # Default ordering
    filter_horizontal = ('files',)  # Allow multiple selection of files
    list_per_page = 10  # Pagination
    true_or_false = ('true_or_false',)  # Filter by true or false
    actions = ['make_true', 'make_false']  # Custom actions
    
    
