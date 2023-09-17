from import_export.admin import ImportExportModelAdmin
from django.contrib import admin
from .models import *
# Register your models here.
class SAdmin(ImportExportModelAdmin, admin.ModelAdmin):
    ...
admin.site.register(Domain, SAdmin)
admin.site.register(SubDomain, SAdmin)
admin.site.register(Tool)
admin.site.register(FoundFrom)
admin.site.register(DomainInfo, SAdmin)