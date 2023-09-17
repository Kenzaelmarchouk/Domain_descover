from django.db import models
from django.core.validators import FileExtensionValidator

class Domain(models.Model):
    domain_name = models.CharField(max_length=200, null=False, unique=True)
    ip_adress = models.CharField(max_length=800, blank=True, null=True)

    def __str__(self):
        return self.domain_name


class SubDomain(models.Model):
    domain = models.ForeignKey(
        Domain, on_delete=models.CASCADE, null=True, blank=True)
    subDomain_name = models.CharField(max_length=100, unique=True)
    ip = models.CharField(max_length=800, blank=True, null=True)

    def __str__(self):
        return self.subDomain_name
class Tool(models.Model):
    tool_name = models.CharField(max_length=800, null=False, unique=True)
    tool_url = models.URLField(max_length=800, unique=True)
    tool_desciption = models.TextField()
    def __str__(self):
        return self.tool_name
class FoundFrom(models.Model):
    subdomain = models.ForeignKey(SubDomain, on_delete=models.CASCADE)
    tool = models.ForeignKey(Tool, on_delete=models.CASCADE)
    scan_date = models.DateField()
class DomainInfo(models.Model):
    domain = models.ForeignKey(
        Domain, on_delete=models.CASCADE, null=True, blank=True)
    registrar = models.CharField(max_length=800, null=True)
    status=models.CharField(max_length=800,null=True)
    dnssec=models.CharField(max_length=800,null=True)
    creation_date = models.DateField(null=True)
    expiration_date = models.DateField(null=True)
    update_date = models.DateField(null=True)


