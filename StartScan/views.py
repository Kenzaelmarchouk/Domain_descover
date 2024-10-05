import json
import os
import socket
import subprocess
import time
from urllib.parse import urlparse
from django.http import HttpResponseRedirect
import asyncwhois
import requests
import tldextract
from apiclient.discovery import build
from bs4 import BeautifulSoup
from django.core import serializers
from django.shortcuts import render
from django.utils import timezone
from duckduckgo_search import ddg
from django.views.decorators.csrf import csrf_exempt, csrf_protect
import re
from django.db.models import Q
from magic import from_file
from django.core.exceptions import SuspiciousFileOperation
import uuid
from .forms import *
from .models import *

#To avoid injection de command
pattern = r'^[A-Za-z0-9\.\-_]+$'

#from django.http import HttpResponseRedirect
# Create your views here.

def accueil(request):
    return render(request, "home.html")
@csrf_exempt
def index(request):
    form = UploadFileForm(request.POST, request.FILES)

    if request.POST:

        if form.is_valid():
            handle_uploaded_file(request.FILES['file'])
            return HttpResponseRedirect('/home')
    return render(request, "index.html", {'form': form})

@csrf_exempt
def home(request):
    if request.method == 'GET':
        filter_value = request.GET.get('filter')
        if filter_value:
            Sub = SubDomain.objects.filter(Q(domain__domain_name=filter_value) | Q(domain_id=filter_value))
        else:
            Sub = SubDomain.objects.all()

    test = serializers.serialize('python', SubDomain.objects.all())
    #Sub = SubDomain.objects.all()
    domain = Domain.objects.all()
    domain_count = Domain.objects.all().count()
    subdomain_count = SubDomain.objects.all().count()
    nbsub_subfinder = FoundFrom.objects.filter(
        tool_id=[i.id for i in Tool.objects.filter(tool_name="SubFinder")][0]).count()
    nbsub_googleapi = FoundFrom.objects.filter(
        tool_id=[i.id for i in Tool.objects.filter(tool_name="Google API")][0]).count()
    nbsub_ddg = FoundFrom.objects.filter(
        tool_id=[i.id for i in Tool.objects.filter(tool_name="DuckDuckGo API")][0]).count()
    nbsub_gal = FoundFrom.objects.filter(
        tool_id=[i.id for i in Tool.objects.filter(tool_name="Get All Urls")][0]).count()
    nbsub_virust = FoundFrom.objects.filter(
        tool_id=[i.id for i in Tool.objects.filter(tool_name="Virus Total")][0]).count()
    nbsub_crtsh = FoundFrom.objects.filter(
        tool_id=[i.id for i in Tool.objects.filter(tool_name="crt.sh")][0]).count()
    nbsub_RapidDNS = FoundFrom.objects.filter(
        tool_id=[i.id for i in Tool.objects.filter(tool_name="RapidDNS")][0]).count()
    nbsub_amass = FoundFrom.objects.filter(
        tool_id=[i.id for i in Tool.objects.filter(tool_name="Amass")][0]).count()
    data = []
    for item in domain:
        data.append(SubDomain.objects.filter(domain__id=item.id).count())
    context = {
        'data': data,
        'domain': domain,
        'domain_count': domain_count,
        'subdomain_count': subdomain_count,
        'test': test,
        'nbsub_subfinder': nbsub_subfinder,
        'nbsub_googleapi': nbsub_googleapi,
        'nbsub_ddg': nbsub_ddg,
        'nbsub_gal': nbsub_gal,
        'nbsub_virust': nbsub_virust,
        'nbsub_crtsh': nbsub_crtsh,
        'nbsub_RapidDNS': nbsub_RapidDNS,
        'nbsub_amass': nbsub_amass,
        'Sub': Sub

    }
    return render(request, "result.html", context)



#@csrf_protect

def handle_uploaded_file(f):
    #file_type = from_file(f.name)
    #Allowed_file_type = ['text/plain']
    #if file_type not in Allowed_file_type:
        #raise SuspiciousFileOperation("Invalid file type")
    #random_name = str(uuid.uuid4())
    #file_ext = os.path.splitext(f.name)
    #path = random_name + file_ext
    #To save the uploaded file in startScan/FILES/file uploaded
    path = os.path.realpath('StartScan/FILES/' + f.name)
    with open(path, 'wb+') as des:
        for chunk in f.chunks():
            des.write(chunk)

    subfind_tool(path)
    google_api(path)
    duckDuckGo_api(path)
    virus_total(path)
    crtsh(path)
    rapidDNS(path)
    amass(path)
    gau(path)
    whois_Domain()





    

######################################################## Tools used  __/(-_-)/__    ##############

# #####################  °/_(-_-)_/ subfinder ##################
def subfind_tool(path):
   
    Tool.objects.update_or_create(
tool_name='SubFinder', tool_url='https://github.com/projectdiscovery/subfinder', tool_desciption='SubFinder  is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources. It has a simple modular architecture and is optimized for speed. subfinder is built for doing one thing only - passive subdomain enumeration, and it does that very well.')
    id_tool = Tool.objects.filter(tool_name='SubFinder')
    with open(path, 'r') as file:
        for line in file:
            domain = line.strip()

            if re.match(pattern, domain):
                if (Domain.objects.filter(domain_name=domain).exists()):
                    print(f'{domain} already exists')
                else:
                    
                    try:
                        Domain.objects.update_or_create(
                            domain_name=domain, ip_adress=socket.gethostbyname(domain))
                    except:
                        #Domain.objects.update_or_create(domain_name=domain, ip_adress=NULL)
                            
                        print(f'"No ip found for " {domain} it is not a resolved domain')

                #compt = Domain.objects.all()
                list_sub=subprocess.run(["subfinder", "-d", domain], text=True, stdout=subprocess.PIPE).stdout.splitlines()
                for subname in list_sub:
                    #print("subdomains for ",domain, subname)
                    
                    id_sub = SubDomain.objects.filter(subDomain_name=subname)
                    extracted = tldextract.extract(subname)       
                    id_domain = Domain.objects.filter(domain_name="{}.{}".format(extracted.domain, extracted.suffix)) 
                    for idsub in id_sub:
                       for idtool in id_tool:
                           if (FoundFrom.objects.filter(subdomain_id=idsub.id,tool_id=idtool.id).exists()):
                            print("data already exits in the database")
                           else:
                                FoundFrom.objects.update_or_create(
                                subdomain_id=idsub.id, tool_id=idtool.id, scan_date=timezone.now())
                    if (id_sub.exists()):
                        print(f'{subname} "already exist in the database"')
                    else:
                        #extracted = tldextract.extract(subname)
                        for i in id_domain:
                            try:
                                SubDomain.objects.update_or_create(
                                domain_id=i.id, subDomain_name=subname, ip=socket.gethostbyname(subname))   
                            except:
                            #SubDomain.objects.update_or_create(domain_id=i.id, subDomain_name=subname, ip=NULL)
                                 print("no ip found for " + subname, "it isn't a resolved domain")
            else:
                raise ValueError('Invalid input')


#################### Amass ##################
def amass(path):
    Tool.objects.update_or_create(
        tool_name='Amass', tool_url='https://github.com/OWASP/Amass',
        tool_desciption='The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.')
    id_tool = Tool.objects.filter(tool_name='Amass')
    with open(path, 'r') as file:
        for line in file:
            domain = line.strip()

            if re.match(pattern, domain):
                list_sub = subprocess.run(["amass", "enum", "-passive", "-d", domain], text=True,
                                          stdout=subprocess.PIPE).stdout.splitlines()
                for subname in list_sub:
                    # print("subdomains for ",domain, subname)

                    id_sub = SubDomain.objects.filter(subDomain_name=subname)
                    extracted = tldextract.extract(subname)
                    id_domain = Domain.objects.filter(domain_name="{}.{}".format(extracted.domain, extracted.suffix))
                    for idsub in id_sub:
                        for idtool in id_tool:
                            if (FoundFrom.objects.filter(subdomain_id=idsub.id, tool_id=idtool.id).exists()):
                                print("data already exits in the database")
                            else:
                                FoundFrom.objects.update_or_create(
                                    subdomain_id=idsub.id, tool_id=idtool.id, scan_date=timezone.now())
                    if id_sub.exists():
                        print(f'{subname} "already exist in the database"')
                    else:
                        # extracted = tldextract.extract(subname)
                        for i in id_domain:
                            try:
                                SubDomain.objects.update_or_create(
                                    domain_id=i.id, subDomain_name=subname, ip=socket.gethostbyname(subname))
                            except:
                                # SubDomain.objects.update_or_create(domain_id=i.id, subDomain_name=subname, ip=NULL)
                                print("no ip found for " + subname, "it isn't a resolved domain")


# ############################ | Google API | ########################


def google_api(path):
    L=[] #I will use this list to remove double values of a subdomain in the foundfrom table 
    Tool.objects.get_or_create(tool_name="Google API",  tool_url="https://developers.google.com/custom-search/docs/overview",
                                           tool_desciption="Programmable Search Engine enables you to create a search engine for your website, your blog, or a collection of websites. You can configure your engine to search both web pages and images. You can fine-tune the ranking, add your own promotions and customize the look and feel of the search results. You can monetize the search by connecting your engine to your Google AdSense account.")
    id_tool = Tool.objects.filter(tool_name='Google API')
    with open(path, 'r') as file:
        for line in file:
            domain = line.strip()
            if re.match(pattern, domain):
                api_key = "YOURAPIKey"
                search_engine_id = "YOURCredential"  # here put your own credential
                resource = build("customsearch", "v1",
                                 developerKey=api_key).cse()
                request = resource.list(
                    q=f'{domain}', cx=search_engine_id)
                result = request.execute()
               
                for subdomain in result["items"]:
                    L.append(urlparse(subdomain["link"]).netloc)
                L=list(set(L))
                for subdomain in L:    
                    id_sub = SubDomain.objects.filter(
                        subDomain_name=subdomain)
                    extracted = tldextract.extract(subdomain)       
                    id_domain = Domain.objects.filter(domain_name="{}.{}".format(extracted.domain, extracted.suffix))    
                    for idsub in id_sub:
                       for idtool in id_tool:
                         if (FoundFrom.objects.filter(subdomain_id=idsub.id,tool_id=idtool.id).exists()):
                            print("data already exits in the database")
                         else:
                            FoundFrom.objects.update_or_create(
                                subdomain_id=idsub.id, tool_id=idtool.id, scan_date=timezone.now())
                    if (id_sub.exists()):
                        print(
                            f'{subdomain} "already exist in the database"')
                    else:
                        for j in id_domain:
                            try:
                                SubDomain.objects.update_or_create(
                                    domain_id=j.id, subDomain_name=subdomain, ip=socket.gethostbyname(subdomain))

                            except:
                                print("no ip found for ", subdomain, "it isn't a resolved domain")
                                #SubDomain.objects.update_or_create(domain_id=j.id, subDomain_name=urlparse(subdomain["link"]).netloc, ip=NULL)
               

# ##################################### duckduckGo api ############################
def duckDuckGo_api(path):
    L=[]
    Tool.objects.get_or_create(tool_name="DuckDuckGo API",  tool_url="https://pypi.org/project/ddg/",
                                           tool_desciption="ddg is a Python library for querying the DuckDuckGo API.")
    id_tool = Tool.objects.filter(tool_name="DuckDuckGo API")
    with open(path, 'r') as file:
        for line in file:
            domain = line.strip()
        
            if re.match(pattern, domain):
                results = ddg(f'site:{domain}', region='wt-wt',
                              safesearch='Moderate', time='y', max_results=100)
                for i in results:
                    L.append(urlparse(i["href"]).netloc)
                L=list(set(L)) 
                for subdomain in L:   
                    id_sub = SubDomain.objects.filter(subDomain_name=subdomain)
                    #id_sub = SubDomain.objects.raw('SELECT * FROM Domain WHERE subDomain_name= %s', [subdomain])
                    extracted = tldextract.extract(subdomain)
                    id_domain = Domain.objects.filter(domain_name="{}.{}".format(extracted.domain, extracted.suffix))    
                    for idsub in id_sub:
                       for idtool in id_tool:
                         if (FoundFrom.objects.filter(subdomain_id=idsub.id,tool_id=idtool.id).exists()):
                            print("data already exits in the database")
                         else:
                        
                           FoundFrom.objects.update_or_create(
                                subdomain_id=idsub.id, tool_id=idtool.id, scan_date=timezone.now())
                    if (id_sub.exists()):
                        print(
                            f'{subdomain} "already exist in the database"')
                    else:
                        for j in id_domain:
                            try:
                                SubDomain.objects.update_or_create(
                                    domain_id=j.id, subDomain_name=subdomain, ip=socket.gethostbyname(subdomain))
                            except:
                                print("no ip found for ", subdomain, "it isn't a resolved domain")
                                #SubDomain.objects.update_or_create(domain_id=j.id, subDomain_name=subdomain, ip=NULL)
                
                

##########################  |Get All Urls (gau: github tool)|  °/_(-_-)_ ################


def gau(path):
    Tool.objects.get_or_create(tool_name="Get All Urls",  tool_url="https://github.com/lc/gau.git",
                                           tool_desciption="get all urls (gau) fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan for any given domain. Inspired by Tomnomnom's waybackurls.")
    id_tool = Tool.objects.filter(tool_name="Get All Urls")
    with open(path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                domain = line.strip()
                
                if re.match(pattern, domain):
                    liste_url = subprocess.run(["gau", domain], text=True, stdout=subprocess.PIPE, encoding='utf-8').stdout.splitlines()
                    liste_url = list(set(urlparse(url).netloc.translate({ord(i): None for i in ':*0123456789'}) for url in liste_url)) #remove double values

                    
                    for sub in liste_url:
                            
                                id_sub = SubDomain.objects.filter(
                                subDomain_name=sub)
                                extracted = tldextract.extract(sub)
                                id_domain = Domain.objects.filter(domain_name="{}.{}".format(extracted.domain, extracted.suffix))
                                for idsub in id_sub:
                                    for idtool in id_tool:
                                         if (FoundFrom.objects.filter(subdomain_id=idsub.id,tool_id=idtool.id).exists()):
                                            print("data already exits in the database")
                                         else:
                                            FoundFrom.objects.update_or_create(
                                subdomain_id=idsub.id, tool_id=idtool.id, scan_date=timezone.now())
                                if (id_sub.exists()):
                                    print(
                                    f'{sub}'"already exist in the database")
                                else:
                                    
                                    for j in id_domain:
                                        try:
                                            SubDomain.objects.update_or_create(domain_id=j.id,
                                                                           subDomain_name=sub, ip=socket.gethostbyname(sub))
                                        except:
                                            print("no ip found for ", sub, "it isn't a resolved domain")
                                            #SubDomain.objects.update_or_create(domain_id=j.id,subDomain_name=sub, ip=NULL)
                                                                          
                
                

 # ############################  |Virus Total | °/_(-_-)_/° ##############################


def virus_total(path):
    Tool.objects.get_or_create(tool_name="Virus Total",  tool_url="https://www.virustotal.com/gui/home/search",
                                           tool_desciption="VirusTotal is a free service that allows you to scan a file or URL to several antivirus engines.It also offers other details, and it helps to determine whether a file or a site is malicious or safe,it helps you determine the status of the latter")
    id_tool = Tool.objects.filter(tool_name="Virus Total")
    with open(path, 'r') as file:
        for line in file:
            domain = line.strip()
            id_domain = Domain.objects.all()
            if re.match(pattern, domain):
                API_key = 'YOUR API'
                url = 'https://www.virustotal.com/vtapi/v2/domain/report'
                params = {'apikey': API_key, 'domain': domain}
                try:
                    response = requests.get(url, params=params)
                    jdata = response.json()
                    subdomains = sorted(jdata['subdomains'])

                except (KeyError):
                    print("No domains found for ")
                    exit(0)
                except (requests.ConnectionError):
                    print("Could not connect to www.virtustotal.com")
                    exit(1)
                for subdomain in subdomains:
                   # print(subdomain)
                    id_sub = SubDomain.objects.filter(subDomain_name=subdomain)
                    extracted = tldextract.extract(subdomain)
                    id_domain = Domain.objects.filter(domain_name="{}.{}".format(extracted.domain, extracted.suffix))
                    for idsub in id_sub:
                       for idtool in id_tool:
                         if (FoundFrom.objects.filter(subdomain_id=idsub.id,tool_id=idtool.id).exists()):
                            print("data already exits in the database")
                         else:
                        
                           FoundFrom.objects.update_or_create(
                                subdomain_id=idsub.id, tool_id=idtool.id, scan_date=timezone.now())
                    if (id_sub.exists()):
                        print(f'{subdomain} "already exist in the database"')
                    else:
                        #print('ok for: ', subdomain)
                        
                        for j in id_domain:
                            
                            try:
                                # print("ok")
                                SubDomain.objects.update_or_create(domain_id=j.id,
                                                                subDomain_name=subdomain, ip=socket.gethostbyname(subdomain))
                            except:
                                print("no ip found for ", subdomain, "it isn't a resolved domain")

                                #SubDomain.objects.update_or_create(domain_id=j.id,subDomain_name=subdomain, ip=NULL)
                                                                   
                time.sleep(20)  
                
                

################### | crt.sh | ##################################


def crtsh(path):
    l=[]
    Tool.objects.get_or_create(tool_name="crt.sh",  tool_url="https://crt.sh/",
                                           tool_desciption="Crt.sh is a website where you could find all the SSL or TLS certificates of the particular targeted domain. And the site is open-source to monitor the certificates.")
    id_tool = Tool.objects.filter(tool_name="crt.sh")
    with open(path, 'r') as file:
        for line in file:
            domain = line.strip()
            
            if re.match(pattern, domain):
                req = requests.get(
                "https://crt.sh/?q=%.{d}&output=json".format(d=domain))
                if req:
                    json_data = json.loads(req.text)

                    #json_data=req.json()
                    for (key, value) in enumerate(json_data):
                        l.append((value['name_value']).translate({ord(i): None for i in ':*0123456789'}))
                    l=list(set(l))
              
                for sub in l:
                    id_sub = SubDomain.objects.filter(
                    subDomain_name=sub)
                    extracted = tldextract.extract(sub)
                    #dname ="{}.{}".format(extracted.domain, extracted.suffix)
                    #if (Domain.objects.filter(domain_name=dname).exists()):
                    #domainname = Domain.objects.get(domain_name=dname)
                    id_domain = Domain.objects.filter(domain_name="{}.{}".format(extracted.domain, extracted.suffix))
                    for idsub in id_sub:
                        for idtool in id_tool:
                             if (FoundFrom.objects.filter(subdomain_id=idsub.id,tool_id=idtool.id).exists()):
                                print("data already exits in the database")
                             else:
                                FoundFrom.objects.update_or_create(
                                subdomain_id=idsub.id, tool_id=idtool.id, scan_date=timezone.now())
                    if (id_sub.exists()):
                        print(sub, "already existe in the database ")
                    else:
                        #print("ok for ", sub)
                        
                        for j in id_domain:
                            try:
                                SubDomain.objects.update_or_create(domain_id=j.id, subDomain_name=sub, ip=socket.gethostbyname(sub))
                            except: 
                                print("no ip found for ",sub," it isn't a resolved domain")   
                                #SubDomain.objects.update_or_create(domain_id=j.id,subDomain_name=sub, ip=NULL)
                                                             
                
                #id_sub = SubDomain.objects.all()
                
               
######################### rapidDNS #######################
#This is a function to scapt the result of table from the given url
def extract_items(url):
    items = []
    response = requests.get(url)
    html = response.content
    if response.status_code != 200:
      print("no valid status code")
    try:
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table", id="table")
        rows = table.findAll("tr")
        items = []
        for row in rows:
            cells = row.findAll("td")
            items.append([value.text.strip() for value in cells])
    except: 
      print("no")
    return items[1:]
def rapidDNS(path):
    Tool.objects.get_or_create(tool_name="RapidDNS",  tool_url="https://rapiddns.io/",
                                           tool_desciption="RapidDNS is a dns query tool which make querying subdomains or sites of a same ip easy.")
    id_tool = Tool.objects.filter(tool_name="RapidDNS")
    with open(path, 'r') as file:
        for line in file:
            domain = line.strip()
            
            if re.match(pattern, domain):
                 url = f"https://rapiddns.io/subdomain/{domain}?full=1&down=1"
                 l=extract_items(url)
                 n=len(l)
                 list_subdomain=[]
                 for i in range(n):
                    list_subdomain.append(l[i][0])
                 list_subdomain=list(set(list_subdomain)) 
                 for sub in list_subdomain:
                            
                                id_sub = SubDomain.objects.filter(
                                subDomain_name=sub)
                                extracted = tldextract.extract(sub)
                                id_domain = Domain.objects.filter(domain_name="{}.{}".format(extracted.domain, extracted.suffix))
                                for idsub in id_sub:
                                    for idtool in id_tool:
                                         if (FoundFrom.objects.filter(subdomain_id=idsub.id,tool_id=idtool.id).exists()):
                                            print("data already exits in the database")
                                         else:
                                            FoundFrom.objects.update_or_create(
                                subdomain_id=idsub.id, tool_id=idtool.id, scan_date=timezone.now())
                                if (id_sub.exists()):
                                    print(
                                    f'{sub}' "already exist in the database")
                                else:
                                    
                                    for j in id_domain:
                                        try:
                                            SubDomain.objects.update_or_create(domain_id=j.id,
                                                                           subDomain_name=sub, ip=socket.gethostbyname(sub))
                                        except:
                                            print("no ip found for ",sub, " it isn't a resolved domain")
                                            #SubDomain.objects.update_or_create(domain_id=j.id,subDomain_name=sub, ip=NULL)
                                                              






#################       | whois |      °/_(-_-)/    ###############


def whois_Domain():
    compt = Domain.objects.all()
    for i in compt:
        result = asyncwhois.whois_domain(i.domain_name)
        who = result.parser_output
        DomainInfo.objects.update_or_create(domain_id=i.id, registrar=who.get('registrar'), status=who.get('status')[0], dnssec=who.get('dnssec'),
                                            creation_date=who.get('created'),
                                            expiration_date=who.get('expires'), update_date=who.get('updated'))
        # Source(source_name='asyncwhois',source_url="https://pypi.org/project/asyncwhois/")
