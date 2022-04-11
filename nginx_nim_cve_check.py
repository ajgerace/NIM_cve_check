#! /usr/bin/python3

from tokenize import single_quoted
from xml.dom.minidom import parse
from pkg_resources import parse_version
import xml.dom.minidom
import requests, getpass
import json, base64
requests.packages.urllib3.disable_warnings()

def buildAuthHeader():
    nimUser = input('Enter NGINX NIM User name: ').rstrip('\n')
    nimPass = getpass.getpass('Enter NGINX NIM password: ').rstrip('\n')
    nimAuthStr = str.encode(nimUser + ':' + nimPass)
    encodeStr = base64.b64encode(nimAuthStr)
    return encodeStr.decode()

def retrieveInventory():

    authStr = buildAuthHeader()

    headers = {
        'Authorization': 'Basic ' + str(authStr),
        'Content-Type': 'application/json'
    }
    nimHost = input('Enter the hostname or IP address for your NIM instance: ').rstrip('\n')
    response = requests.request('GET', 'https://' + nimHost + '/api/platform/v1/systems', headers=headers, verify=False )
    if response.status_code == 200:
        inv = json.loads(response.text)
        invList = inv['items']
        for dev in invList:
            hostName = dev['hostname']
            if len(dev['nginxInstances']) > 0:
                instanceInfo = dev['nginxInstances'][0]
                if instanceInfo['build']['nginxPlus']:
                    instanceType = 'NginxPlus'
                else:
                    instanceType = "NginxOSS"
                version = instanceInfo['build']['version']
                deviceList[hostName] = {}
                deviceList[hostName]['instanceType'] = instanceType
                deviceList[hostName]['version'] = version
    else:
        print('An error occurred ' + str(response.status_code) )

        
def checkForVuln(vulnStartStr, vulnEndStr, version):
    vulnerable = False
    if vulnStartStr == 'single':
        if parse_version(version) == parse_version(vulnEndStr):
            vulnerable = True
    else:
        if parse_version(version) < parse_version(vulnEndStr):
            if parse_version(version) >= parse_version(vulnStartStr):
                vulnerable = True
        if parse_version(version) == parse_version(vulnEndStr):
            vulnerable = True
    return vulnerable

def pullAdvisoryFile():
    response = requests.request('GET', 'http://hg.nginx.org/nginx.org/raw-file/tip/xml/en/security_advisories.xml')
    if response.status_code == 200:
        f = open(advisoryFile, 'w')
        f.write(response.text)
        f.close()
    else:
        print('Unable to retrieve NGINX security advisory file \n'  )

def parseAdvisories():
    DOMTree = xml.dom.minidom.parse(advisoryFile)
    collection = DOMTree.documentElement
    items = collection.getElementsByTagName("item")
    for rec in items:
    #    print('**** Vulnerability ****')
        name = rec.getAttribute('name')
        sev = rec.getAttribute('severity')
        advisoryURL = rec.getAttribute('advisory')
        cveNum = rec.getAttribute('cve')
        vulnerableStr = rec.getAttribute('vulnerable')
        advisoryList[name] = {}
        advisoryList[name]['severity'] = sev
        advisoryList[name]['url'] = advisoryURL
        advisoryList[name]['cve'] = cveNum
        advisoryList[name]['vulnVersions'] = vulnerableStr

    
        

advisoryFile = 'security_advisories.xml'
output = ''
deviceList = {}
advisoryList = {}
pullAdvisoryFile()
retrieveInventory()
parseAdvisories()
for dev in deviceList:
        deviceName = dev 
        deviceVersion = deviceList[dev]['version']
        devInstanceType = deviceList[dev]['instanceType']
        x = 0
        for vuln in advisoryList:
            vulnerableStr = advisoryList[vuln]['vulnVersions']
            if '-' in vulnerableStr:
                if ',' in vulnerableStr:
                    vulnVersionList = vulnerableStr.split(', ')
                    for vulnStr in vulnVersionList:
                        (vulnStart, vulnEnd) = vulnStr.split('-')
                        isVulnerable = checkForVuln(vulnStart, vulnEnd, deviceVersion)
                else:
                    (vulnStart, vulnEnd) = vulnerableStr.split('-')
                    isVulnerable = checkForVuln(vulnStart, vulnEnd, deviceVersion) 
            else:
                vulnStart = 'single'
                vulnEnd = vulnerableStr
                isVulnerable = checkForVuln(vulnStart,vulnEnd, deviceVersion)             
            if isVulnerable:
                if x == 0:
                    output += "\n******** " + deviceName + " - " + devInstanceType +  " - " + deviceVersion + " ********\n"
                    x +=1
                output += "\t**** Vulnerability ****\n"
                output += "\tName: " + vuln + '\n'
                output += '\tSeverity: ' + advisoryList[vuln]['severity'] + '\n'
                output += '\tCVE: ' + advisoryList[vuln]['cve'] + '\n'
                output += '\tURL:' + advisoryList[vuln]['url'] + '\n'
                output += '\tVulnerable versions: ' + vulnerableStr + '\n'
                output += '\n'
print(output)

