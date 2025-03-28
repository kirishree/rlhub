"""
This script have to run on HUB.
It is running in Django's web frame work.
It should be listening on 5000 port.
whenever the new SPOKEs join with this HUB, SPOKES post the 
details of it.
Here, once it receives the data from SPOKE,
it configure that spoke as neighbor for that corresponding tunnel interface.
Also it adds the route to reach the REAL subnet behind the spoke.
"""

from django.http import HttpRequest, HttpResponse,  JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
import numpy as np  # For percentile calculation
import logging
logger = logging.getLogger('reachlink')
import os
import subprocess
import json
import ipaddress
import pymongo
from pymongo.server_api import ServerApi
import requests
from datetime import datetime
from dateutil.relativedelta import relativedelta
from pyroute2 import IPRoute
ipr = IPRoute()
from netaddr import IPAddress
import threading
import router_configure
import microtek_configure
import time
import yaml
import io
import zipfile
#import the files
import onboarding
import hub_config
import ubuntu_info
import onboardblock
import robustel_configure
from decouple import config
from datetime import timedelta
newuser = False
dummy_expiry_date = ""
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_registered_organization = db_tunnel["registered_organization"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]
coll_dialer_ip = db_tunnel["dialer_ip"]
coll_hub_info = db_tunnel["hub_info"]
coll_spoke_disconnect = db_tunnel["spoke_disconnect"]
vrf1_ip = config('VRF_IP')
url = config('ONBOARDING_API_URL')
hub_ip = config('HUB_IP')
hub_location = config('HUB_LOCATION')
hub_uuid = config('HUB_UUID')
hub_hostid = config('HUB_HOSTID')
gretunnelnetwork = config('GRE_NETWORK')
gretunnelnetworkip = config('HUB_GRE_NETWORKIP')
hub_tunnel_endpoint = config('HUB_GRE_END_POINT')
openvpnhubip = config('HUB_OPENVPN_ENDPOINT')
dialernetworkip = config('DIALER_NERWORK_IP')
dialer_netmask = config('DIALER_NETMASK')
snmpcommunitystring = config('SNMP_COMMUNITY_STRING')
ubuntu_dialerclient_ip = config('UBUNTU_DIALER_CLIENT_IP')
device_info_path = config('DEVICE_INFO_PATH')
reachlink_zabbix_path = config('REACHLINK_ZABBIX_PATH')
robustel_exe_path = config('ROBUSTEL_EXE_PATH')
# Zabbix API URL
zabbix_api_url = config('ZABBIX_API_URL')  # Replace with your Zabbix API URL
# Api key
auth_token = config('ZABBIX_API_TOKEN')
# Zabbix server details
ZABBIX_WEB_URL=config('ZABBIX_WEB_URL')
USERNAME=config('USERNAME')
PASSWORD=config('PASSWORD')
GRAPH_URL=config('GRAPH_URL')

# Step 1: Login using web form
login_payload = {
    "name": USERNAME,
    "password": PASSWORD,
    "enter": "Sign in"
}

# Create a session
session = requests.Session()

def new_client(client_name):
    try:
        # Path configuration
        os.chdir("/etc/openvpn/server/easy-rsa/")
        os.system(f"./easyrsa --batch --days=3650 build-client-full {client_name} nopass")
        base_path = "/etc/openvpn/server"
        client_common_file = os.path.join(base_path, "client-common.txt")
        ca_cert_file = os.path.join(base_path, "easy-rsa/pki/ca.crt")
        client_cert_file = os.path.join(base_path, f"easy-rsa/pki/issued/{client_name}.crt")
        client_key_file = os.path.join(base_path, f"easy-rsa/pki/private/{client_name}.key")
        tls_crypt_file = os.path.join(base_path, "tc.key")

        # Output .ovpn file path
        output_file = os.path.expanduser(f"~/{client_name}.ovpn")

        with open(output_file, "w") as ovpn:
            # Append client-common.txt
            with open(client_common_file, "r") as common:
                ovpn.write(common.read())
        
            # Append CA certificate
            ovpn.write("\n<ca>\n")
            with open(ca_cert_file, "r") as ca_cert:
                ovpn.write(ca_cert.read())
            ovpn.write("</ca>\n")
        
            # Append client certificate
            ovpn.write("<cert>\n")
            with open(client_cert_file, "r") as client_cert:
                # Only read from "BEGIN CERTIFICATE"
                cert_started = False
                for line in client_cert:
                    if "BEGIN CERTIFICATE" in line:
                        cert_started = True
                    if cert_started:
                        ovpn.write(line)
            ovpn.write("</cert>\n")
                    
            # Append client key
            ovpn.write("<key>\n")
            with open(client_key_file, "r") as client_key:
                ovpn.write(client_key.read())
            ovpn.write("</key>\n")
        print(f"Client configuration generated at: {output_file}")
    except Exception as e:
        print(e)

def setass(response, devicename):    
    try:
        connected_spoke =[]
        try:
            time.sleep(40)   
        except Exception as e:
            print(e)
        newspokedevicename = response[0]["spokedevice_name"]        
        newspokeconnstatus = False
        with open(r'/etc/openvpn/server/openvpn-status.log','r') as f:
            lines = f.readlines()
            for row in  lines:     
                data=row.split(",")
                if data[0] == "CLIENT_LIST":
                    collection = {"Tunnel_ip":data[3], "Public_ip":data[2].split(":")[0], "spokedevice_name": data[1]}
                    connected_spoke.append(collection) 
        for spoke in connected_spoke:
            if spoke["spokedevice_name"] == newspokedevicename:
                if devicename == "microtek":
                    query = {"spokedevice_name": newspokedevicename }
                    update_data = {"$set": {"public_ip":spoke["Public_ip"],
                                            "tunnel_ip": spoke["Tunnel_ip"]                                                                       
                                        }
                                       }
                    newspokeconnstatus = True    
                    coll_tunnel_ip.update_many(query, update_data) 
                    organizationid = response[0]["organization_id"]
                    regdevices = coll_registered_organization.find_one({"organization_id":organizationid}) 
                    for dev in regdevices["registered_devices"]:                    
                        if "microtek_spokes_info" in dev:                             
                                for mispoke in  dev["microtek_spokes_info"]:                         
                                    if newspokedevicename == mispoke["spokedevice_name"]:
                                        mispoke["tunnel_ip"] = spoke["Tunnel_ip"] 
                                        mispoke["public_ip"] = spoke["Public_ip"]                                 
                                        
                    query = {"organization_id": organizationid}
                    update_data = {"$set": {
                                        "registered_devices": regdevices["registered_devices"]                                                                           
                                        }
                                       }
                    coll_registered_organization.update_many(query, update_data)   
                elif devicename == "robustel":
                    query = {"spokedevice_name": newspokedevicename }
                    update_data = {"$set": {"public_ip":spoke["Public_ip"],
                                            "tunnel_ip": spoke["Tunnel_ip"]                                                                       
                                        }
                                       }
                    newspokeconnstatus = True    
                    coll_tunnel_ip.update_many(query, update_data) 
                    organizationid = response[0]["organization_id"]
                    regdevices = coll_registered_organization.find_one({"organization_id":organizationid}) 
                    for dev in regdevices["registered_devices"]:                    
                        if "robustel_spokes_info" in dev:                             
                                for rospoke in  dev["robustel_spokes_info"]:                         
                                    if newspokedevicename == rospoke["spokedevice_name"]:
                                        rospoke["tunnel_ip"] = spoke["Tunnel_ip"] 
                                        rospoke["public_ip"] = spoke["Public_ip"]                               
                                        
                    query = {"organization_id": organizationid}
                    update_data = {"$set": {
                                        "registered_devices": regdevices["registered_devices"]                                                                           
                                        }
                                       }
                    coll_registered_organization.update_many(query, update_data)                                  
                else:
                    newspokeovpnip = spoke["Tunnel_ip"]
                    newspokeconnstatus = True
                    newspokegreip = response[0]["gretunnel_ip"].split("/")[0]
                    command = f"sudo ip neighbor replace {newspokegreip} lladdr {newspokeovpnip} dev Reach_link1"
                    subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                    query = {"spokedevice_name": newspokedevicename }
                    update_data = {"$set": {"public_ip":newspokeovpnip                                                                         
                                        }
                                       }
                    coll_tunnel_ip.update_many(query, update_data)
                os.system(f"python3 {reachlink_zabbix_path}")
                os.system("systemctl restart reachlink_test")                           
        if not newspokeconnstatus:
            print(f"New spoke is not connected yet({newspokedevicename}). Trying again")
            setass(response, devicename)
        else:
            print(f"GRE tunnel created successfully for this {newspokedevicename}.")
    except Exception as e:
        print(f"set ass execption:{e}")

@api_view(['POST'])
def login_or_register(request):
    username = request.data.get("username")
    password = request.data.get("password")

    if not username or not password:
        return Response({"error": "Username and password are required"}, status=400)

    # Authenticate existing user
    user = authenticate(username=username, password=password)

    if user:
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "message": "User authenticated successfully"
        })

    # Perform your custom validation before creating a new user (add logic here)
    # Example: Check if username meets your policy, etc.
    onboard_status = onboarding.check_onboarding(username, password)
    if onboard_status == "True":
        # Create new user
        user = User.objects.create_user(username=username, password=password)

        # Generate JWT tokens for new user
        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "message": "User registered and authenticated successfully"
        })
    else:
        return Response({            
            "message": onboard_status
        })
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def login(request: HttpRequest):
    data = json.loads(request.body)
    print(data)
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for configure spoke: {request.method} {request.path} Requested ip: {public_ip}')
    global newuser
    try:
        response, newuser = onboarding.check_user(data, newuser)        
        if newuser:
            userStatus = onboarding.authenticate_user(data)
            print(userStatus)
            if userStatus:
                response, newuser = onboarding.check_user(data, newuser)
            else:
                response = [{"message": userStatus,"expiry_date": dummy_expiry_date}]
        if "spokedevice_name" in response[0]:
            client_name = response[0]["spokedevice_name"]
            output_file = os.path.expanduser(f"~/{client_name}.ovpn")
            if not os.path.exists(output_file):
                print("Generating new client")
                new_client(client_name)    
            else:
                print("Client already available")
            with open(output_file, 'r') as file:
                conffile_content = file.read()
                file.close()
            response1 = HttpResponse(conffile_content, content_type='text/plain')
            response1['Content-Disposition'] = f'attachment; filename="{client_name}.ovpn"'
            response1['X-Message'] = json.dumps(response)
            background_thread = threading.Thread(target=setass, args=(response,"ubuntu",))
            background_thread.start() 
        else:
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(response)        
    except Exception as e:
        logger.error(f"Error: Login request: {e}")
        response = [{"message": "Internal Server Error", "expiry_date": dummy_expiry_date}]
        response1 = HttpResponse(content_type='text/plain')
        response1['X-Message'] = json.dumps(response)
    return response1

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_cisco_device(request: HttpRequest):
    data = json.loads(request.body)  
    global newuser
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for configure spoke: {request.method} {request.path} Requested ip: {public_ip}')
    print(f"requested ip of add cisco device spoke:{public_ip}") 
    if data["device"].lower() == "robustel":        
        data["uuid"] = data['branch_location'] + "_robustel.net"
        print(data)
        data["username"] = "none"
        data["password"] = "none"        
        try:
            response, newuser = onboarding.check_user(data, newuser)        
            if newuser:
                userStatus = onboarding.authenticate_user(data)
                print(userStatus)
                if userStatus:
                    response, newuser = onboarding.check_user(data, newuser)
                else:
                    response = [{"message": userStatus,"expiry_date": dummy_expiry_date}]
            if "spokedevice_name" in response[0]:
                client_name = response[0]["spokedevice_name"]
                # Path configuration
                output_file = os.path.expanduser(f"~/{client_name}.ovpn")
                if not os.path.exists(output_file):
                    print("Generating new client")
                    new_client(client_name)    
                else:
                    print("Client already available")
                base_path = "/etc/openvpn/server"
                ca_cert_file = os.path.join(base_path, "easy-rsa/pki/ca.crt")
                client_cert_file = os.path.join(base_path, f"easy-rsa/pki/issued/{client_name}.crt")
                client_key_file = os.path.join(base_path, f"easy-rsa/pki/private/{client_name}.key")
                
                with open(ca_cert_file, "r") as f:
                    cacrt = f.read()
                    f.close()
                with open(client_cert_file, "r")as f:
                    clientcrt = f.read()
                    f.close()
                with open(client_key_file, "r") as f:
                    clientkey = f.read()
                    f.close()
                with open(robustel_exe_path, "rb") as f:
                    robustelexe = f.read()
                    f.close()
                files_to_send = {
                    "ca.crt": cacrt,
                    "client.crt": clientcrt,
                    "client.key": clientkey,
                    "reachlink_robustel_config.exe": robustelexe  # Keep binary
                }
                # Create a buffer for the ZIP file
                buffer = io.BytesIO()

                # Create a ZIP archive
                with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for filename, content in files_to_send.items():
                        zip_file.writestr(filename, content)

                # Prepare the response
                buffer.seek(0)
                json_response = [{"message": response[0]["message"]}]
                response1 = HttpResponse(buffer, content_type='application/zip')
                response1['Content-Disposition'] = 'attachment; filename="reachlink_conf.zip"'
                response1['X-Message'] = json.dumps(json_response)
                response1["Access-Control-Expose-Headers"] = "X-Message"
                background_thread = threading.Thread(target=setass, args=(response, "robustel",))
                background_thread.start() 
                os.system(f"python3 {reachlink_zabbix_path}")
                os.system("systemctl restart reachlink_test") 
            else:
                response1 = HttpResponse(content_type='text/plain')
                response1['X-Message'] = json.dumps(response)    
                response1["Access-Control-Expose-Headers"] = "X-Message"    
        except Exception as e:
            logger.error(f"Error: Configure Robustel Spoke: {e}")
            response = [{"message": "Internal Server Error", "expiry_date": dummy_expiry_date}]
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(response)
            response1["Access-Control-Expose-Headers"] = "X-Message"
        return response1    
    if data["device"].lower() == "mikrotek":        
        data["uuid"] = data['branch_location'] + "_microtek.net"
        print(data)
        data["username"] = "none"
        data["password"] = "none"        
        try:
            response, newuser = onboarding.check_user(data, newuser)        
            if newuser:
                userStatus = onboarding.authenticate_user(data)
                print(userStatus)
                if userStatus:
                    response, newuser = onboarding.check_user(data, newuser)
                else:
                    response = [{"message": userStatus,"expiry_date": dummy_expiry_date}]
            if "spokedevice_name" in response[0]:
                client_name = response[0]["spokedevice_name"]
                # Path configuration
                output_file = os.path.expanduser(f"~/{client_name}.ovpn")
                if not os.path.exists(output_file):
                    print("Generating new client")
                    new_client(client_name)    
                else:
                    print("Client already available")                
                base_path = "/etc/openvpn/server"
                ca_cert_file = os.path.join(base_path, "easy-rsa/pki/ca.crt")
                client_cert_file = os.path.join(base_path, f"easy-rsa/pki/issued/{client_name}.crt")
                client_key_file = os.path.join(base_path, f"easy-rsa/pki/private/{client_name}.key")
                with open(output_file, "r") as f:
                    ovpnfile = f.read()
                    f.close()                
                with open("/root/reachlink/reachlink_microtek_config.exe", "rb") as f:
                    microtekexe = f.read()
                    f.close()
                files_to_send = {                    
                    f"{client_name}.ovpn": ovpnfile,
                    "reachlink_microtek_config.exe": microtekexe  # Keep binary
                }
                # Create a buffer for the ZIP file
                buffer = io.BytesIO()

                # Create a ZIP archive
                with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for filename, content in files_to_send.items():
                        zip_file.writestr(filename, content)
                # Prepare the response
                buffer.seek(0)
                json_response = [{"message": response[0]["message"]}]
                response1 = HttpResponse(buffer, content_type='application/zip')
                response1['Content-Disposition'] = 'attachment; filename="reachlink_conf.zip"'
                response1['X-Message'] = json.dumps(json_response)
                response1["Access-Control-Expose-Headers"] = "X-Message"
                #background_thread = threading.Thread(target=setass, args=(response, "microtek",))
                #background_thread.start() 
                os.system(f"python3 {reachlink_zabbix_path}")
                os.system("systemctl restart reachlink_test")   
            else:
                response1 = HttpResponse(content_type='text/plain')
                response1['X-Message'] = json.dumps(response)    
                response1["Access-Control-Expose-Headers"] = "X-Message"    
        except Exception as e:
            print(f"Error: Configure Microtek Spoke:{e}")
            logger.error(f"Error: Configure Microtek Spoke:{e}")
            response = [{"message": "Internal Server Error", "expiry_date": dummy_expiry_date}]
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(response)
            response1["Access-Control-Expose-Headers"] = "X-Message"
        return response1
    if data["device"].lower() == "cisco":     
        if  data.get("dialer_ip", "") != hub_ip:
            check_hub_configured = coll_hub_info.find_one({"hub_wan_ip_only": data.get("dialer_ip", "")})
            if not check_hub_configured:
                json_response = [{"message": f"Error:Hub not configured yet. Pl configure HUB first."}]
                response = HttpResponse(content_type='application/zip')
                response['X-Message'] = json.dumps(json_response)
                response["Access-Control-Expose-Headers"] = "X-Message"
                return response
            data["uuid"] = data['branch_location'] + "_" + data["dialer_ip"] + "_ciscodevice.net"
        else:
            data["uuid"] = data['branch_location'] + "_" + data["dialer_ip"] + "_cisco_ubuntu.net"
        print(data)
        data["username"] = "none"
        data["password"] = "none" 
        try:
            response, newuser = onboarding.check_user(data, newuser)
            if newuser:
                userStatus = onboarding.authenticate_user(data)            
                if userStatus:
                    response, newuser = onboarding.check_user(data, newuser)
                else:
                    response = [{"message": userStatus,"expiry_date": dummy_expiry_date}]
            print(response)
            if response[0]["message"] == "Successfully Registered" or response[0]["message"] == "This Cisco Spoke is already Registered":
                devicename = response[0]["spokedevice_name"]
                devicedialerinfo = coll_dialer_ip.find_one({"dialerusername":devicename})
                dialer_ip = data.get("dialer_ip", "")
                if not devicedialerinfo:
                    if data.get("dialer_ip", "") != hub_ip:
                        newdialerinfo = hub_config.get_dialer_ip_fromciscohub(devicename, dialer_ip )
                    else:
                        newdialerinfo = ubuntu_info.get_dialer_ip(devicename)
                    routerpassword = hub_config.generate_router_password_cisco()
                    if newdialerinfo:
                        newdialerinfo["router_username"] = devicename.lower()
                        newdialerinfo["router_password"] = routerpassword
                        newdialerinfo["spokedevice_name"] = devicename
                        newdialerinfo["uuid"] = data["uuid"]
                        newdialerinfo["hub_dialer_wildcardmask"] = ".".join(str(255 - int(octet)) for octet in newdialerinfo["hub_dialer_netmask"].split("."))
                        newdialerinfo["router_wan_ip_only"] = data["router_wan_ip"].split("/")[0]
                        subnet = ipaddress.IPv4Network(data["router_wan_ip"], strict=False)  # Allow non-network addresses
                        newdialerinfo["router_wan_ip_netmask"] = str(subnet.netmask) 
                        coll_dialer_ip.insert_one({"uuid": data["uuid"],
                                                "router_username": devicename.lower(),
                                                "router_password": newdialerinfo["router_password"],
                                                "spokedevice_name": devicename,
                                                "dialerip":newdialerinfo["dialerip"],
                                                "dialerpassword": newdialerinfo["dialerpassword"],
                                                "dialerusername": devicename,
                                                "dialer_hub_ip":dialer_ip,
                                                "router_wan_ip_only": newdialerinfo["router_wan_ip_only"],
                                                "router_wan_ip_netmask": newdialerinfo["router_wan_ip_netmask"],
                                                "router_wan_ip_gateway": data["router_wan_gateway"],
                                                "hub_dialer_network": newdialerinfo["hub_dialer_network"],
                                                "hub_dialer_netmask":newdialerinfo["hub_dialer_netmask"],
                                                "hub_dialer_wildcardmask": newdialerinfo["hub_dialer_wildcardmask"],
                                                "branch_location": data["branch_location"]
                                                }) 
                        organizationid = response[0]["organization_id"]
                        regdevices = coll_registered_organization.find_one({"organization_id":organizationid}) 
                        if data.get("dialer_ip", "") != hub_ip:
                            for dev in regdevices["registered_devices"]:                    
                                if "cisco_hub_info" in dev:
                                    if data["dialer_ip"] == dev["cisco_hub_info"]["hub_wan_ip_only"]: 
                                        for cispoke in  dev["cisco_spokes_info"]:                         
                                            if data["uuid"] == cispoke["uuid"]:
                                                cispoke["router_username"] = devicename.lower()
                                                cispoke["router_password"] = newdialerinfo["router_password"]
                                                cispoke["spokedevice_name"] = devicename
                                                cispoke["dialerip"] =  newdialerinfo["dialerip"]
                                                cispoke["dialerpassword"] = newdialerinfo["dialerpassword"]
                                                cispoke["dialerusername"] = devicename
                                                cispoke["dialer_hub_ip"] = dialer_ip
                                                cispoke["router_wan_ip_only"] = newdialerinfo["router_wan_ip_only"]
                                                cispoke["router_wan_ip_netmask"] = data["router_wan_gateway"]
                                                cispoke["router_wan_ip_gateway"] = data["router_wan_gateway"]                     
                                                cispoke["hub_dialer_network"] = newdialerinfo["hub_dialer_network"]
                                                cispoke["hub_dialer_netmask"] = newdialerinfo["hub_dialer_netmask"]
                                                cispoke["hub_dialer_wildcardmask"] = newdialerinfo["hub_dialer_wildcardmask"]
                                                cispoke["branch_location"] = data["branch_location"]
                        else:
                            for dev in regdevices["registered_devices"]:                    
                                if "reachlink_hub_info" in dev:
                                    if data["dialer_ip"] == dev["reachlink_hub_info"]["hub_ip"]: 
                                        for cispoke in  dev["cisco_spokes_info"]:                         
                                            if data["uuid"] == cispoke["uuid"]:
                                                cispoke["router_username"] = devicename.lower()
                                                cispoke["router_password"] = newdialerinfo["router_password"]
                                                cispoke["spokedevice_name"] = devicename
                                                cispoke["dialerip"] =  newdialerinfo["dialerip"]
                                                cispoke["dialerpassword"] = newdialerinfo["dialerpassword"]
                                                cispoke["dialerusername"] = devicename
                                                cispoke["dialer_hub_ip"] = dialer_ip
                                                cispoke["router_wan_ip_only"] = newdialerinfo["router_wan_ip_only"]
                                                cispoke["router_wan_ip_netmask"] = data["router_wan_gateway"]
                                                cispoke["router_wan_ip_gateway"] = data["router_wan_gateway"]                     
                                                cispoke["hub_dialer_network"] = newdialerinfo["hub_dialer_network"]
                                                cispoke["hub_dialer_netmask"] = newdialerinfo["hub_dialer_netmask"]
                                                cispoke["hub_dialer_wildcardmask"] = newdialerinfo["hub_dialer_wildcardmask"]
                                                cispoke["branch_location"] = data["branch_location"]
                        query = {"organization_id": organizationid}
                        update_data = {"$set": {
                                        "registered_devices": regdevices["registered_devices"]                                                                           
                                        }
                                       }
                        coll_registered_organization.update_many(query, update_data)                                          
                        dialerinfo = coll_dialer_ip.find_one({"uuid": data["uuid"]}, {"_id":0})        
                        coll_tunnel_ip.insert_one(dialerinfo)                    
                    else:
                        json_response = [{"message": f"Error:while generating dialerip"}]
                        response = HttpResponse(content_type='application/zip')
                        response['X-Message'] = json.dumps(json_response)
                        response["Access-Control-Expose-Headers"] = "X-Message"
                        return response
                else:
                    newdialerinfo = devicedialerinfo                 
                # Create a buffer for the ZIP file
                buffer = io.BytesIO()
                if data.get("dialer_ip", "") != hub_ip:
                    # Create a ZIP archive
                    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                        # Read the EXE file and add it to the ZIP
                        with open("reachlink_config.exe", "rb") as f:
                            zip_file.writestr("reachlink_config.exe", f.read())
                    # Prepare the response
                    buffer.seek(0)
                else:
                    # Create a ZIP archive
                    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                        # Read the EXE file and add it to the ZIP
                        with open("reachlink_cisco_config.exe", "rb") as f:
                            zip_file.writestr("reachlink_config.exe", f.read())
                    # Prepare the response
                    buffer.seek(0)
                json_response = [{"message": response[0]["message"]}]
                response = HttpResponse(buffer, content_type='application/zip')
                response['Content-Disposition'] = 'attachment; filename="reachlink_conf.zip"'
                response['X-Message'] = json.dumps(json_response)
                response["Access-Control-Expose-Headers"] = "X-Message"
                #Currently registered device to show via frontend
                registered_data = coll_tunnel_ip.find_one({"uuid": data["uuid"]})
                print("regdata",registered_data)             
                os.system(f"python3 {reachlink_zabbix_path}")
                os.system("systemctl restart reachlink_test")            
                return response
            else:
                json_response = [{"message": f"Error:{response[0]['message']}"}]
        except Exception as e:
            print("device add exception", e)
            logger.error(f"Error: Configure cisco spoke:{e}")
            json_response = [{"message": f"Error:Internal Server Error"}]
        print(json_response)
        response = HttpResponse(content_type='application/zip')
        response['X-Message'] = json.dumps(json_response)
        response["Access-Control-Expose-Headers"] = "X-Message"
        return response

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_cisco_hub(request: HttpRequest):
    data = json.loads(request.body)    
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of add cisco hub:{public_ip}")
    logger.debug(f'Received request for configure HUB: {request.method} {request.path} Requested ip: {public_ip}')
    subnet = ipaddress.IPv4Network(data["hub_dialer_ip"], strict=False)  # Allow non-network addresses
    hub_dialer_netmask = str(subnet.netmask) 
    # Extract the network address
    hub_dialer_network = str(subnet.network_address)   
    for hubinf in coll_hub_info.find({}):
        if hubinf["hub_dialer_network"] == hub_dialer_network:
            if hubinf["hub_ip"] != data["hub_ip"]:
                json_response = [{"message": f"Error: This Dialer network ID already available, pl choose different one."}]
                print(json_response)
                response = HttpResponse(content_type='application/zip')
                response['X-Message'] = json.dumps(json_response)
                response["Access-Control-Expose-Headers"] = "X-Message"
                return response
    data["uuid"] = data['branch_location'] + "_ciscohub.net"
    print(data)
    data["username"] = "none"
    data["password"] = "none" 
    global newuser
    try:
        response, newuser = onboarding.check_user(data, newuser)
        print(response)
        print(newuser)
        if newuser:
            userStatus = onboarding.authenticate_user(data)
            print(userStatus)
            if userStatus:
                response, newuser = onboarding.check_user(data, newuser)
            else:
                response = [{"message": userStatus,"expiry_date": dummy_expiry_date}]
        print(response)
        if response[0]["message"] == "Successfully Registered" or response[0]["message"] == "This Cisco HUB is already Registered":
            devicename = response[0]["spokedevice_name"]
            devicename = devicename   
            devicehubinfo = coll_hub_info.find_one({"hub_wan_ip_only":data["hub_ip"].split("/")[0]})            
            coll_tunnel_ip.delete_many({"uuid":data["uuid"]})
            if not devicehubinfo:
                devicehubinfo = {}
                devicehubinfo["router_username"] = devicename.lower()
                devicehubinfo["router_password"] = hub_config.generate_router_password_cisco() 
                devicehubinfo["hub_dialer_ip"] = data["hub_dialer_ip"].split("/")[0]
                devicehubinfo["hub_dialer_netmask"] = hub_dialer_netmask
                # Extract the network address
                devicehubinfo["hub_dialer_network"] = hub_dialer_network                   
                data["hub_wan_ip"] = data["hub_ip"]                
                devicehubinfo["hub_wan_ip_only"] = data["hub_wan_ip"].split("/")[0]
                wansubnet = ipaddress.IPv4Network(data["hub_wan_ip"], strict=False)  # Allow non-network addresses
                devicehubinfo["hub_wan_ip_netmask"] = str(wansubnet.netmask)          
                coll_hub_info.insert_one({"uuid": data["uuid"],
                                                "router_username": devicename.lower(),
                                                "router_password": devicehubinfo["router_password"],
                                                "hubdevice_name": devicename,
                                                "hub_dialer_ip": devicehubinfo["hub_dialer_ip"],
                                                "hub_dialer_netmask": devicehubinfo["hub_dialer_netmask"],
                                                "hub_dialer_network": devicehubinfo["hub_dialer_network"],
                                                "hub_ip":data["hub_ip"],
                                                "hub_wan_ip_only": devicehubinfo["hub_wan_ip_only"] ,
                                                "hub_wan_ip_netmask": devicehubinfo["hub_wan_ip_netmask"],
                                                "hub_wan_ip_gateway": data["hub_wan_ip_gateway"],
                                                'branch_location': data["branch_location"],
                                                "hub_dialer_ip_cidr": data["hub_dialer_ip"]
                                                }) 
                organizationid = response[0]["organization_id"]
                regdevices = coll_registered_organization.find_one({"organization_id":organizationid}) 
                for dev in regdevices["registered_devices"]:                    
                    if "cisco_hub_info" in dev:
                        if data["uuid"] == dev["cisco_hub_info"]["uuid"]:
                            dev["cisco_hub_info"]["router_username"] = devicename.lower()
                            dev["cisco_hub_info"]["router_password"] = devicehubinfo["router_password"]
                            dev["cisco_hub_info"]["hubdevice_name"] = devicename
                            dev["cisco_hub_info"]["hub_dialer_ip"] =  devicehubinfo["hub_dialer_ip"]
                            dev["cisco_hub_info"]["hub_dialer_netmask"] = devicehubinfo["hub_dialer_netmask"]
                            dev["cisco_hub_info"]["hub_dialer_network"] = devicehubinfo["hub_dialer_network"]
                            dev["cisco_hub_info"]["hub_ip"] = data["hub_ip"]
                            dev["cisco_hub_info"]["hub_wan_ip_only"] = devicehubinfo["hub_wan_ip_only"]
                            dev["cisco_hub_info"]["hub_wan_ip_netmask"] = devicehubinfo["hub_wan_ip_netmask"]
                            dev["cisco_hub_info"]["hub_wan_ip_gateway"] = data["hub_wan_ip_gateway"]                      
                            dev["cisco_hub_info"]["hub_dialer_ip_cidr"] = data["hub_dialer_ip"]
                query = {"organization_id": organizationid}
                update_data = {"$set": {
                                        "registered_devices": regdevices["registered_devices"]                                                                           
                                        }
                                       }
                coll_registered_organization.update_many(query, update_data)
                network = ipaddress.ip_network(data["hub_dialer_ip"], strict=False)
                first_ip = list(network.hosts())[0]
                if str(first_ip) == devicehubinfo["hub_dialer_ip"]:
                    first_ip = list(network.hosts())[1]
                unitno = len([f for f in os.listdir("/etc/ppp/peers/") if os.path.isfile(os.path.join("/etc/ppp/peers/", f))])
                list1 = ["{hub_ip}",
                         "{dialer_ubuntu_ip}",
                         "{dialer_hub_ip}",
                         "{unitno}"
                         ] 
                
                list2 = [devicehubinfo["hub_wan_ip_only"],
                         str(first_ip),
                         devicehubinfo["hub_dialer_ip"],
                         str(unitno)
                         ]
                with open("pon.txt", "r") as f:
                    data1 = f.read()
                    f.close()
                for i in range(0, len(list1)):
                    data1 = data1.replace(list1[i], list2[i]) 
                with open(f"/etc/ppp/peers/{devicename.lower()}", "w") as f:
                    f.write(data1)
                    f.close()
                os.system(f"python3 {reachlink_zabbix_path}")                
                os.system("systemctl restart reachlink_test")  
            
            # Create a buffer for the ZIP file
            buffer = io.BytesIO()
            # Create a ZIP archive
            with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Read the EXE file and add it to the ZIP
                with open("reachlink_hub_config.exe", "rb") as f:
                    zip_file.writestr("reachlink_hub_config.exe", f.read())
            # Prepare the response
            buffer.seek(0)
            json_response = [{"message": response[0]["message"]}]
            response = HttpResponse(buffer, content_type='application/zip')
            response['Content-Disposition'] = 'attachment; filename="reachlink_hub_conf.zip"'
            response['X-Message'] = json.dumps(json_response)
            response["Access-Control-Expose-Headers"] = "X-Message"
            print("hub config response", response)
            return response
        else:
            json_response = [{"message": f"Error:{response[0]['message']}"}]
    except Exception as e:
        print(e)
        logger.error(f"Error: Configure cisco HUB:{e}")
        json_response = [{"message": f"Error:Internal Server Error"}]
    print(json_response)
    response = HttpResponse(content_type='application/zip')
    response['X-Message'] = json.dumps(json_response)
    response["Access-Control-Expose-Headers"] = "X-Message"
    return response

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def homepage_info(request: HttpRequest):
    try:        
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Home page info: {request.method} {request.path} Requested ip: {public_ip}')
        response = {}
        total_no_branches = 0
        organization_id = str(request.GET.get('organization_id'))
        with open(device_info_path, "r") as f:
            total_devices = json.load(f)
            f.close()
        organization_registered = False
        for device in total_devices:
            if device["organization_id"] == organization_id:
                organization_registered = True
                total_no_branches = device["total_no_active_spokes"] + device["total_no_inactive_spokes"]
                hub_info = []
                bandwidth_info = []
                for hubs in device["hub_info"]:
                    hub_info.append({hubs["hub_location"]: {"hub_status":hubs["hub_status"],
                                                            "no_of_active_branches": len(hubs["active_spokes"]),
                                                            "no_of_inactive_branches": len(hubs["inactive_spokes"]),
                                                            "active_branches": hubs["active_spokes"],
                                                            "inactive_branches": hubs["inactive_spokes"]
                                                            }
                                    })
                    bandwidth_info.append({hubs["hub_location"]: {"hub_status":hubs["hub_status"],
                                                            "no_of_active_branches": len(hubs["active_spokes"]),
                                                            "no_of_inactive_branches": len(hubs["inactive_spokes"]),
                                                            "branch_data": hubs["bandwidth_info"],
                                                            "hub_data": hubs["bandwidth_info_hub"]                                                     
                                                            }
                                    })
                response = {
                            "total_no_hubs": device["no_of_hubs"],
                            "active_no_hubs": device["no_active_hubs"],
                            "inactive_no_hubs": device["no_inactive_hubs"],
                            "hub_summary": str(device["no_active_hubs"]) + "/" + str(device["no_of_hubs"]),
                            "total_no_branches": total_no_branches,
                            "active_no_branches": device["total_no_active_spokes"],
                            "inactive_no_branches": device["total_no_inactive_spokes"],
                            "branch_summary": str(device["total_no_active_spokes"]) + "/" + str(total_no_branches),
                            "hub_info": hub_info,  
                            "bandwidth_info":bandwidth_info,                         
                            "organization_id": organization_id
                            }
                return JsonResponse(response, safe=False)
    except Exception as e:
        logger.error(f"Error: Home Page info:{e}")   
    for device in total_devices:
        hub_info = []
        bandwidth_info = []
        for hubs in device["hub_info"]:
            if hubs["hub_location"] == "Reachlink_server":
                hub_info.append({hubs["hub_location"]: {"hub_status":hubs["hub_status"],
                                                            "no_of_active_branches": 0,
                                                            "no_of_inactive_branches": 0,
                                                            "active_branches": [],
                                                            "inactive_branches": []
                                                            }
                                    })
                bandwidth_info.append({hubs["hub_location"]: {"hub_status":hubs["hub_status"],
                                                            "no_of_active_branches": 0,
                                                            "no_of_inactive_branches": 0,
                                                            "branch_data": [],
                                                            "hub_data": hubs["bandwidth_info_hub"]                                                     
                                                            }
                                    })
                response = {
                            "total_no_hubs": 1,
                            "active_no_hubs": 1,
                            "inactive_no_hubs": 0,
                            "hub_summary": "1/1",
                            "total_no_branches": 0,
                            "active_no_branches": 0,
                            "inactive_no_branches": 0,
                            "branch_summary": "0/0",
                            "hub_info": hub_info, 
                            "bandwidth_info": bandwidth_info,                             
                            "organization_id": organization_id
                            }
    return JsonResponse(response, safe=False)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def branch_info(request: HttpRequest):
    try:       
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Branch info: {request.method} {request.path} Requested ip: {public_ip}')
        response = {}
        data = []     
        active_branches = 0
        inactive_branches = 0
        total_no_branches = 0
        organization_id = str(request.GET.get('organization_id'))
        with open(device_info_path, "r") as f:
            total_devices = json.load(f)
            f.close()
        for device in total_devices:
            if device["organization_id"] == organization_id:
                response = {    "data":device["branch_info_only"],
                        "total_branches":device["total_no_active_spokes"] + device["total_no_inactive_spokes"],
                        "inactive_branches":device["total_no_active_spokes"],
                        "active_branches": device["total_no_inactive_spokes"],
                        "organization_id": organization_id
                    }
                return JsonResponse(response, safe=False)
    except Exception as e:
        logger.error(f"Error: Getting Branch info:{e}")
    response = {    "data":data,
                        "total_branches":total_no_branches,
                        "inactive_branches":inactive_branches,
                        "active_branches": active_branches,
                        "organization_id": organization_id
                    }
    return JsonResponse(response, safe=False)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def hub_info(request: HttpRequest):
    try:        
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Hub info: {request.method} {request.path} Requested ip: {public_ip}')
        response = {}
        data = []        
        organization_id = str(request.GET.get('organization_id'))
        with open(device_info_path, "r") as f:
            total_devices = json.load(f)
            f.close()
        for device in total_devices:
            if device["organization_id"] == organization_id:
                response = {    "data":device["hub_info_only"],
                        "total_hubs":device["no_of_hubs"],
                        "inactive_hubs":device["no_inactive_hubs"],
                        "active_hubs": device["no_active_hubs"],
                        "organization_id": organization_id
                    }
                return JsonResponse(response, safe=False)
    except Exception as e:
        logger.error(f"Error: Configure Microtek Spoke:{e}")
    data.append({"branch_location": "Reachlink_server",
                                         "hub_ip":hub_ip,
                                         "hub_status":"active",
                                         "uuid": "reachlinkserver.net",
                                         "host_id": hub_hostid,
                                         "hub_dialer_ip_cidr": "10.8.0.1"
                                         })   
    response = {    "data":data,
                        "total_hubs":1,
                        "inactive_hubs":0,
                        "active_hubs": 1,
                        "organization_id": organization_id
                    }
    return JsonResponse(response, safe=False)
###########SPOKE####################
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deactivate(request: HttpRequest):
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    data = json.loads(request.body) 
    logger.debug(f'Received request for Deactivation: {request.method} {request.path} Requested ip: {public_ip}')
    if ".net" not in data.get("uuid", ""):         
        response = ubuntu_info.deactivate(data)
    if "ciscodevice" in data.get("uuid", ""):
        hubinfo = coll_hub_info.find_one({"hub_wan_ip_only": data.get("hub_ip", "")})
        if hubinfo:
            dialerinfo = coll_dialer_ip.find_one({"dialerip":data.get("tunnel_ip", "")})
            if dialerinfo:
                deactivate_data = {"tunnel_ip": data["hub_ip"],
                                   "router_username": hubinfo["router_username"],
                                   "router_password": hubinfo["router_password"],
                                   "username": dialerinfo["dialerusername"]
                                   }
                response = router_configure.removeuser(deactivate_data)
                if response:                    
                    os.system("systemctl restart reachlink_test")   
                    coll_spoke_disconnect.insert_one({"hub_ip": data["hub_ip"], 
                                      "dialer_ip": data["tunnel_ip"],
                                      "uuid":data["uuid"]                                     
                                                                          
                                    })
                    response = {"message":f"Successfully disconnected: {data['tunnel_ip']}"}
                else:
                    response = {"message":f"Error:while deactivating data['tunnel_ip']"}   
        else:
            response = {"message": "Error HUB IP is missed"}
    if "microtek" in data.get("uuid", ""):
        response = ubuntu_info.deactivate(data)
    print(response)
    return JsonResponse(response, safe=False)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def lan_info(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of get lan info:{public_ip}")
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            try:
                response = requests.get(url + "lan_info", headers=headers)  # Timeout set to 5 seconds
                response.raise_for_status()
                print(response)
                # response = requests.post(url+"addroute", data=json_data, headers=headers)
                # Check the response
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    lan_info = json.loads(get_response)
                    print(lan_info)
                    response = {"message":lan_info}              
                else:
                    response = {"message":"Error while getting lan info from spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response_microtek = microtek_configure.laninfo(data)
            response = {"message":response_microtek}
    except Exception as e:
        response = {"message": f"Error: {e}"}
    print(response)
    return JsonResponse(response, safe=False)

@api_view(['POST'])      
@permission_classes([IsAuthenticated])
def lan_config(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of lan config:{public_ip}")
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "lan_config", data=json_data, headers=headers)                                
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    lan_config_response = json.loads(get_response)
                    print(lan_info)
                    response = {"message":lan_config_response["message"]}              
                else:
                    response = {"message":"Error while configuring LAN in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = microtek_configure.lanconfig(data)
    except Exception as e:
        response = {"message": f"Error: {e}"}
    print(response)
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def dhcp_config(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of dhcp_config:{public_ip}")
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "dhcp_config", data=json_data, headers=headers)                               
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    lan_config_response = json.loads(get_response)
                    print(lan_info)
                    response = {"message":lan_config_response["message"]}              
                else:
                    response = {"message":"Error while configuring DHCP in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = microtek_configure.dhcpconfig(data)            
    except Exception as e:
        response = {"message": f"Error: {e}"}
    print(response)
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_interface_details_spoke(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Get interface details: {request.method} {request.path} Requested ip: {public_ip}')
        response = []
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            try:
                response = requests.get(url + "get_interface_details")                                
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)
                    #print(response)      
                else:
                    response =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")                
        elif "microtek" in data["uuid"]:     
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.interfacedetails(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.get_interface_cisco(data)
        elif "robustel" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = robustel_configure.get_interface_robustel(data)
    except Exception as e:
        logger.error(f"Error: Get interafce details of spoke:{e}")
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_vlan_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for create VLAN Interface: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "create_vlan_interface", data=json_data, headers=headers)                                 
                if response.status_code == 200:           
                    print(response.text)
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)            
                else:
                    response = {"message":"Error while configuring VLAN interface in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.createvlaninterface(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.createvlaninterface(data)   
        elif "robustel" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = robustel_configure.createvlaninterface(data) 
    except Exception as e:
        logger.error(f"Error: Create VLAN interface in HUB:{e}")
        response = [{"message": f"Error: While creating VLAN interface"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_sub_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Create Sub-interface: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "create_vlan_interface", data=json_data, headers=headers)                                 
                if response.status_code == 200:           
                    print(response.text)
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)              
                else:
                    response = {"message":"Error while configuring VLAN interface in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.createvlaninterface(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            print("vlan data", data)
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.createsubinterface(data)      
    except Exception as e:
        response = [{"message": f"Error: while creating Sub interface"}]
        logger.error(f"Error: Create Sub Interface spoke:{e}")
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_loopback_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for create Loopback interface: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "create_vlan_interface", data=json_data, headers=headers)  # Timeout set to 5 seconds
                if response.status_code == 200:           
                    print(response.text)
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)     
                else:
                    response = {"message":"Error while configuring VLAN interface in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #interface_details = microtek_configure.createvlaninterface(data)   
            response = [{"message": "Loopback Interface created successfully"}]              
            return JsonResponse(response,safe=False) 
        elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.createloopbackinterface(data)      
    except Exception as e:
        logger.error(f"Error: Create Loopback Interface Spoke:{e}")
        response = [{"message": f"Error: while creating Loopback Intreface"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_tunnel_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for create Tunnel Interface spoke: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "create_tunnel_interface", data=json_data, headers=headers)                                
                if response.status_code == 200:           
                    print(response.text)
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)         
                else:
                    response = {"message":"Error while configuring VLAN interface in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #interface_details = microtek_configure.createtunnelinterface(data)   
            interface_details = [{"message":"Tunnel interface created successfully"}]              
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            print("vlan data", data)
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.createtunnelinterface(data)      
    except Exception as e:
        logger.error(f"Error: Create Tunnel Interface Spoke:{e}")
        response = [{"message": f"Error: While craeting Tunnel interface"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def interface_config_spoke(request):
    try:
        data = json.loads(request.body)
        print(data)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Interface config Spoke: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "interface_config", data=json_data, headers=headers)                           
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)               
                else:
                    response = {"message":"Error while configuring interface in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.interfaceconfig(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            print(data)
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.interfaceconfig(data)
            print(response)
        elif "robustel" in data["uuid"]:
            print(data)
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = robustel_configure.interface_config(data)
            print(response)
    except Exception as e:
        logger.error(f"Error: Configure Interface Spoke:{e}")
        response = {"message": f"Error: while configuring interface"}
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def vlan_interface_delete_spoke(request):
    try:
        data = json.loads(request.body)
        print("vlan delete ", data)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for delete interface spoke: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "vlan_interface_delete", data=json_data, headers=headers)  # Timeout set to 5 seconds
                               
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)                
                               
                else:
                    response = {"message":"Error while deleting VLAN interface in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.deletevlaninterface(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.deletevlaninterface(data)
    except Exception as e:
        logger.error(f"Error: Delete Interface Spoke:{e}")
        response = {"message": f"Error: "}
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_routing_table_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Get routing table spoke: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"               
            try:
                response = requests.get(url + "get_routing_table")                                 
                if response.status_code == 200:      
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    routing_table_response = json.loads(get_response)
                    response = routing_table_response           
                else:                    
                    response =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = []
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            routing_table = microtek_configure.routingtable(data)                      
            return JsonResponse(routing_table,safe=False) 
        elif "cisco" in data["uuid"]:       
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.get_routingtable_cisco(data)
        elif "robustel" in data["uuid"]:       
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = robustel_configure.get_routingtable_robustel(data)
    except Exception as e:
        logger.error(f"Error: Get routing table spoke:{e}")
        response = []
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def add_route_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for add route spoke: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "addstaticroute", data=json_data, headers=headers)                                 
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)                
                else:
                    response = {"message":"Error while deleting VLAN interface in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            route_details = microtek_configure.addroute(data)                 
            return JsonResponse(route_details,safe=False) 
        elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            status = router_configure.addroute(data)
            if status:
                response = {"message": "Successfully route added"}
            else:
                response = {"message":"Error in adding route"}
            print("check",response)
    except Exception as e:
        logger.error(f"Error: Adding route in Spoke:{e}")
        response = {"message": f"Error: while adding route"}
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def del_staticroute_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for del static route spoke: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "delstaticroute", data=json_data, headers=headers)                                 
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)             
                else:
                    response = {"message":"Error while deleting VLAN interface in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            route_details = microtek_configure.delstaticroute(data)                 
            return JsonResponse(route_details,safe=False) 
        elif "cisco" in data["uuid"]:
            router_info = coll_dialer_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            for subnet in data["routes_info"]:
                if subnet["destination"].split("/")[0] == router_info["dialer_hub_ip"]:
                    response = {"message":f"Error: This route ({subnet}) not able to delete"}
                    return JsonResponse(response, safe=False)  
            status = router_configure.delstaticroute(data)
            if status:
                response = {"message": "Successfully route deleted"}
            else:
                response = {"message":"Error in deleting route"}
    except Exception as e:
        logger.error(f"Error: Delete route in Spoke:{e}")
        response = {"message": f"Error: while deleting route"}
    return JsonResponse(response, safe=False)        

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_pbr_info_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for get pbr info spoke: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"                   
            try:
                response = requests.get(url + "getpbrinfo")                                 
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)
                else:
                    response =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = []
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.getconfigurepbr(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #status = router_configure.addroute(data)
            response = []
    except Exception as e:
        logger.error(f"Error: get pbr info spoke:{e}")
        response = []
    print(response)
    return JsonResponse(response, safe=False)

#Ping_hub end point
@api_view(['POST'])  
@permission_classes([IsAuthenticated]) 
def diagnostics(request: HttpRequest):
    data = json.loads(request.body)   
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for ping HUB: {request.method} {request.path} Requested ip: {public_ip}')  
    try:
        if "cisco" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]     
                ping_result = router_configure.pingspoke(data)
                re = ping_result.split("\n")
                last_line = re[-2]
                print(last_line)
                out = last_line.split(" ")[3]            
                print(out)
                if out == "0":
                    response = {"message":f"Error: Subnet {data['subnet']} Not Reachable"}
                else:
                    rtt = last_line.split(" ")[9].split("/")[1]
                    print(rtt)
                    response = {"message":f"Subnet {data['subnet']} Reachable with RTT: {rtt}ms"}
            else:
                response = {"message":f"Error: Hub info not found"}        
        else:
            response = ubuntu_info.diagnostics(data)
    except Exception as e:
        logger.error(f"Error: Ping from HUB:{e}")
    return JsonResponse(response, safe=False)  

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def ping_spoke(request: HttpRequest):  
    try: 
        data = json.loads(request.body) 
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for ping spoke: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data["uuid"]:       
            print(data)
            route_add = {"subnet": data["subnet"]}
            tunnel_ip = data["tunnel_ip"].split("/")[0]
            json_data = json.dumps(route_add)    
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}
            response = requests.post(url+"checksubnet", data=json_data, headers=headers)
            # Check the response
            if response.status_code == 200:           
                json_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                json_response = json.loads(json_response)
                #print(json_response)
                if json_response[0]["avg_rtt"] != -1:
                    response = {"message":f"Subnet {data['subnet']} Reachable with RTT: {json_response[0]['avg_rtt']}ms"}
                else:
                    response = {"message": f"Error: Subnet {data['subnet']} Not Reachable"}
            else:
                print("error response", response)
                response =  {"message": f"Error: Subnet {data['subnet']} Not Reachable" }
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            ping_result = microtek_configure.pingspoke(data)          
            if ping_result == "0":
                response = {"message":f"Error: Subnet {data['subnet']} Not Reachable"}
            else:                
                response = {"message":f"Subnet {data['subnet']} Reachable with RTT: {ping_result}"}
        elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            ping_result = router_configure.pingspoke(data)
            re = ping_result.split("\n")
            last_line = re[-2]
            print(last_line)
            out = last_line.split(" ")[3]            
            print(out)
            if out == "0":
                response = {"message":f"Error: Subnet {data['subnet']} Not Reachable"}
            else:
                rtt = last_line.split(" ")[9].split("/")[1]
                print(rtt)
                response = {"message":f"Subnet {data['subnet']} Reachable with RTT: {rtt}ms"}
    except Exception as e:    
        logger.error(f"Error: Ping from Spoke:{e}")
        response = {"message": f"Error: Subnet {data['subnet']} Not Reachable" }   
    return JsonResponse(response, safe=False)    

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def traceroute_spoke(request):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for traceroute spoke: {request.method} {request.path} Requested ip: {public_ip}')
    host_ip = data.get('trace_ip', None)
    if "microtek" in data["uuid"]:
        router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
        data["router_username"] = router_info["router_username"]
        data["router_password"] = router_info["router_password"]
        trace_result = microtek_configure.traceroute(data)   
        response_msg = {"message": trace_result}            
        return JsonResponse(response_msg,safe=False) 
    if "ciscodevice" in data["uuid"]:        
        device_info = coll_dialer_ip.find_one({"uuid":data["uuid"]})
        if device_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = device_info["router_username"]
                data["router_password"] = device_info["router_password"]        
                trace_result = router_configure.traceroute(data)   
                response_msg = {"message": trace_result}   
                print("traceroute spoke",response_msg)    
        else:
            response_msg = {"message": "Error in connecting HUB"} 
        return JsonResponse(response_msg,safe=False)   
    if host_ip:
        tunnel_ip = data["tunnel_ip"].split("/")[0] 
        url = "http://" + tunnel_ip + ":5000/"
        # Set the headers to indicate that you are sending JSON data
        headers = {"Content-Type": "application/json"}        
        trace_add = {"trace_ip": host_ip}
        json_data = json.dumps(trace_add)
        print(json_data)
        try:
            response = requests.post(url + "traceroute_spoke", data=json_data, headers=headers) 
            if response.status_code == 200:              
                try:
                    content = response.content.decode(response.encoding or 'utf-8', errors='ignore')
                    response_msg = {"message": content}
                    return JsonResponse(response_msg,safe=False)
                except Exception as e:
                   print(e)
                   response = {"message":e}       
            else:
                    response = {"message":"Error while sending route info to spoke"}
        except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
    else:
        response = {"message":"Error:Trace ip is invalid"}
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def traceroute_hub(request):
    data = json.loads(request.body)
    print("trace hub data", data) 
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for Trachroute HUB: {request.method} {request.path} Requested ip: {public_ip}')
    host_ip = data.get('trace_ip', None)
    if "cisco" in data["uuid"]:
        hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
        if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]        
                trace_result = router_configure.traceroute(data)   
                response = {"message": trace_result}   
                print("traceroute hub",response)    
        else:
            response = {"message": "Error in connecting HUB"}        
    else:           
            result1 = subprocess.run(['traceroute', '-d', host_ip], capture_output=True, text=True)
            response = {"message":result1.stdout}
    return JsonResponse(response,safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def addsubnet(request: HttpRequest):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for add route to ReachLink server: {request.method} {request.path} Requested ip: {public_ip}')
        response = ubuntu_info.addsubnet(data)        
    except Exception as e:
        logger.error(f"Error: Add route in ReachLink server:{e}")
        response = {"message": f"Error in adding route, pl try again" }
    return JsonResponse(response, safe=False) 

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def add_ip_rule_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for add ip rule: {request.method} {request.path} Requested ip: {public_ip}')
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "add_ip_rule", data=json_data, headers=headers)                               
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    ip_rule_response = json.loads(get_response)
                    print(lan_info)
                    response = {"message":ip_rule_response["message"]}              
                else:
                    response = {"message":"Error while configuring ip rule in spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
        else:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #status = router_configure.addroute(data)
            response = {"message":"Dummy"}
    except Exception as e:
        logger.error(f"Error: Add IP rule Spoke:{e}")
        response = {"message": f"Error: {e}"}
    print(response)
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def autofix(request: HttpRequest):  
    try:       
        data = json.loads(request.body)  
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for autofix: {request.method} {request.path} Requested ip: {public_ip}')
        response = {"message": f"Successfully fixed the Gateway issue: {data['tunnel_ip']}"}
        route_add = {"default_gw": hub_tunnel_endpoint}
        tunnel_ip = data["tunnel_ip"].split("/")[0]
        json_data = json.dumps(route_add)    
        url = "http://" + tunnel_ip + ":5000/"
        # Set the headers to indicate that you are sending JSON data
        headers = {"Content-Type": "application/json"}
        response1 = requests.post(url+"changedefaultgw", data=json_data, headers=headers)
        # Check the response
        if response1.status_code == 200:           
            json_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
            json_response = json.loads(json_response)                  
        else:
            response = {"message":f"Error while changing gateway:{data['tunnel_ip']}"}
    except Exception as e:    
        logger.error(f"Error: autofix in Spoke:{e}")
    logger.debug(f'Received request: {request.method} {request.path}')      
    return JsonResponse(response, safe=False)  

@api_view(['POST'])    
@permission_classes([IsAuthenticated])
def delsubnet(request: HttpRequest):
    data = json.loads(request.body)   
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for Del subnet spoke: {request.method} {request.path} Requested ip: {public_ip}')
    response = ubuntu_info.background_deletesubnet(data)
    return JsonResponse(response, safe=False)
##############Inactive branch##############
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def activate(request: HttpRequest):
    data = json.loads(request.body)     
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for Activation of spoke: {request.method} {request.path} Requested ip: {public_ip}')
    if ".net" not in data.get("uuid", ""):         
        response = ubuntu_info.activate(data)
    if "ciscodevice" in data.get("uuid", ""):
        hubinfo = coll_hub_info.find_one({"hub_wan_ip_only": data.get("hub_ip", "")})
        if hubinfo:
            dialerinfo = coll_dialer_ip.find_one({"dialerip":data.get("tunnel_ip", "")})
            if dialerinfo:
                activate_data = {"tunnel_ip": data["hub_ip"],
                                   "router_username": hubinfo["router_username"],
                                   "router_password": hubinfo["router_password"],
                                   "username": dialerinfo["dialerusername"],
                                   "password": dialerinfo["dialerpassword"]
                                   }
                response = router_configure.adduser(activate_data)
                if response:
                    coll_spoke_disconnect.delete_many({"uuid": data["uuid"]})
                    response = {"message":f"Successfully activated: {data['tunnel_ip']}"}
                else:
                    response = {"message":f"Error:while activating data['tunnel_ip']"}     
    if "microtek" in data.get("uuid", ""):
        response = ubuntu_info.activate(data)
    return JsonResponse(response, safe=False)

###############HUB info page##############################
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_routing_table(request):
    try:
        data = json.loads(request.body) 
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for HUB routing table: {request.method} {request.path} Requested ip: {public_ip}')
        if "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.get_routingtable_cisco(data)
            else:
                response = []
        elif data["hub_wan_ip"] == hub_ip:
            response  =ubuntu_info.get_routing_table_ubuntu()        
    except Exception as e:
        logger.error(f"Error: Get hub routing table:{e}")
        response = []
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def addstaticroute_hub(request: HttpRequest):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for add static route HUB: {request.method} {request.path} Requested ip: {public_ip}')
        routes = data["routes_info"]    
        for route in routes:
            if route["destination"].split(".")[0] == "127" or route["destination"].split(".")[0] == "169" or int(route["destination"].split(".")[0]) > 223:
                response = {"message":"Error Invalid destination"}
                return JsonResponse(response, safe=False) 
            if dialernetworkip in route["destination"]:
                response = {"message":"Error Invalid destination"}
                return JsonResponse(response, safe=False) 
        if "ciscohub" in data["uuid"]:
            print("hiciscohub")
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                data["subnet_info"] = data["routes_info"]
                status = router_configure.addroute(data)
                if status:
                    response = {"message": "Successfully route added"}
                else:
                    response = {"message":"Error in adding route"}
            else:
                response = {"message":"Error in getting hub info"}
        elif data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.addstaticroute_ubuntu(data)
    except Exception as e:  
        logger.error(f"Error: Add static routing in HUB:{e}")
        response = {"message": f"Error in adding route, pl try again." }
    return JsonResponse(response, safe=False) 

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def delstaticroute_hub(request: HttpRequest):
    response = [{"message":"Successfully deleted"}]
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for Delete static route in HUB: {request.method} {request.path} Requested ip: {public_ip}')
    try:         
        data = json.loads(request.body)      
        print("delstatichub",data)
        if "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                status = router_configure.delstaticroute(data)
                if status:
                    response = {"message": "Successfully route deleted"}
                else:
                    response = {"message":"Error in deleting route"}
        elif data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.delstaticroute_ubuntu(data)
    except Exception as e:
        logger.error(f"Error: Delete static route HUB:{e}")
        response = {"message":f"Error while deleting route"}
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
#@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def get_interface_details_hub(request):
    try:
        data = json.loads(request.body)  
        print(data)  
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Gte interafce details HUB: {request.method} {request.path} Requested ip: {public_ip}')
        if "_ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.get_interface_cisco(data)
            else:
                response = []
        elif data["hub_wan_ip"] == hub_ip:            
            response = ubuntu_info.get_interface_details_ubuntu(data)            
    except Exception as e:
        logger.error(f"Error: Get Interface_details of HUB:{e}")
        response = []    
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_vlan_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Create VLAN interface HUB: {request.method} {request.path} Requested ip: {public_ip}')
        if "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.createvlaninterface(data)
        elif data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.create_vlan_interface(data)        
    except Exception as e:
        logger.error(f"Error: Create VLAN INterface HUB:{e}")
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_sub_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for create SUb Interface HUB: {request.method} {request.path} Requested ip: {public_ip}')
        if "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.createsubinterface(data) 
        elif data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.create_vlan_interface(data)        
    except Exception as e:
        logger.error(f"Error: Create Sub Interface HUB:{e}")
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_loopback_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for create Loopback Interface HUB: {request.method} {request.path} Requested ip: {public_ip}')
        if "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.createloopbackinterface(data) 
        elif data["hub_wan_ip"] == hub_ip:
            response = [{"message":"Loopback interface created successfully"}] 
    except Exception as e:
        logger.error(f"Error: Create Loopback Interface HUB:{e}")
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_tunnel_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for create Tunnel Interface: {request.method} {request.path} Requested ip: {public_ip}')
        if "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.createtunnelinterface(data) 
        elif data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.create_tunnel_interface(data)            
    except Exception as e:
        logger.error(f"Error: Create Tunnel Interface in HUB:{e}")
        response = [{"message": f"Error: while Creating Tunnel Interface"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def vlan_interface_delete_hub(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for Delete interface HUB: {request.method} {request.path} Requested ip: {public_ip}')
        if "ciscohub" in data["uuid"]:
            if data["intfc_name"].lower() == "loopback1":
                response = [{"message": f"Error Don't try to modify interface interface {data['intfc_name']}"}] 
                return JsonResponse(response, safe=False)
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                print(data)
                response = router_configure.deletevlaninterface(data)
                print(response) 
        elif data["hub_ip"] == hub_ip:
            response = [] 
            intfc_name = data["intfc_name"]
            if os.path.exists("/etc/netplan/00-installer-config.yaml"):
                # Open and read the Netplan configuration
                with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                    network_config = yaml.safe_load(f)
                    f.close()             
                if "." in data["intfc_name"]:
                    # Ensure the `vlans` section exists
                    if "vlans" not in network_config["network"]:
                        response = [{"message": f"No such VLAN available"}]
                    # Add VLAN configuration
                    else:
                        if intfc_name in network_config["network"]["vlans"]:
                            del network_config["network"]["vlans"][intfc_name]          
                        response = [{"message": f"Successfully deleted the VLAN Interface: {intfc_name}"}]                                              
                # Write the updated configuration back to the file
                with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                    yaml.dump(network_config, f, default_flow_style=False)
                    f.close()
                os.system("netplan apply")            
                cmd = f"sudo ip link del {intfc_name}"
                result = subprocess.run(
                                cmd, shell=True, text=True
                                )    
            else:            
                cmd = f"sudo ip link del {intfc_name}"
                result = subprocess.run(
                                cmd, shell=True, text=True
                                )            
                response = [{"message": f"Successfully  deleted VLAN Interface: {intfc_name}"}]
    except Exception as e:
        logger.error(f"Error: Delete Interface HUB:{e}")
        response = [{"message": f"Error while deleting the VLAN interface interface {data['intfc_name']}: {e}"}] 
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def interface_config_hub(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for configure Interface HUB: {request.method} {request.path} Requested ip: {public_ip}')
        if data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.interface_config(data)                
        elif "microtekhub" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = microtek_configure.interfaceconfig(data)      
        elif "ciscohub" in data["uuid"]:
            if data["intfc_name"].lower() == "loopback1":
                response = [{"message": f"Error dont try to modify {data['intfc_name']} interface address"}]
                print(response)
                return JsonResponse(response, safe=False)
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                print(data)
            response = router_configure.interfaceconfig(data)
            print(response)
    except Exception as e:
        logger.error(f"Error: Interface configure HUB:{e}")
        response = {"message": f"Error: {e}"}
    return JsonResponse(response, safe=False)
##################HUB COMPLETE#################


####################HUB & Spoke setup end point###############
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_ciscohub_config(request: HttpRequest):
    data = json.loads(request.body) 
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for Cisco HUB Config: {request.method} {request.path} Requested ip: {public_ip}')
    response = hub_config.get_ciscohub_config(data)
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_ciscospoke_config(request: HttpRequest):
    data = json.loads(request.body) 
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for Configure Cisco spoke: {request.method} {request.path} Requested ip: {public_ip}')
    response = hub_config.get_ciscospoke_config(data)
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_microtekspoke_config(request: HttpRequest):
    global newuser
    data = json.loads(request.body) 
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for Microtek Spoke Config: {request.method} {request.path} Requested ip: {public_ip}')
    response, newuser = onboarding.check_user(data, newuser)
    if "This Microtek Spoke is already Registered" in response[0]["message"]:
        #spokeinfo = coll_tunnel_ip.find_one({"uuid":data["uuid"]})        
        spokedetails = {"spokedevice_name": response[0]["spokedevice_name"],
                        "router_username": response[0]["router_username"],
                        "router_password": response[0]["router_password"],
                        "message": response[0]["message"],
                        "snmpcommunitystring": snmpcommunitystring
                        }
        background_thread = threading.Thread(target=setass, args=(response, "microtek",))
        background_thread.start()
    else:
        spokedetails= {"message": response[0]["message"]}
    
    return JsonResponse(spokedetails, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def onboard_block(request: HttpRequest):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for onboard block: {request.method} {request.path} Requested ip: {public_ip}')
    response = onboardblock.onboard_block(data)
    logger.debug(f'Received request: {request.method} {request.path}')
    return HttpResponse(response)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def onboard_unblock(request: HttpRequest):
    data = json.loads(request.body)   
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for onboard unblock: {request.method} {request.path} Requested ip: {public_ip}')
    response = onboardblock.onboard_unblock(data)
    return HttpResponse(response)      

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def onboard_delete(request: HttpRequest):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for onboard delete: {request.method} {request.path} Requested ip: {public_ip}')
    onboardblock.onboard_delete(data)
    return HttpResponse

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def spoke_update(request: HttpRequest):
    data = json.loads(request.body)
    response = onboardblock.spoke_update(data)
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for Spoke update: {request.method} {request.path} Requested ip: {public_ip}')
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_configured_hub(request):
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f'Received request for get configured HUB: {request.method} {request.path} Requested ip: {public_ip}')
    try:
        hubips = []
        for hubinfo in coll_hub_info.find({}):
            hubips.append(hubinfo["hub_wan_ip_only"])
    except Exception as e:
        print(f"error in fetch hubips:", e)
    return JsonResponse(hubips, safe=False)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for change Password: {request.method} {request.path} Requested ip: {public_ip}')
        # Retrieve the user object
        user = User.objects.get(username=data.get("username"))        
        # Change the password
        user.password = make_password(data.get("password"))
        user.save()
        response = {"message": "Password Changed successfully"}               
    except ObjectDoesNotExist:
        logger.error(f"Error: Error User doesnot exist. {data}")
        response = {"message": "Error User doesnot exist"}        
    except Exception as e:
        logger.error(f"Error: Change Password:{e}")
        response = {"message": "Error while changing password"}
    return JsonResponse(response, safe=False)

def get_item_id(host_id, name):
    """Fetch item IDs related to bits received/sent."""
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name"],
            "hostids": host_id,
        },
        'auth': auth_token,
        'id': 1,
    }
    try:          
        response = session.post(zabbix_api_url, json=get_item)
        result = response.json().get('result', [])
        items = {item["name"]: item["itemid"] for item in result if "Bits" in item["name"] and name.split(":")[0] in item["name"]}
        print(items)
        return items
        
    except Exception as e:
        print(f"Failed to get item list: {e}")
        return {}

def get_item_id_uptime(host_id):
    """Fetch item IDs related to bits received/sent."""
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
        "output": ["lastvalue", "name"],
        "hostids": host_id,        
        "search": {
            "key_": "system.net.uptime"
        },
        "sortfield": "name"
    },
        'auth': auth_token,
        'id': 1,
    }
    try:          
        response = session.post(zabbix_api_url, json=get_item)
        result = response.json().get('result', [])
        uptimevalue = int(result[0]['lastvalue'])
        # Convert to readable format
        uptime_str = str(timedelta(seconds=uptimevalue))
        #items = {item["name"]: item["itemid"] for item in result if "Bits" in item["name"] and name.split(":")[0] in item["name"]}
        return uptime_str     
    except Exception as e:
        print(f"Failed to get item list: {e}")
        return False

def get_trends(itemid, fromdate, todate):  
    time_from = int(time.mktime(time.strptime(fromdate, "%Y-%m-%d %H:%M:%S")))
    time_to = int(time.mktime(time.strptime(todate, "%Y-%m-%d %H:%M:%S")))
    get_trend = {
        "jsonrpc": "2.0",
        "method": "trend.get",
        "params": {
            "output": "extend",
            "itemids": itemid,
            "time_from": time_from,
            "time_till": time_to
                        
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        trend_response = session.post(zabbix_api_url, json=get_trend)
        trend_result1 = trend_response.json()
        trend_result = trend_result1.get('result')
        if 'error' in trend_result:
            print(f"Failed to get item list: {trend_result['error']['data']}")
            return False
        else:
            return trend_result                    
    except Exception as e:
        print(f"Failed to get trend: {e}")
        return False   
    
def convert_to_mb(bits):
    """Convert bits to Megabytes (MB)."""
    #return round(int(bits) / (8 * 1024 * 1024), 4)
    return round(int(bits) / (1024 * 1024), 4)

def convert_to_mbps(bits):
    """Convert bits to Megabits per second (Mbit/s)."""
    return round(int(bits) / (1024 * 1024), 4)

def download_graph(graphid, fromdate, todate):
    try:
        login_response = session.post(ZABBIX_WEB_URL, data=login_payload)
        # Check if login was successful
        if "zbx_session" not in session.cookies.get_dict():
            print("Login failed! Check credentials.")
            return False
        print("Login successful! Proceeding to download graph...")
        # Step 2: Fetch the graph image
        params = {
            "graphid": graphid,  # Replace with your graph ID
            "from": fromdate,  # Start time (Unix timestamp)
            "to": todate,  # End time (Unix timestamp)
            "width": 800,
            "height": 400,
            "profileIdx": "web.graphs"
            }
        graph_response = session.get(GRAPH_URL, params=params)
        # Step 3: Save the graph if response is an image
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        graph_filename = f"graph_{timestamp}.png"
        if "image/png" in graph_response.headers.get("Content-Type", ""):
            with open(graph_filename, "wb") as f:
                f.write(graph_response.content)
            print("Graph image downloaded successfully as graph.png")
            return graph_filename
        else:
            print("Failed to retrieve graph. Response:", graph_response.text)
            return False
    except Exception as e:
        print("Execption raised on donload graph", e)
        return False
    
def graph_create(itemid1, itemid2, graphname):
    graph_create = {
        "jsonrpc": "2.0",
        "method": "graph.create",
        "params": {
            "name": graphname,
            "width": 900,
            "height": 200,
            "show_work_period": 0,
            "show_triggers": 0,
            "gitems": [
                {
                "itemid": itemid1,
                "color": "1a2856",
                "drawtype": 1
                },
                {
                "itemid": itemid2,
                "color": "c8262b",
                "drawtype": 2
                }
            ]            
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=graph_create)
        graphids = response.json()        
        graphid = graphids["result"]["graphids"][0] 
        return graphid    
    except Exception as e:
        print(f"Failed to get create graph: {e}")
        return False

def graph_delete(graphid):
    graph_delete = {
        "jsonrpc": "2.0",
        "method": "graph.delete",
        "params": [
                    graphid
                    
                ],
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=graph_delete)
        graphids = response.json()        
        graphid = graphids["result"]["graphids"][0] 
        return graphid    
    except Exception as e:
        print(f"Failed to delete graph: {e}")
        return False
    
def get_percentile(itemidsent, itemidreceived, fromdate):    
    get_history = {
        "jsonrpc": "2.0",
        "method": "history.get",
        "params": {
            "output": "extend",
            "itemids": [itemidsent, itemidreceived],            
            "time_from": int(fromdate),
            "time_till": int(fromdate) + 3600
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=get_history)
        history_results = response.json().get('result')
        sentvalues = []
        receivedvalues = []
        totalvalues = []
        for history_result in history_results:
            if history_result["itemid"] == itemidsent:
                sentvalues.append(int(history_result["value"]))
            if history_result["itemid"] == itemidreceived:
                receivedvalues.append(int(history_result["value"]))
        for i in range(0,len(sentvalues)):
            totalvalues.append(sentvalues[i] +receivedvalues[i] )
        if len(totalvalues) > 0:
            in_value_avg = round(np.mean(sentvalues), 4)
            out_value_avg = round(np.mean(receivedvalues), 4)
            total_value_avg = round(np.mean(totalvalues), 4)
            in_percentile = round(np.percentile(sentvalues, 95), 4)
            out_percentile = round(np.percentile(receivedvalues, 95), 4)
            total_percentile = round(np.percentile(totalvalues, 95), 4)
            coverage = round((len(totalvalues)/60) * 100, 4)     
        else:
            in_value_avg = 0
            out_value_avg = 0
            total_value_avg = 0
            in_percentile = 0
            out_percentile = 0
            total_percentile = 0
            coverage = 0  
            get_trend = {
                "jsonrpc": "2.0",
                "method": "trend.get",
                "params": {
                    "output": "extend",
                    "itemids": [itemidsent, itemidreceived],            
                    "time_from": int(fromdate),
                    "time_till": int(fromdate) + 3600
                },
                'auth': auth_token,
                'id': 1,
            }
            try:
                response = session.post(zabbix_api_url, json=get_trend)
                trend_results = response.json().get('result')                
                for trend_result in trend_results:
                    coverage = round((int(trend_result["num"])/60) * 100, 4)
                    if trend_result["itemid"] == itemidsent:
                        in_value_avg = trend_result["value_avg"]
                        in_percentile = trend_result["value_max"]
                    if trend_result["itemid"] == itemidreceived:
                        out_value_avg = trend_result["value_avg"]
                        out_percentile = trend_result["value_max"]
                total_value_avg = in_value_avg + out_value_avg
                total_percentile = in_percentile + out_percentile
            except Exception as e:
                print("Error in trend data")                
        percentile_result = {"in_avg":in_value_avg,
                             "in_percentile": in_percentile,
                             "out_avg": out_value_avg,
                             "out_percentile": out_percentile,
                             "total_avg": total_value_avg,
                             "total_percentile": total_percentile,
                             "coverage": coverage}
        return percentile_result
    except Exception as e:
        print(f"Failed to get History: {e}")
        return []

def save_to_pdf(intfcname, branch_location, fromdate, todate, graphname, itemidreceived, itemidsent, uptime_str, filename="traffic_data.pdf", logo_path="logo.png"):
    """Generate a well-structured PDF report with logo, traffic data, and percentile details."""

    # Define PDF document with margins
    doc = SimpleDocTemplate(filename, pagesize=letter,
                            leftMargin=20, rightMargin=20, topMargin=40, bottomMargin=40)
    elements = []

    # Get styles for headings
    styles = getSampleStyleSheet()
    
    # **Add Logo** (Ensure 'logo.png' is in the same directory)
    try:
        img = Image(logo_path, width=100, height=50)  # Adjust size as needed
        elements.append(img)
        elements.append(Spacer(1, 10))  # Space below logo
    except:
        print("Logo not found, continuing without it.")

    # **Title & Subtitle**
    title = Paragraph(f"<b>Report for {intfcname}</b>", styles["Title"])
    title2 = Paragraph(f"<b>{branch_location}</b>", styles["Title"])
    subtitle = Paragraph(f"<b>Generated on:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]) 

    # Table Header
    data = [["Date Time", "Traffic In(Mbit/s)", "Traffic In(MB)", 
             "Traffic Out(Mbit/s)", "Traffic Out(MB)", "Traffic Total(Mbit/s)", "Traffic Total(MB)", "Percentile", "Coverage"]]

    in_avg_values = []
    out_avg_values = []
    total_speed_values = []
    total_volumes = []
    total_coverages = []
    in_volumes = []
    out_volumes = []
    time_from = int(time.mktime(time.strptime(fromdate, "%Y-%m-%d %H:%M:%S")))
    time_to = int(time.mktime(time.strptime(todate, "%Y-%m-%d %H:%M:%S")))

    # Add data rows
    for time_from in range(time_from, time_to, 3600):
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(time_from)))
        percentile_output = get_percentile(itemidsent, itemidreceived, time_from)
        in_speed = convert_to_mbps(int(percentile_output["in_avg"]))
        out_speed = convert_to_mbps(int(percentile_output["out_avg"]))
        coverage = percentile_output["coverage"]
        in_volume = round((in_speed * 180) / (8), 4)
        out_volume = round((out_speed * 180) / (8), 4)
        total_speed = round(in_speed + out_speed, 4)
        total_volume = round(in_volume + out_volume, 4)
        total_percentile = convert_to_mbps(percentile_output["total_percentile"])
        # Store values for percentile calculation
        in_avg_values.append(in_speed)
        out_avg_values.append(out_speed)
        total_speed_values.append(total_speed)
        total_volumes.append(total_volume)  
        total_coverages.append(coverage) 
        in_volumes.append(in_volume) 
        out_volumes.append(out_volume)
        row = [time_str, in_speed, in_volume, out_speed, out_volume, total_speed, total_volume, total_percentile, coverage]
        data.append(row)

    # Calculate 95th percentile
    in_95th = round(np.percentile(in_avg_values, 95), 4)    
    out_95th = round(np.percentile(out_avg_values, 95), 4)
    total_95th = round(np.percentile(total_speed_values, 95), 4)
    avg_speed = round(np.mean(total_speed_values), 4)  # Average
    total_traffic = round(np.sum(total_volumes), 4)  # Total
    percentile = round(np.percentile(total_speed_values, 95), 4)
    avg_in_speed = round(np.mean(in_avg_values), 4)
    avg_out_speed = round(np.mean(out_avg_values), 4)    
    avg_coverage = round(np.mean(total_coverages), 4)
    total_in_volumes = round(np.sum(in_volumes), 4)
    total_out_volumes = round(np.sum(out_volumes), 4)
    # Table Header
    data1 = [["Date Time", "Traffic In(Mbit/s)", "Traffic In(MB)", 
             "Traffic Out(Mbit/s)", "Traffic Out(MB)", "Traffic Total(Mbit/s)", "Traffic Total(MB)", "Percentile", "Coverage"]]

    data1.append([f"Sums(of {len(total_volumes)}) values", " ", total_in_volumes, 
                  " ", total_out_volumes, " ", total_traffic, " " , " "])
    
    data1.append([f"Averages(of {len(total_volumes)}) values", avg_in_speed, " ", 
                  avg_out_speed, " ", avg_speed, " ", " " , avg_coverage])
    # Append 95th percentile row to table
    #data.append(["95th Percentile", in_95th, "-", out_95th, "-", total_95th, "-"])
    # Set column widths to fit within the page
    column_widths = [110, 70, 60, 70, 65, 70, 70, 50, 50]

    # Create the table with defined column widths
    table = Table(data, colWidths=column_widths)
    # Create the table with defined column widths
    tableconsolidated = Table(data1, colWidths=column_widths)
    # Add table styles
    tableconsolidated.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),  # Adjust font size for better fit
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid for table
        #('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),  # 95th percentile row highlight
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))
    # Add table styles
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),  # Adjust font size for better fit
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid for table
        #('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),  # 95th percentile row highlight
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))
    totaltraffic = Paragraph(f"<b>Traffic Total: {str(total_traffic)} MB</b>", styles["Normal"])
    avgspeed = Paragraph(f"<b>Average Speed: {str(avg_speed)} Mbit/s</b>", styles["Normal"])
    percentilestr = Paragraph(f"<b>Percentile: {str(percentile)} Mbit/s</b>", styles["Normal"])
    duration = Paragraph(f"<b>Duration: {fromdate} to {todate} </b>", styles["Normal"])
    uptime = Paragraph(f"<b>Uptime: {uptime_str} </b>", styles["Normal"])
    elements.append(title)
    elements.append(Spacer(1, 12))  # Space
    elements.append(title2)
    elements.append(Spacer(1, 12))  # Space
    elements.append(subtitle)
    elements.append(Spacer(1, 12))  # Space
    elements.append(duration)
    elements.append(Spacer(1, 12))  # Space
    elements.append(uptime)
    elements.append(Spacer(1, 12))  # Space
    elements.append(totaltraffic)
    elements.append(Spacer(1, 12))  # Space
    elements.append(avgspeed)
    elements.append(Spacer(1, 12))  # Space
    elements.append(percentilestr)
    elements.append(Spacer(1, 12))  # More space before the table
    # **Add Logo** (Ensure 'logo.png' is in the same directory)
    try:
        graphimg = Image(graphname, width=500, height=200)  # Adjust size as needed
        elements.append(graphimg)
        elements.append(Spacer(1, 20))  # Space below logo
    except:
        print("Logo not found, continuing without it.")
    elements.append(tableconsolidated)
    elements.append(Spacer(1, 12))  # More space before the table
    elements.append(table)
    # Build PDF
    doc.build(elements)
    print(f"Traffic data saved to {filename}")

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def traffic_report(request):
    try:
        data = json.loads(request.body)
        print(data)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f'Received request for traffic report: {request.method} {request.path} Requested ip: {public_ip}')
        hostid = data["hostid"]
        intfcname = data["intfcname"]
        fromdate = data["fromdate"]
        todate = data["todate"]
        ishub = data["ishub"]
        ishub = True
        if ishub:
            branch_location = "HUB Location: " + data["branch_location"]
        else:
            branch_location = "Branch Location: " + data["branch_location"]
        #hostid = "10677"
        #intfcname = "Interface Fa4(): Network traffic"
        #branch_location = "Jeddah Cisco HUB"
        #fromdate = "2025-03-15 00:00:00"
        #todate = "2025-03-18 00:00:00"
        item_ids = get_item_id(hostid, intfcname)        
        if not item_ids:
            print("No relevant items found.")
            logger.error(f"Error: Get Traffic report: No relevant items found.")
            response = [{"message": "No relevant items found."}]
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(response)
            response1["Access-Control-Expose-Headers"] = "X-Message"
            return response1
        for name, itemid in item_ids.items():
            if "received" in name:
                itemidreceived = itemid                
            if "sent" in name:
                itemidsent = itemid 
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        graphname = f"graph_{timestamp}"     
        graphid = graph_create(itemidsent, itemidreceived, graphname)
        if graphid: 
            download_graph_name = download_graph(graphid, fromdate, todate)
            graph_delete(graphid)
            if(download_graph_name):
                    uptime_str = get_item_id_uptime(hostid) 
                    save_to_pdf(intfcname, branch_location, fromdate, todate, download_graph_name, itemidreceived, itemidsent, uptime_str)         
                    #save_to_pdf(incoming_traffic, outgoing_traffic, intfcname, branch_location, fromdate, todate, uptime_str, download_graph_name)
                    with open("traffic_data.pdf", "rb") as f:
                            trafficdatapdf = f.read()
                            # Files to include in ZIP
                    #os.system("rm -r traffic_data.pdf")
                    os.system(f"rm -r {download_graph_name}")
                    files_to_send = {
                        "traffic_data.pdf": trafficdatapdf
                    }
                    # Create an in-memory ZIP buffer
                    buffer = io.BytesIO()
                    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                        for filename, content in files_to_send.items():
                            zip_file.writestr(filename, content)
                    # Prepare the response
                    buffer.seek(0)
                    json_message = json.dumps({"message": "Traffic data generated successfully."})
                    response = HttpResponse(buffer.getvalue(), content_type="application/zip")
                    response["Content-Disposition"] = 'attachment; filename="traffic_data.zip"'
                    response["X-Message"] = json_message  # Ensure this is a JSON-encoded string
                    response["Access-Control-Expose-Headers"] = "X-Message"
                    return response                
            else:
                print("Issue to download graph")
                logger.error(f"Error: Get Traffic report: Issue to get Graph.")
                response = [{"message": "Error Issue to get Graph."}]
        else:
            print("Issue to create graph")
            logger.error(f"Error: Get Traffic report: Issue to create Graph.")
            response = [{"message": "Error Issue to create Graph."}]
    except Exception as e:
        print(f"Error: {e}")
        logger.error(f"Error: Get Traffic report: {e}")
        response = [{"message": "Error Internal server problem."}]
    response1 = HttpResponse(content_type='text/plain')
    response1['X-Message'] = json.dumps(response)
    response1["Access-Control-Expose-Headers"] = "X-Message"
    return response1