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
import logging
logger = logging.getLogger(__name__)
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
resource_active = True
resource_inactive = True
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
vrf1_ip = '10.200.202.0/24'
url = "https://dev-api.cloudetel.com/api/v1/"
hub_ip = config('HUB_IP')
hub_location = "jeddah"
hub_uuid = "reachlinkserver.net"
hub_hostid = "10084"
gretunnelnetwork = "10.200.202.0/24"
gretunnelnetworkip = "10.200.202."
hub_tunnel_endpoint = "10.200.202.2"
openvpnhubip = "10.8.0.1"
dialernetworkip = config('DIALER_NERWORK_IP')
cisco_dialer_hub_ip = config('DIALER_HUB_IP')
cisco_hub_username = config('DIALER_HUB_USERNAME')
cisco_hub_password = config('DIALER_HUB_PASSWORD')
dialer_netmask = config('DIALER_NETMASK')
snmpcommunitystring = "reachlink"
ubuntu_dialerclient_ip = config('UBUNTU_DIALER_CLIENT_IP')


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
            time.sleep(1)   
        except Exception as e:
            print(e)
        newspokedevicename = response[0]["spokedevice_name"]
        newspokegreip = response[0]["gretunnel_ip"].split("/")[0]
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
                    coll_tunnel_ip.update_many(query, update_data)                  
                else:
                    newspokeovpnip = spoke["Tunnel_ip"]
                    newspokeconnstatus = True
                    command = f"sudo ip neighbor replace {newspokegreip} lladdr {newspokeovpnip} dev Reach_link1"
                    subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                    query = {"spokedevice_name": newspokedevicename }
                    update_data = {"$set": {"public_ip":newspokeovpnip                                                                         
                                        }
                                       }
                    coll_tunnel_ip.update_many(query, update_data)
                os.system("python3 /root/reachlink/reachlink_zabbix.py")
                os.system("systemctl stop reachlink_test")
                tunneldata = []
                for device in coll_tunnel_ip.find({},{"_id":0}):
                    tunneldata.append(device)
                with open("total_branches.json", "w") as f:
                    json.dump(tunneldata, f)
                    f.close()
                os.system("systemctl start reachlink_test")                 
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
    except:
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
                with open("robustel_conf.exe", "rb") as f:
                    robustelexe = f.read()
                    f.close()
                files_to_send = {
                    "ca.crt": cacrt,
                    "client.crt": clientcrt,
                    "client.key": clientkey,
                    "robustel_conf.exe": robustelexe  # Keep binary
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
                #background_thread = threading.Thread(target=setass, args=(response, "robustel",))
                #background_thread.start() 
            else:
                response1 = HttpResponse(content_type='text/plain')
                response1['X-Message'] = json.dumps(response)    
                response1["Access-Control-Expose-Headers"] = "X-Message"    
        except Exception as e:
            print(e)
            response = [{"message": "Internal Server Error", "expiry_date": dummy_expiry_date}]
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(response)
            response1["Access-Control-Expose-Headers"] = "X-Message"
        return response1

    check_hub_configured = coll_hub_info.find_one({"hub_wan_ip_only": data.get("dialer_ip", "")})
    if not check_hub_configured:
        json_response = [{"message": f"Error:Hub not configured yet. Pl configure HUB first."}]
        response = HttpResponse(content_type='application/zip')
        response['X-Message'] = json.dumps(json_response)
        response["Access-Control-Expose-Headers"] = "X-Message"
        return response
    data["uuid"] = data['branch_location'] + "_" + data["dialer_ip"] + "_ciscodevice.net"
    print(data)
    data["username"] = "none"
    data["password"] = "none" 
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
        if response[0]["message"] == "Successfully Registered" or response[0]["message"] == "This device is already Registered":
            devicename = response[0]["spokedevice_name"]
            devicedialerinfo = coll_dialer_ip.find_one({"dialerusername":devicename})
            dialer_ip = data.get("dialer_ip", "")
            if not devicedialerinfo:
                newdialerinfo = hub_config.get_dialer_ip_fromciscohub(devicename, dialer_ip )
                if newdialerinfo:
                    newdialerinfo["router_username"] = devicename.lower()
                    newdialerinfo["router_password"] = hub_config.generate_router_password_cisco()
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
                    orgid = onboarding.get_organization_id(data)
                    details = coll_registered_organization.find_one({"organization_id":orgid})
                    registered_devices_info = details["registered_devices"]
                    for device in registered_devices_info:
                        if device["uuid"] == data["uuid"]:
                            device["gretunnel_ip"] = newdialerinfo["dialerip"]
                    query = {"organization_id": orgid}
                    update_data = {"$set": {"registered_devices": registered_devices_info } }
                    coll_registered_organization.update_many(query, update_data)
            
                    query = {"uuid": data["uuid"]}
                    update_data = {"$set": {"tunnel_ip": newdialerinfo["dialerip"],
                                    "router_username": devicename.lower(),
                                    "router_password": newdialerinfo["router_password"]
                                    } }
                    coll_tunnel_ip.update_many(query, update_data)
                    os.system("python3 /root/reachlink/reachlink_zabbix.py")
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

            # Create a ZIP archive
            with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Read the EXE file and add it to the ZIP
                with open("reachlink_config.exe", "rb") as f:
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
            os.system("systemctl stop reachlink_test") 
            os.system("python3 /root/reachlink/reachlink_zabbix.py")
            spokedata = []
            for device in coll_tunnel_ip.find({},{"_id":0}):
                spokedata.append(device)
            with open("/root/reachlink/total_branches.json", "w") as f:
                json.dump(spokedata, f)
                f.close()
            os.system("systemctl start reachlink_test") 
            return response
        else:
            json_response = [{"message": f"Error:{response[0]['message']}"}]
    except Exception as e:
        print("device add exception", e)
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
        if response[0]["message"] == "Successfully Registered" or response[0]["message"] == "This device is already Registered":
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
                os.system("python3 /root/reachlink/reachlink_zabbix_hub.py")
                os.system("systemctl stop reachlink_test")
                hubdata = []
                for device in coll_hub_info.find({},{"_id":0}):
                    hubdata.append(device)
                with open("/root/reachlink/total_hubs.json", "w") as f:
                    json.dump(hubdata, f)
                    f.close()   
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
        json_response = [{"message": f"Error:Internal Server Error"}]
    print(json_response)
    response = HttpResponse(content_type='application/zip')
    response['X-Message'] = json.dumps(json_response)
    response["Access-Control-Expose-Headers"] = "X-Message"
    return response

#@api_view(['GET'])
#@permission_classes([IsAuthenticated])
def branch_info(request: HttpRequest):
    try:
        print(request)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of branch info:{public_ip}")
        response = {}
        data = []     
        active_branches = 0
        inactive_branches = 0
        total_no_branches = 0
        organization_id = str(request.GET.get('organization_id'))
        with open("/root/reachlink/total_branches.json", "r") as f:
            total_branches = json.load(f)
            f.close()
        reg_devices = coll_registered_organization.find_one({"organization_id":organization_id})
        for device in reg_devices["registered_devices"]:
            for branch in total_branches:
                if device["uuid"] == branch["uuid"]:
                    branch["spokedevice_name"] = device.get("spokedevice_name", "None")
                    data.append({   "public_ip": branch.get("public_ip", ""),
                                    "tunnel_ip": branch.get("tunnel_ip", ""),
                                    "branch_location": branch.get("branch_location", ""),
                                    "subnet": branch.get("subnet", []),
                                    "vrf": branch.get("vrf", ""),
                                    "uuid": branch.get("uuid", ""),
                                    "hub_ip":branch.get("hub_ip", ""),
                                    "host_id": branch.get("host_id", ""),
                                    "status": branch.get("status", ""),
                                    "spokedevice_name": branch.get("spokedevice_name", "")
                                    })
                    if branch.get("status", "") == "active":
                        active_branches = active_branches + 1
                    else:
                        inactive_branches = inactive_branches + 1
                    total_no_branches = total_no_branches + 1
        response = {    "data":data,
                        "total_branches":total_no_branches,
                        "inactive_branches":inactive_branches,
                        "active_branches": active_branches,
                        "organization_id": organization_id
                    }
    except Exception as e:
        print(e)
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
        print(request)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of hub_info:{public_ip}")
        response = {}
        data = []
        data.append({"hub_ip":hub_ip,
                            "branch_location": hub_location,
                            "hub_dialer_ip_cidr": hub_tunnel_endpoint,
                            "hub_status": "active",
                            "uuid": hub_uuid,
                            "host_id": hub_hostid
                            })     
        active_hubs = 1
        inactive_hubs = 0
        total_no_hubs = 1
        organization_id = str(request.GET.get('organization_id'))
        with open("/root/reachlink/total_hubs.json", "r") as f:
            total_branches = json.load(f)
            f.close()
        reg_devices = coll_registered_organization.find_one({"organization_id":organization_id})
        for device in reg_devices["registered_devices"]:
            for branch in total_branches:
                if device["uuid"] == branch["uuid"]:
                    branch["spokedevice_name"] = device.get("spokedevice_name", "None")
                    data.append({"hub_ip":branch["hub_wan_ip_only"],
                            "branch_location": branch["branch_location"],
                            "hub_dialer_ip_cidr": branch["hub_dialer_ip_cidr"],
                            "hub_status": branch.get("status", "inactive"),
                            "uuid": branch["uuid"],
                            "host_id": branch.get("host_id", "")
                            })
                    if branch.get("status", "") == "active":
                        active_hubs = active_hubs + 1
                    else:
                        inactive_hubs = inactive_hubs + 1
                    total_no_hubs = total_no_hubs + 1
        
        response = {    "data":data,
                        "total_hubs":total_no_hubs,
                        "inactive_hubs":inactive_hubs,
                        "active_hubs": active_hubs,
                        "organization_id": organization_id
                    }
    except Exception as e:
        response = {    "data":data,
                        "total_hubs":total_no_hubs,
                        "inactive_hubs":inactive_hubs,
                        "active_hubs": active_hubs,
                        "organization_id": organization_id
                    }
    return JsonResponse(response, safe=False)
###########SPOKE####################
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deactivate(request: HttpRequest):
    data = json.loads(request.body) 
    print(data)
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
                    os.system("systemctl stop reachlink_test") 
                    with open("/root/reachlink/total_branches.json", "r") as f:
                        totalbranches = json.load(f)
                        f.close()
                    for dev in totalbranches:
                        if dev["uuid"] == data["uuid"]:
                            dev["status"] = "inactive"
                    with open("/root/reachlink/total_branches.json", "w") as f:
                        json.dump(totalbranches, f)
                        f.close() 
                    os.system("systemctl start reachlink_test")   
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
        print(f"requested ip of get interface details spoke:{public_ip}")
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
        print(e)
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_vlan_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of create vlan interface:{public_ip}")
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
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_sub_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of create vlan interface:{public_ip}")
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
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_loopback_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of create vlan interface:{public_ip}")
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
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_tunnel_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of create vlan interface:{public_ip}")
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
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def interface_config_spoke(request):
    try:
        data = json.loads(request.body)
        print(data)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of interface config spoke:{public_ip}")
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
    except Exception as e:
        print(e)
        response = {"message": f"Error: while configuring interface"}
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def vlan_interface_delete_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of vlan interface delete spoke:{public_ip}")
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
            router_info = coll_dialer_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            print(data)
            response = router_configure.deletevlaninterface(data)
    except Exception as e:
        response = {"message": f"Error: {e}"}
    print("deletevlan", response)
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_routing_table_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of get routing table spoke:{public_ip}")
        print(data)
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
        print(e)
        response = []
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def add_route_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of add route spoke:{public_ip}")
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
        response = {"message": f"Error: {e}"}
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def del_staticroute_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of del static route spoke:{public_ip}")
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
        response = {"message": f"Error: {e}"}
    return JsonResponse(response, safe=False)        

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_pbr_info_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of get pbr info spoke:{public_ip}")
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
        print(e)
        response = []
    print(response)
    return JsonResponse(response, safe=False)

#Ping_hub end point
@api_view(['POST'])  
@permission_classes([IsAuthenticated]) 
def diagnostics(request: HttpRequest):
    data = json.loads(request.body)      
    response = ubuntu_info.diagnostics(data)
    return JsonResponse(response, safe=False)  

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def ping_spoke(request: HttpRequest):  
    try: 
        data = json.loads(request.body) 
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of ping spoke:{public_ip}")
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
                response = {"message":f"Subnet {data['subnet']} Reachable with RTT: {ping_result}ms"}
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
        print(e)
        response = {"message": f"Error: Subnet {data['subnet']} Not Reachable" }
    print(response)       
    logger.debug(f'Received request: {request.method} {request.path}')
    return JsonResponse(response, safe=False)    

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def traceroute_spoke(request):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of traceroute spoke:{public_ip}")
    host_ip = data.get('trace_ip', None)
    if "microtek" in data["uuid"]:
        router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
        data["router_username"] = router_info["router_username"]
        data["router_password"] = router_info["router_password"]
        trace_result = microtek_configure.traceroute(data)   
        response_msg = {"message": trace_result}            
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
    print(response) 
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def traceroute_hub(request):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of traceroute hub:{public_ip}")
    host_ip = data.get('trace_ip', None)
    if host_ip:           
            result1 = subprocess.run(['traceroute', '-d', host_ip], capture_output=True, text=True)
            response = {"message":result1.stdout}
            return JsonResponse(response, safe=False)
    response = {"message":"Invalid trace ip"}
    return JsonResponse(response,safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def addsubnet(request: HttpRequest):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of addsubnet:{public_ip}") 
        response = ubuntu_info.addsubnet(data)        
    except Exception as e:
        print(e)
        response = {"message": f"Error in adding route, pl try again {e}" }
    logger.debug(f'Received request: {request.method} {request.path}')   
    return JsonResponse(response, safe=False) 

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def add_ip_rule_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of add ip rule:{public_ip}")
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
        print(f"requested ip of autofix:{public_ip}")      
        print(data)
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
        print(e)
    logger.debug(f'Received request: {request.method} {request.path}')      
    return JsonResponse(response, safe=False)  

@api_view(['POST'])    
@permission_classes([IsAuthenticated])
def delsubnet(request: HttpRequest):
    data = json.loads(request.body)   
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of delsubnet:{public_ip}")
    response = ubuntu_info.background_deletesubnet(data)
    logger.debug(f'Received request: {request.method} {request.path}')
    return JsonResponse(response, safe=False)
##############Inactive branch##############
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def activate(request: HttpRequest):
    data = json.loads(request.body)      
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
        print(f"requested ip of hub routing table: {public_ip}")
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
        print(e)
        response = []
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def addstaticroute_hub(request: HttpRequest):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of get static route hub:{public_ip}")
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
        response = {"message": f"Error in adding route, pl try again {e}" }
    logger.debug(f'Received request: {request.method} {request.path}')   
    print(response) 
    return JsonResponse(response, safe=False) 

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def delstaticroute_hub(request: HttpRequest):
    response = [{"message":"Successfully deleted"}]
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of del static route hub:{public_ip}")
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
        print(e)
        response = {"message":f"Error while deleting route: {e}"}
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
        print(f"requested ip of get interface hub:{public_ip}")
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
        print(e)
        response = []
    print("hub interface details")
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_vlan_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of add vlan hub:{public_ip}")
        #data["hub_wan_ip"] = "78.110.5.90"
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
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_sub_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of add sub interface hub:{public_ip}")
        #data["hub_wan_ip"] = "78.110.5.90"
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
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_loopback_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of add loopback hub:{public_ip}")
        #data["hub_wan_ip"] = "78.110.5.90"
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
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_tunnel_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of add loopback hub:{public_ip}")
        #data["hub_wan_ip"] = "78.110.5.90"
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
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def vlan_interface_delete_hub(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of vlan interface delete hub:{public_ip}")
        if "ciscohub" in data["uuid"]:
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
        print(e)
        response = [{"message": f"Error while deleting the VLAN interface interface {data['intfc_name']}: {e}"}] 
    print(response)
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def interface_config_hub(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of interface config spoke:{public_ip}")
        if data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.interface_config(data)                
        elif "microtekhub" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = microtek_configure.interfaceconfig(data)      
        elif "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                print(data)
            response = router_configure.interfaceconfig(data)
            print(response)
    except Exception as e:
        response = {"message": f"Error: {e}"}
    return JsonResponse(response, safe=False)
##################HUB COMPLETE#################


####################HUB & Spoke setup end point###############
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_ciscohub_config(request: HttpRequest):
    data = json.loads(request.body) 
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of cisco hub config:{public_ip}") 
    response = hub_config.get_ciscohub_config(data)
    return JsonResponse(response)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_ciscospoke_config(request: HttpRequest):
    data = json.loads(request.body) 
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of get cisco spoke config:{public_ip}") 
    response = hub_config.get_ciscospoke_config(data)
    return JsonResponse(response)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def onboard_block(request: HttpRequest):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of onboard block:{public_ip}")
    response = onboardblock.onboard_block(data)
    logger.debug(f'Received request: {request.method} {request.path}')
    return HttpResponse(response)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def onboard_unblock(request: HttpRequest):
    data = json.loads(request.body)   
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of onboard unblock:{public_ip}") 
    response = onboardblock.onboard_unblock(data)
    logger.debug(f'Received request: {request.method} {request.path}')
    return HttpResponse(response)      

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def onboard_delete(request: HttpRequest):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    print(f"requested ip of onboard delete:{public_ip}")
    onboardblock.onboard_delete(data)
    return HttpResponse

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def spoke_update(request: HttpRequest):
    data = json.loads(request.body)
    response = onboardblock.spoke_update(data)
    logger.debug(f'Received request: {request.method} {request.path}')
    return JsonResponse(response, safe=False)

@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_configured_hub(request):
    try:
        hubips = []
        for hubinfo in coll_hub_info.find({}):
            hubips.append(hubinfo["hub_wan_ip_only"])
    except Exception as e:
        print("error in fetch hubips:", e)
    return JsonResponse(hubips, safe=False)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    try:
        data = json.loads(request.body)
        # Retrieve the user object
        user = User.objects.get(username=data.get("username"))        
        # Change the password
        user.password = make_password(data.get("password"))
        user.save()
        response = {"message": "Password Changed successfully"}
        return JsonResponse(response, safe=False)        
    except ObjectDoesNotExist:
        response = {"message": "Error User doesnot exist"}
        return JsonResponse(response, safe=False)    
    except Exception as e:
        response = {"message": "Error while changing password"}
        return JsonResponse(response, safe=False)    
