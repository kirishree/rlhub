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
from rest_framework import serializers
from .serializers import AuthLoginSerializer, AuthLoginResponseSerializer, ActivateInfoSerializer, MessageSerializer
from .serializers import HubInfoSerializer, DeviceInfoSerializer, RouteEntrySerializer, InterfaceEntrySerializer
from .serializers import AddRouteInfoSerializer, DelRouteInfoSerializer, PingHubInfoSerializer, PingSpokeInfoSerializer
from .serializers import TraceSpokeInfoSerializer, TraceHubInfoSerializer, VlanAddHubSerializer, AddRouteHubSerializer
from .serializers import LoopbackAddHubSerializer, TunnelAddHubSerializer, DeleteInterfaceHubSerializer
from .serializers import ConfigInterfaceHubSerializer, VlanAddSpokeSerializer, LoopbackAddSpokeSerializer
from .serializers import TunnelAddSpokeSerializer, ConfigInterfaceSpokeSerializer, DeleteInterfaceSpokeSerializer
from .serializers import AddReachLinkDeviceSerializer, AddDeviceSerializer, AddHubDeviceSerializer
from .serializers import ConfigCiscoHubSerializer, ConfigCiscoHubResponseSerializer, ConfigCiscoSpokeSerializer, ConfigCiscoSpokeResponseSerializer, ConfigMicrotikSpokeSerializer, ConfigMicrotikSpokeResponseSerializer, ConfigRobustelSpokeSerializer, ConfigRobustelSpokeResponseSerializer, TrafficReportInfoSerializer
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
from django.core.cache import cache
#from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
User = get_user_model()
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from reportlab.lib.pagesizes import letter, landscape
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
import zabbix_gen_report
import zabbix_ping_report
import jwt
from .tasks import setass_task 
newuser = False
dummy_expiry_date = ""
mongo_uri = config('DB_CONNECTION_STRING')
super_user_name = config('SUPER_USER_NAME')
SECRET_KEY = config('DJANGO_SECRET_KEY')
ALGORITHM = 'HS256' 
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
microtik_exe_path = config('MICROTIK_EXE_PATH')
reachlink_cisco_exe_path = config('REACHLINK_CISCO_EXE_PATH')
cisco_spoke_exe_path = config('CISCO_SPOKE_EXE_PATH')
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
        if not os.path.exists(client_cert_file):            
            return False
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
        logger.info(
                    f"Client configuration generated",
                    extra={
                            "device_type": "",
                            "device_ip": client_name,
                            "be_api_endpoint": "add_cisco_device",
                            "exception": ""
                        }
        )
        return True
    except Exception as e:
        logger.error(
                        f"Error during client certificate creation",
                        extra={
                                "device_type": "",
                                "device_ip": client_name,
                                "be_api_endpoint": "add_cisco_device",
                                "exception": str(e)
                            }
        )
        return False

def validate_ip(ip_address):
    octet = ip_address.split(".")
    prefix_len = ip_address.split("/")[1]
    if prefix_len == 32:
        return False
    if 0 < int(octet[0]) < 127:
        if 7 < int(prefix_len) < 33:
            return True
    if int(octet[0]) == 169 and int(octet[1]) == 254:
        return False
    if 127 < int(octet[0]) < 192:
        if 15 < int(prefix_len) < 33 :
            return True
    if 191 < int(octet[0]) < 224:
        if 23< int(prefix_len) < 33:
            return True    
    return False
      
@swagger_auto_schema(
    method='post',
    tags=['Authentication'],
    request_body=AuthLoginSerializer,
    responses={200: AuthLoginResponseSerializer}
)
@api_view(['POST'])
def login_or_register(request):
    username = request.data.get("username")
    password = request.data.get("password")    
    if not username or not password:
        return Response({"error": "Username and password are required"}, status=400)
    if username ==  super_user_name:
        # Authenticate existing user
        user = authenticate(username=username, password=password)
        if not user:
            return Response({            
            "message": False,
            "msg_status": "Invalid Password"
            })
        # Generate JWT tokens for new user
        refresh = RefreshToken.for_user(user)
        refresh['role'] = "admin"  # Assuming 'role' is a field on your user model
        logger.info(
            f"Admin Logged in",
            extra={                
                "be_api_endpoint": "login",
                "exception": ""
            }
            )
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "message": True
        })
    # Authenticate existing user
    user = authenticate(username=username, password=password)
    if user:
        # Generate JWT tokens        
        refresh = RefreshToken.for_user(user)
        current_datetime = datetime.now()         
        refresh['role'] = getattr(user, 'role', 'org-user')
        refresh['onboarding_org_id'] = getattr(user, 'onboarding_org_id', 'NA')
        refresh['onboarding_user_id'] = getattr(user, 'onboarding_user_id', 'NA')
        refresh['onboarding_first_name'] = getattr(user, 'onboarding_first_name', "NA")
        refresh['onboarding_last_name'] = getattr(user, 'onboarding_last_name', "NA")
        refresh['onboarding_org_name'] = getattr(user, 'onboarding_org_name', "NA")
        subscription_till_str = getattr(user, 'subscription_till', None)
        if subscription_till_str:
            subscription_till = datetime.strptime(subscription_till_str, "%Y-%m-%d %H:%M:%S")         
        if current_datetime < subscription_till:              
            refresh['subscription_till'] = getattr(user, 'subscription_till', "NA") 
            logger.info(
            f"{username} logged in",
            extra={                
                "be_api_endpoint": "login",
                "exception": ""
            }
            )           
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "message": True
            })
        else:
            details = coll_registered_organization.find_one({"organization_id":getattr(user, 'onboarding_org_id', 'NA')})
            if details:
                if current_datetime > details["subscription_to"] :
                    renew_status, subs_msg, subsription_todate = onboarding.check_subscription_renewed_login(username, password, getattr(user, 'onboarding_org_id', 'NA'))
                    if renew_status:
                        refresh['subscription_till'] = subsription_todate
                        logger.info(
                            f"{username} logged in & Subscription renewed",
                            extra={                
                                "be_api_endpoint": "login",
                                "exception": ""
                            }
                            )   
                        return Response({
                            "access": str(refresh.access_token),
                            "refresh": str(refresh),
                            "message": True
                        })
                    else:
                        refresh['subscription_till'] = str(details["subscription_to"])
                        logger.info(
                            f"{username} logged in & {subs_msg}",
                            extra={                
                                "be_api_endpoint": "login",
                                "exception": ""
                            }
                            )  
                        return Response({   
                                    "access": str(refresh.access_token),
                                    "refresh": str(refresh),         
                                    "message": True
                                })  
                else:
                    refresh['subscription_till'] = str(details["subscription_to"])
                    return Response({
                            "access": str(refresh.access_token),
                            "refresh": str(refresh),
                            "message": True
                        })
    # Perform your custom validation before creating a new user (add logic here)
    # Example: Check if username meets your policy, etc.
    onboard_status, onuser_role, onorg_id, user_id, first_name, last_name, org_name, to_date = onboarding.check_login_onboarding_new(username, password)
    if onboard_status == "True":
        if onuser_role == "ADMIN":
            onuser_role = "org-admin"
        else:
            onuser_role = "org-user"
        # Create new user
        user = User.objects.create_user(username=username, 
                                        password=password,
                                        role=onuser_role,
                                        onboarding_org_id=onorg_id,
                                        onboarding_user_id=user_id,
                                        onboarding_first_name=first_name,
                                        onboarding_last_name=last_name,
                                        onboarding_org_name=org_name,
                                        subscription_till=to_date
                                        )
        # Generate JWT tokens for new user
        refresh = RefreshToken.for_user(user)
        # Manually add custom claim for 'role'
        refresh['role'] = user.role  # Assuming 'role' is a field on your user model
        refresh['subscription_till'] = user.subscription_till
        refresh['onboarding_org_id'] = user.onboarding_org_id
        refresh['onboarding_user_id'] = user.onboarding_user_id
        refresh['onboarding_first_name'] = user.onboarding_first_name
        refresh['onboarding_last_name'] = user.onboarding_last_name
        refresh['onboarding_org_name'] = user.onboarding_org_name
        logger.info(
                            f"New user: {username} added ",
                            extra={                
                                "be_api_endpoint": "login",
                                "exception": ""
                            }
                            )  
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),            
            "message": True
        })
    else:
        logger.error(f"New user: {username} not added due to {onboard_status} ",
                            extra={                
                                "be_api_endpoint": "login",
                                "exception": ""
                            }
                    )  
        return Response({            
            "message": False,
            "msg_status": onboard_status
        })

@swagger_auto_schema(
    method='post',
    tags=['Add Device'],
    request_body=AddReachLinkDeviceSerializer,
    responses={200: MessageSerializer}
)        
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def login(request: HttpRequest):
    data = json.loads(request.body)    
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "reachlink_spoke_login" }
                    )
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Authorization header missing or malformed'}, safe=False)

    token = auth_header.split(' ')[1]
    try:
        # Verify and decode the token
        decodedtoken = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])       

    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, safe=False)

    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, safe=False)
    orgname = decodedtoken.get("onboarding_org_name", False)
    data["organization_id"] = decodedtoken.get("onboarding_org_id", False)
    if not orgname or not data["organization_id"]:
        logger.error(f"Error: Get Configure Microtek HUB: Error in getting organization name ")
        json_response = {"message": f"Error:Error in getting organization name or id"}
        return JsonResponse(json_response, safe=False)     
    
    global newuser
    try:
        response, newuser = onboarding.check_user(data, newuser)         
        if "spokedevice_name" in response[0]:
            client_name = response[0]["spokedevice_name"]
            output_file = os.path.expanduser(f"~/{client_name}.ovpn")
            if not os.path.exists(output_file):                
                new_client(client_name) 
            with open(output_file, 'r') as file:
                conffile_content = file.read()
                file.close()
            response1 = HttpResponse(conffile_content, content_type='text/plain')
            response1['Content-Disposition'] = f'attachment; filename="{client_name}.ovpn"'
            response1['X-Message'] = json.dumps(response)
            #background_thread = threading.Thread(target=setass, args=(response,"ubuntu",))
            #background_thread.start() 
        else:
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(response)        
    except Exception as e:
        logger.error(f"Error: Login request: {e}")
        response = [{"message": "Internal Server Error", "expiry_date": dummy_expiry_date}]
        response1 = HttpResponse(content_type='text/plain')
        response1['X-Message'] = json.dumps(response)
    return response1
@swagger_auto_schema(
    method='post',
    tags=['Add Device'],
    request_body=AddDeviceSerializer,
    responses={200: MessageSerializer}
) 
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_cisco_device(request: HttpRequest):
    try:
        data = json.loads(request.body)         
        data['branch_location'] = data['branch_location'].lower()
        global newuser    
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "configure_spoke" }
                    ) 
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authorization header missing or malformed'}, safe=False)

        token = auth_header.split(' ')[1]
        try:
            # Verify and decode the token
            decodedtoken = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])       

        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, safe=False)

        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, safe=False)        
        organization_id = decodedtoken.get("onboarding_org_id", "admin")                
        if organization_id == "admin":
            org_info = coll_registered_organization.find_one({"organization_id": data["organization_id"]})
            if org_info:
                orgname = org_info["organization_name"]
                data["username"] = org_info["regusers"][0]["username"]            
            else:               
                logger.error(
                            f"Error: Configure spoke: Error in getting organization name ",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": ""
                            }
                        ) 
                json_response = [{"message": f"Error:Error in getting organization name"}]
                response = HttpResponse(content_type='application/zip')
                response['X-Message'] = json.dumps(json_response)
                response["Access-Control-Expose-Headers"] = "X-Message"
                return response
        else:
            data["organization_id"] = organization_id
            orgname = decodedtoken.get("onboarding_org_name", "NA")
            data["username"] = decodedtoken.get("onboarding_first_name", "NA")
        if data["device"].lower() == "robustel":        
            data["uuid"] = data['branch_location'] + f"_{orgname}_robustel.net"      
            try:
                response, newuser = onboarding.check_user(data, newuser) 
                if "spokedevice_name" in response[0]:
                    client_name = response[0]["spokedevice_name"]
                    # Path configuration
                    output_file = os.path.expanduser(f"~/{client_name}.ovpn")
                    if not os.path.exists(output_file):                    
                        if not(new_client(client_name)):                        
                            logger.error(
                                f"Error: Configure Robustel Spoke: Issue with client certificate generation",
                                extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": ""
                                }
                            ) 
                            response = [{"message": "Internal Server Error", "expiry_date": dummy_expiry_date}]
                            response1 = HttpResponse(content_type='text/plain')
                            response1['X-Message'] = json.dumps(response)
                            response1["Access-Control-Expose-Headers"] = "X-Message"
                            return response1                
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
                    logger.info(
                            f"New Robustel client: {client_name} added",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": ""
                            }
                        ) 
                    json_response = [{"message": response[0]["message"]}]
                    response1 = HttpResponse(buffer, content_type='application/zip')
                    response1['Content-Disposition'] = 'attachment; filename="reachlink_conf.zip"'
                    response1['X-Message'] = json.dumps(json_response)
                    response1["Access-Control-Expose-Headers"] = "X-Message"
                    os.system("systemctl restart reachlink_test") 
                    with open(device_info_path, "r") as f:
                        registered_organization = json.load(f)
                        f.close()
                    for org in registered_organization:
                        if org["organization_id"] == data["organization_id"]:
                            org["total_no_inactive_spokes"] += 1
                            org["branch_info_only"].append({
                                                "uuid": data["uuid"],
                                                "tunnel_ip": "None",
                                                "public_ip": "None",
                                                "branch_location": data["branch_location"].lower(),
                                                "subnet": [],
                                                "vrf": "",
                                                "hub_ip": hub_ip,
                                                "host_id": "",
                                                "status": "inactive",
                                                "spokedevice_name": response[0]["spokedevice_name"]
                                            })
                            for hub in org["hub_info"]:
                                if hub["hub_ip"] == hub_ip:
                                    hub["no_inactive_spoke"] += 1
                                    hub["bandwidth_info"].append({
                                                    "branch_location": data["branch_location"].lower(),
                                                    "bits_recieved": 0,
                                                    "bits_sent": 0
                                                    })
                                    hub["inactive_spokes"].append(data["branch_location"].lower())
                                    hub["spokes_info"]["robustel_spokes"]["spokes_info"].append({
                                                "uuid": data["uuid"],
                                                "tunnel_ip": "None",
                                                "public_ip": "None",
                                                "branch_location": data["branch_location"].lower(),
                                                "subnet": [],
                                                "vrf": "",
                                                "hub_ip": hub_ip,
                                                "host_id": "",
                                                "status": "inactive",
                                                "spokedevice_name": response[0]["spokedevice_name"]
                                            })
                                    hub["spokes_info"]["robustel_spokes"]["no_inactive_spokes"] += 1
                    with open(device_info_path, "w") as f:
                        json.dump(registered_organization, f)
                        f.close()                                   
                    return response1   
                else:                
                    logger.error(
                            f"Error: Configure Robustel Spoke:{response[0]['message']}",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": ""
                            }
                        ) 
                    json_response = [{"message": f"Error:{response[0]['message']}"}]
            except Exception as e:            
                logger.error(
                            f"Error: Configure Robustel Spoke",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": str(e)
                            }
                        ) 
            json_response = [{"message": f"Error:{response[0]['message']}"}]
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(json_response)
            response1["Access-Control-Expose-Headers"] = "X-Message"
            return response1    
        if "microtik" in data["device"].lower():        
            data["uuid"] = data['branch_location'] + f"_{orgname}_microtek.net"     
            try:
                response, newuser = onboarding.check_user(data, newuser)  
                if "spokedevice_name" in response[0]:
                    client_name = response[0]["spokedevice_name"]
                    # Path configuration
                    output_file = os.path.expanduser(f"/root/{client_name}.ovpn")
                    if not os.path.exists(output_file):                        
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
                    with open(microtik_exe_path, "rb") as f:
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
                    logger.info(
                            f"New Microtek {client_name} added",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": ""
                            }
                        ) 
                    response1 = HttpResponse(buffer, content_type='application/zip')
                    response1['Content-Disposition'] = 'attachment; filename="reachlink_conf.zip"'
                    response1['X-Message'] = json.dumps(json_response)
                    response1["Access-Control-Expose-Headers"] = "X-Message"
                    os.system(f"python3 {reachlink_zabbix_path}")
                    os.system("systemctl restart reachlink_test")  
                    with open(device_info_path, "r") as f:
                        registered_organization = json.load(f)
                        f.close()
                    for org in registered_organization:
                        if org["organization_id"] == data["organization_id"]:
                            org["total_no_inactive_spokes"] += 1
                            org["branch_info_only"].append({
                                                "uuid": data["uuid"],
                                                "tunnel_ip": "None",
                                                "public_ip": "None",
                                                "branch_location": data["branch_location"].lower(),
                                                "subnet": [],
                                                "vrf": "",
                                                "hub_ip": hub_ip,
                                                "host_id": "",
                                                "status": "inactive",
                                                "spokedevice_name": response[0]["spokedevice_name"]
                                            })
                            for hub in org["hub_info"]:
                                if hub["hub_ip"] == hub_ip:
                                    hub["no_inactive_spoke"] += 1
                                    hub["bandwidth_info"].append({
                                                    "branch_location": data["branch_location"].lower(),
                                                    "bits_recieved": 0,
                                                    "bits_sent": 0
                                                    })
                                    hub["inactive_spokes"].append(data["branch_location"].lower())
                                    hub["spokes_info"]["microtek_spokes"]["spokes_info"].append({
                                                "uuid": data["uuid"],
                                                "tunnel_ip": "None",
                                                "public_ip": "None",
                                                "branch_location": data["branch_location"].lower(),
                                                "subnet": [],
                                                "vrf": "",
                                                "hub_ip": hub_ip,
                                                "host_id": "",
                                                "status": "inactive",
                                                "spokedevice_name": response[0]["spokedevice_name"]
                                            })
                                    hub["spokes_info"]["microtek_spokes"]["no_inactive_spokes"] += 1
                    with open(device_info_path, "w") as f:
                        json.dump(registered_organization, f)
                        f.close()                    
                    return response1 
                else:                
                    logger.error(
                            f"Error: Configure Microtek Spoke:{response[0]['message']}",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": ""
                            }
                        )              
                    json_response = [{"message": f"Error:{response[0]['message']}"}]
            except Exception as e:            
                logger.error(
                            f"Error: Configure Microtek Spoke",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": str(e)
                            }
                        )     
                json_response = [{"message": f"Error while configuring, pl try again!"}]
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(json_response)
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
                data["uuid"] = data['branch_location'] + f"_{orgname}_ciscodevice.net"
            else:
                data["uuid"] = data['branch_location'] + f"_{orgname}_cisco_ubuntu.net"
            data["username"] = "none"
            data["password"] = "none" 
            try:
                response, newuser = onboarding.check_user(data, newuser)                            
                if response[0]["message"] == "Successfully Registered" or response[0]["message"] == "This Cisco Spoke is already Registered":
                    devicename = response[0]["spokedevice_name"]
                    devicedialerinfo = coll_dialer_ip.find_one({"dialerusername":devicename})
                    dialer_ip = data.get("dialer_ip", "")
                    if not devicedialerinfo: #New device
                        routerpassword = hub_config.generate_router_password_cisco()
                        routerusername = devicename.lower()
                        if data.get("dialer_ip", "") != hub_ip:
                            newdialerinfo = hub_config.get_dialer_ip_fromciscohub(devicename, dialer_ip )
                        else:
                            newdialerinfo = ubuntu_info.get_dialer_ip(devicename)
                    else:
                        routerpassword = devicedialerinfo["router_password"]
                        routerusername = devicedialerinfo["router_username"]
                        if devicedialerinfo["dialer_hub_ip"] == dialer_ip: #same hub
                            newdialerinfo= {"dialerip": devicedialerinfo["dialerip"],
                                        "dialerpassword": devicedialerinfo["dialerpassword"],
                                        "dialerusername": devicedialerinfo["dialerusername"],
                                        "hub_dialer_network":devicedialerinfo["hub_dialer_network"],
                                        "hub_dialer_netmask":devicedialerinfo["hub_dialer_netmask"]}
                        else:
                            if data.get("dialer_ip", "") != hub_ip:
                                newdialerinfo = hub_config.get_dialer_ip_fromciscohub(devicename, dialer_ip )
                            else:
                                newdialerinfo = ubuntu_info.get_dialer_ip(devicename)                 
                    if newdialerinfo:
                        newdialerinfo["router_username"] = routerusername
                        newdialerinfo["router_password"] = routerpassword
                        newdialerinfo["spokedevice_name"] = devicename
                        newdialerinfo["uuid"] = data["uuid"]
                        newdialerinfo["hub_dialer_wildcardmask"] = ".".join(str(255 - int(octet)) for octet in newdialerinfo["hub_dialer_netmask"].split("."))
                        newdialerinfo["router_wan_ip_only"] = data["router_wan_ip"].split("/")[0]
                        subnet = ipaddress.IPv4Network(data["router_wan_ip"], strict=False)  # Allow non-network addresses
                        newdialerinfo["router_wan_ip_netmask"] = str(subnet.netmask) 
                        coll_dialer_ip.update_one({"uuid": data["uuid"]}, #filter
                                                  {"$set":{"uuid": data["uuid"],
                                                            "router_username": routerusername,
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
                                                            }
                                                    }, #update
                                                    upsert=True                  # this enables "insert if not found"
                                                ) 
                        organizationid = response[0]["organization_id"]
                        regdevices = coll_registered_organization.find_one({"organization_id":organizationid}) 
                        if data.get("dialer_ip", "") != hub_ip:
                            for dev in regdevices["registered_devices"]:                    
                                if "cisco_hub_info" in dev:
                                    if data["dialer_ip"] == dev["cisco_hub_info"]["hub_wan_ip_only"]: 
                                        for cispoke in  dev["cisco_spokes_info"]:                         
                                            if data["uuid"] == cispoke["uuid"]:
                                                cispoke["router_username"] = routerusername
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
                                                cispoke["router_username"] = routerusername
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
                        logger.error(
                            f"Error:while generating dialerip for cisco",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": ""
                            }
                        )    
                        json_response = [{"message": f"Error:while generating dialerip"}]
                        response = HttpResponse(content_type='application/zip')
                        response['X-Message'] = json.dumps(json_response)
                        response["Access-Control-Expose-Headers"] = "X-Message"
                        return response                  

                    # Create a buffer for the ZIP file
                    buffer = io.BytesIO()
                    if data.get("dialer_ip", "") != hub_ip:
                        # Create a ZIP archive
                        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                            # Read the EXE file and add it to the ZIP
                            with open(cisco_spoke_exe_path, "rb") as f:
                                zip_file.writestr("reachlink_config.exe", f.read())
                        # Prepare the response
                        buffer.seek(0)
                    else:
                        # Create a ZIP archive
                        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                            # Read the EXE file and add it to the ZIP
                            with open(reachlink_cisco_exe_path, "rb") as f:
                                zip_file.writestr("reachlink_config.exe", f.read())
                        # Prepare the response
                        buffer.seek(0)
                    json_response = [{"message": response[0]["message"]}]
                    logger.info(
                            f"{response[0]['message']}",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": ""
                            }
                        )  
                    response = HttpResponse(buffer, content_type='application/zip')
                    response['Content-Disposition'] = 'attachment; filename="reachlink_conf.zip"'
                    response['X-Message'] = json.dumps(json_response)
                    response["Access-Control-Expose-Headers"] = "X-Message"                        
                    os.system(f"python3 {reachlink_zabbix_path}")
                    os.system("systemctl restart reachlink_test")  
                    logger.info(
                            f"test log",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": ""
                            }
                        )               
                    with open(device_info_path, "r") as f:
                        registered_organization = json.load(f)
                        f.close()
                    for org in registered_organization:
                        if org["organization_id"] == data["organization_id"]:
                            org["total_no_inactive_spokes"] += 1
                            org["branch_info_only"].append({
                                                "uuid": data["uuid"],
                                                "tunnel_ip": "None",
                                                "public_ip": "None",
                                                "branch_location": data["branch_location"],
                                                "subnet": [],
                                                "vrf": "",
                                                "hub_ip": data.get("dialer_ip", ""),
                                                "host_id": "",
                                                "status": "inactive",
                                                "spokedevice_name": response[0]["spokedevice_name"]
                                            })
                            for hub in org["hub_info"]:
                                if hub["hub_ip"] == data.get("dialer_ip", ""):
                                    hub["no_inactive_spoke"] += 1
                                    hub["bandwidth_info"].append({
                                                    "branch_location": data["branch_location"],
                                                    "bits_recieved": 0,
                                                    "bits_sent": 0
                                                    })
                                    hub["inactive_spokes"].append(data["branch_location"])
                                    newbranchinfo = {
                                                "uuid": data["uuid"],
                                                "tunnel_ip": "None",
                                                "public_ip": "None",
                                                "branch_location": data["branch_location"],
                                                "subnet": [],
                                                "vrf": "",
                                                "hub_ip": data.get("dialer_ip", ""),
                                                "host_id": "",
                                                "status": "inactive",
                                                "spokedevice_name": response[0]["spokedevice_name"]
                                            }
                                    if data.get("dialer_ip", "") == hub_ip:
                                        hub["spokes_info"]["cisco_spokes"]["spokes_info"].append(newbranchinfo)
                                        hub["spokes_info"]["cisco_spokes"]["no_inactive_spokes"] += 1
                                    else:                                        
                                        hub["spokes_info"].append(newbranchinfo)                                        
                    with open(device_info_path, "w") as f:
                        json.dump(registered_organization, f)
                        f.close()                               
                    return response
                else:
                    json_response = [{"message": f"Error:{response[0]['message']}"}]
            except Exception as e:
                logger.error(
                            "Error: Configure cisco spoke",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": str(e)
                            }
                        )             
                json_response = [{"message": f"Error:Internal Server Error, pl try again!"}]
            response = HttpResponse(content_type='application/zip')
            response['X-Message'] = json.dumps(json_response)
            response["Access-Control-Expose-Headers"] = "X-Message"
            return response
        else:
            return JsonResponse(
                {"message": "client-side input error"},
                status=400
            )
    except Exception as e:
        logger.error(
                            "Error: Configure cisco spoke",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure spoke",
                                "exception": str(e)
                            }
                        ) 
        if isinstance(e, (KeyError, ValueError)):
            return JsonResponse(
                {"message": "client-side input error"},
                status=400
            )
        json_response = {
            "message": "Error while configuring spoke, please try again!"
            }
        return JsonResponse(json_response, status=500)  # Internal Server Error

@swagger_auto_schema(
    method='post',
    tags=['Add Device'],
    request_body=AddHubDeviceSerializer,
    responses={200: MessageSerializer}
) 
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_cisco_hub(request: HttpRequest):
    data = json.loads(request.body)    
    data['branch_location'] = data['branch_location'].lower()
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "configure_hub" }
                    )
    subnet = ipaddress.IPv4Network(data["hub_dialer_ip"], strict=False)  # Allow non-network addresses
    hub_dialer_netmask = str(subnet.netmask) 
    # Extract the network address
    hub_dialer_network = str(subnet.network_address)   
    for hubinf in coll_hub_info.find({}):
        if hubinf["hub_dialer_network"] == hub_dialer_network:
            if hubinf["hub_ip"] != data["hub_ip"]:
                json_response = [{"message": f"Error: This Dialer network ID already available, pl choose different one."}]                
                logger.error(
                            "Error: This Dialer network ID already available",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure HUB",
                                "exception": ""
                            }
                        )             
                response = HttpResponse(content_type='application/zip')
                response['X-Message'] = json.dumps(json_response)
                response["Access-Control-Expose-Headers"] = "X-Message"
                return response
    orgstatus = False
    print("cisco hub data", data)    
    if "organization_id" in data:
        org_info = coll_registered_organization.find_one({"organization_id": data["organization_id"]})
        if org_info:
            orgname = org_info["organization_name"]
            data["username"] = org_info["regusers"][0]["username"]
            orgstatus = True
        else:
            orgstatus = False
    elif "access_token" in data:
        orgname, orgstatus = onboarding.organization_name(data)
    if not orgstatus:
        logger.error(
                            "Error: Error in getting organization name ",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure HUB",
                                "exception": ""
                            }
                        ) 
        json_response = [{"message": f"Error:Error in getting organization name"}]
        response = HttpResponse(content_type='application/zip')
        response['X-Message'] = json.dumps(json_response)
        response["Access-Control-Expose-Headers"] = "X-Message"
        return response
    data["uuid"] = data['branch_location'] + f"_{orgname}_ciscohub.net"
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
            configuredhubinfo = coll_hub_info.find_one({"uuid": data["uuid"]})            
            coll_tunnel_ip.delete_many({"uuid":data["uuid"]}) 
            devicehubinfo = {}           
            if  configuredhubinfo: #old HUB
                devicehubinfo["router_password"] = configuredhubinfo["router_password"]                
                devicehubinfo["router_username"] = configuredhubinfo["router_username"]
            else:
                devicehubinfo["router_password"] = hub_config.generate_router_password_cisco()
                devicehubinfo["router_username"] = devicename.lower()             
            devicehubinfo["hub_dialer_ip"] = data["hub_dialer_ip"].split("/")[0]
            devicehubinfo["hub_dialer_netmask"] = hub_dialer_netmask
            # Extract the network address
            devicehubinfo["hub_dialer_network"] = hub_dialer_network                   
            data["hub_wan_ip"] = data["hub_ip"]                
            devicehubinfo["hub_wan_ip_only"] = data["hub_wan_ip"].split("/")[0]
            wansubnet = ipaddress.IPv4Network(data["hub_wan_ip"], strict=False)  # Allow non-network addresses
            devicehubinfo["hub_wan_ip_netmask"] = str(wansubnet.netmask)          
            coll_hub_info.update_one({"uuid": data["uuid"]}, #query
                                     {"$set": {"uuid": data["uuid"],
                                                "router_username": devicehubinfo["router_username"],
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
                                                }
                                        }, #update
                                        upsert=True                  # this enables "insert if not found"
                                        ) 
            organizationid = response[0]["organization_id"]
            regdevices = coll_registered_organization.find_one({"organization_id":organizationid}) 
            for dev in regdevices["registered_devices"]:                    
                if "cisco_hub_info" in dev:
                    if data["uuid"] == dev["cisco_hub_info"]["uuid"]:
                            dev["cisco_hub_info"]["router_username"] = devicehubinfo["router_username"]
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
            logger.info(
                            f"{response[0]['message']}:{devicename}",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure HUB",
                                "exception": ""
                            }
                        ) 
            response = HttpResponse(buffer, content_type='application/zip')
            response['Content-Disposition'] = 'attachment; filename="reachlink_hub_conf.zip"'
            response['X-Message'] = json.dumps(json_response)
            response["Access-Control-Expose-Headers"] = "X-Message"
            print("hub config response", response)
            return response
        else:
            json_response = [{"message": f"Error:{response[0]['message']}"}]
    except Exception as e:        
        logger.error(
                            f"Error while configuring HUB",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure HUB",
                                "exception": str(e)
                            }
                        ) 
        json_response = [{"message": f"Error:Internal Server Error, pl try again!"}]
    print(json_response)
    response = HttpResponse(content_type='application/zip')
    response['X-Message'] = json.dumps(json_response)
    response["Access-Control-Expose-Headers"] = "X-Message"
    return response

@swagger_auto_schema(
    method='get',    
    tags=['Home'],
    responses={200: "Home page info JSON"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def homepage_info(request: HttpRequest):
    try:  
        #organization_id = str(request.GET.get('organization_id')) 
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authorization header missing or malformed'}, safe=False)

        token = auth_header.split(' ')[1]
        try:
            # Verify and decode the token
            decodedtoken = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])       

        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, safe=False)

        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, safe=False)        
        organization_id = decodedtoken.get("onboarding_org_id", "admin")        
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {organization_id}",
                    extra={ "be_api_endpoint": "homepage_info" }
                    )
        response = {}        
        total_no_branches = 0
             
        cache_key = f"home_page_{organization_id}"
        home_page_details = cache.get(cache_key)
        if home_page_details:
            return JsonResponse(home_page_details, safe=False)
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
                # Store in cache for 60 seconds
                cache.set(cache_key, response, timeout=60)
                return JsonResponse(response, safe=False, status=200)
    except Exception as e:        
        logger.error(f"Error: Home Page info",
                     extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "Home page info",
                                "exception": str(e)
                            }
                    )   
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
    # Store in cache for 60 seconds
    cache.set(cache_key, response, timeout=60)
    return JsonResponse(response, safe=False, status=200)

def adminbranch_info():
    try: 
        with open(device_info_path, "r") as f:
            total_devices = json.load(f)
            f.close()
        adminbranch_info = []
        for device in total_devices:            
                adminbranch_info.append({device["organization_name"]:
                                                {"data":device["branch_info_only"],
                                                "total_branches":device["total_no_active_spokes"] + device["total_no_inactive_spokes"],
                                                "inactive_branches":device["total_no_active_spokes"],
                                                "active_branches": device["total_no_inactive_spokes"],
                                                "organization_id": device["organization_id"]
                                                }
                                        })
    except Exception as e:
        logger.error(f"Error: Getting Branch info",
                     extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "admin branch info",
                                "exception": str(e)
                            }
                    )
    return adminbranch_info

@swagger_auto_schema(
    method='get', 
    tags=['Branch Info'],
    responses={200: "Branch info JSON"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def branch_info(request: HttpRequest):
    try:       
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')        
        #organization_id = str(request.GET.get('organization_id'))
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authorization header missing or malformed'}, safe=False)

        token = auth_header.split(' ')[1]
        try:
            # Verify and decode the token
            decodedtoken = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])       

        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, safe=False)

        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, safe=False)        
        organization_id = decodedtoken.get("onboarding_org_id", "admin")
        if organization_id == "admin":
            try:
                adminbranchinfo = []
                adminbranchinfo = adminbranch_info()
                logger.debug(f"Requested_ip:{public_ip}, payload: {organization_id}",
                    extra={ "be_api_endpoint": "branch_info" }
                    )
            except Exception as e:
                logger.error(f"Error: Getting Admin Branch info:{e}")
            return JsonResponse(adminbranchinfo, safe=False)    
        response = {}
        data = []     
        active_branches = 0
        inactive_branches = 0
        total_no_branches = 0
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
        logger.error(f"Error: Getting Branch info",
                     extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "branch info",
                                "exception": str(e)
                            }
                    )
    response = {    "data":data,
                        "total_branches":total_no_branches,
                        "inactive_branches":inactive_branches,
                        "active_branches": active_branches,
                        "organization_id": organization_id
                    }
    return JsonResponse(response, safe=False)

def adminhub_info():
    try:        
        response = []
        with open(device_info_path, "r") as f:
            total_devices = json.load(f)
            f.close()
        for device in total_devices:
            response.append({device["organization_name"]: 
                                    {    
                                    "data":device["hub_info_only"],
                                    "total_hubs":device["no_of_hubs"],
                                    "inactive_hubs":device["no_inactive_hubs"],
                                    "active_hubs": device["no_active_hubs"],
                                    "organization_id": device["organization_id"]
                                    }
                                })
    except Exception as e:
        logger.error(f"Error: get Admin hub info Spoke",
                     extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "admin hub info",
                                "exception": str(e)
                            }
                    )
    return response

@swagger_auto_schema(
    method='get',   
    tags=['Hub Info'],
    responses={200: "HUB info JSON"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def hub_info(request: HttpRequest):
    try:        
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')        
        #organization_id = str(request.GET.get('organization_id'))
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authorization header missing or malformed'}, safe=False)

        token = auth_header.split(' ')[1]
        try:
            # Verify and decode the token
            decodedtoken = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])       

        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, safe=False)

        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, safe=False)        
        organization_id = decodedtoken.get("onboarding_org_id", "admin")
        if organization_id == "admin":
            try:
                adminhubinfo = []
                adminhubinfo = adminhub_info()
                logger.debug(f"Requested_ip:{public_ip}, payload: {organization_id}",
                    extra={ "be_api_endpoint": "hub_info" }
                    )
            except Exception as e:
                logger.error(f"Error: Getting Admin Hub info:{e}")
            return JsonResponse(adminhubinfo, safe=False)       
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
        logger.error(f"Error: hub info",
                     extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "Hub info",
                                "exception": str(e)
                            }
                    )
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
@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Activate/Deactivate'],
    request_body=ActivateInfoSerializer,
    responses={200: MessageSerializer(many=True)}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deactivate(request: HttpRequest):
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    data = json.loads(request.body) 
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "deactivate" }
                    )
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
                    response = [{"message":f"Successfully disconnected: {data['tunnel_ip']}"}]
                else:
                    response = [{"message":f"Error:while deactivating data['tunnel_ip']"}]   
        else:
            response = [{"message": "Error HUB IP is missed"}]
    if "microtek" in data.get("uuid", ""):
        response = ubuntu_info.deactivate(data)  
    if "robustel" in data.get("uuid", ""):
        response = ubuntu_info.deactivate(data)  
    return JsonResponse(response, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Interfaces'],
    request_body=DeviceInfoSerializer,
    responses={200: InterfaceEntrySerializer(many=True)}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_interface_details_spoke(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_interface_details" }
                    )
        branch_id = data["tunnel_ip"].split("/")[0]
        cache_key = f"interfaces_branch_{branch_id}"
        interface_details = cache.get(cache_key)
        if interface_details:
            return JsonResponse(interface_details, safe=False)
        interface_details = []
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )      
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            try:
                response = requests.get(url + "get_interface_details")                                
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    interface_details = json.loads(get_response)
                    #print(response)      
                else:
                    interface_details =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")  
                logger.error(f"Connection timeout ",
                     extra={
                                "device_type": "ReachlinkSpoke",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "get_interface_info",
                                "exception": str(e)
                            }
                    )     
                interface_details =[]         
        elif "microtek" in data["uuid"]:           
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.interfacedetails(data)                 
            #return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = router_configure.get_interface_cisco(data)
        elif "robustel" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = robustel_configure.get_interface_robustel(data)
        # Store in cache for 60 seconds
        cache.set(cache_key, interface_details, timeout=60)
    except Exception as e:
        logger.error(f"Error in get interface details ",
                     extra={
                                "device_type": "",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "get_interface_info",
                                "exception": str(e)
                            }
                    )        
    return JsonResponse(interface_details, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Interfaces'],
    request_body=VlanAddSpokeSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_vlan_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "create_vlan_interafce_spoke" }
                    )
        branch_id = data["tunnel_ip"].split("/")[0]
        cache_key = f"interfaces_branch_{branch_id}"
        cache.delete(cache_key)
        for int_addr in data["addresses"]:
             # Exclude unwanted categories
            if int(int_addr.split("/")[1]) > 32:
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                logger.error(f"Error: {int_addr} is invalid IP",
                    extra={ "be_api_endpoint": "create_vlan_interface_spoke" }
                    )
                return JsonResponse(response, safe=False, status=400)
            
            ip = ipaddress.IPv4Address(int_addr.split("/")[0])
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_private:     
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                logger.error(f"Error: {int_addr} is invalid IP",
                    extra={ "be_api_endpoint": "create_vlan_interface_spoke" }
                    )
                return JsonResponse(response, safe=False, status=400)
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "create_vlan_interface", data=json_data, headers=headers)                                 
                respstatus = response.status_code
                if response.status_code == 200:           
                    print(response.text)
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)   
                else:                    
                    response = [{"message":"Error while configuring VLAN interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                respstatus = 504
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}] 
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details, respstatus = microtek_configure.createvlaninterface(data)                 
            return JsonResponse(interface_details,safe=False, status = respstatus) 
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response, respstatus = router_configure.createvlaninterface(data)   
        elif "robustel" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response, respstatus = robustel_configure.createvlaninterface(data) 
    except Exception as e:  
        if isinstance(e, (KeyError, ValueError)):            
            respstatus=400
        else:
            respstatus = 500        
        logger.error(f"Error: Create VLAN interface in Spoke:{e}")
        response = [{"message": f"Error: While creating VLAN interface"}]
    return JsonResponse(response, safe=False, status = respstatus)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Interfaces'],
    request_body=VlanAddSpokeSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_sub_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "create_sub_interface_spoke" }
                    )
        if "robustel" in data["uuid"] or "microtek" in data["uuid"]:
            response = [{"message": f"Error: This device doesn't support Sub Interface"}]            
            return JsonResponse(response, safe=False, status=501)
        for int_addr in data["addresses"]:
            if int(int_addr.split("/")[1]) > 32:
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                logger.error(f"Error: {int_addr} is invalid IP",
                    extra={ "be_api_endpoint": "create_sub_interface_spoke" }
                    )
                return JsonResponse(response, safe=False, status=400)
            
            ip = ipaddress.IPv4Address(int_addr.split("/")[0])
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_private:     
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                logger.error(f"Error: {int_addr} is invalid IP",
                    extra={ "be_api_endpoint": "create_sub_interface_spoke" }
                    )
                return JsonResponse(response, safe=False, status=400)
        branch_id = data["tunnel_ip"].split("/")[0]
        cache_key = f"interfaces_branch_{branch_id}"
        cache.delete(cache_key)
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
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
                    response = [{"message":"Error while configuring VLAN interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}]   
        elif "cisco" in data["uuid"]:
            if data["link"].lower() == "fastethernet4":
                data["router_username"] = router_info["router_username"]
                data["router_password"] = router_info["router_password"]
                response = router_configure.createsubinterface(data) 
            else:
                response = [{"message": f"Error: {data['link']} doesn't support sub-interface"}]        
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):            
            respstatus=400
        else:
            respstatus = 500    
        response = [{"message": f"Error: while creating Sub interface"}]
        logger.error(f"Error: Create Sub Interface spoke:{e}")
    return JsonResponse(response, safe=False, status=respstatus)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Interfaces'],
    request_body=LoopbackAddSpokeSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_loopback_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "create_loopback_interface_spoke" }
                    )
        if "robustel" in data["uuid"] or "microtek" in data["uuid"]:
            response = [{"message": "Error: This device doesn't support Loopback Interface"}]
            return JsonResponse(response, safe=False, status=501)
        for int_addr in data["addresses"]:
            if int(int_addr.split("/")[1]) > 32:
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                logger.error(f"Error: {int_addr} is invalid IP",
                    extra={ "be_api_endpoint": "create_loopback_interface_spoke" }
                    )
                return JsonResponse(response, safe=False, status=400)
            
            ip = ipaddress.IPv4Address(int_addr.split("/")[0])
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_private:     
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                logger.error(f"Error: {int_addr} is invalid IP",
                    extra={ "be_api_endpoint": "create_loopback_interface_spoke" }
                    )
                return JsonResponse(response, safe=False, status=400)
        branch_id = data["tunnel_ip"].split("/")[0]
        cache_key = f"interfaces_branch_{branch_id}"
        cache.delete(cache_key)
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
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
                    response = [{"message":"Error while configuring Loopback interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}]            
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.createloopbackinterface(data)                       
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):            
            respstatus=400
        else:
            respstatus = 500    
        logger.error(f"Error: Create Loopback Interface Spoke:{e}")
        response = [{"message": f"Error: while creating Loopback Interface"}]
    return JsonResponse(response, safe=False, status=respstatus)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Interfaces'],
    request_body=TunnelAddSpokeSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_tunnel_interface_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "create_tunnel_interface_spoke" }
                    )
        if "robustel" in data["uuid"]:
            response = [{"message": "Error: This device doesn't support Tunnel Interface"}]
            return JsonResponse(response, safe=False, status=501)
        #validation for tunnel address
        for int_addr in data["addresses"]:
            if int(int_addr.split("/")[1]) > 32:
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                logger.error(f"Error: {int_addr} is invalid IP",
                    extra={ "be_api_endpoint": "create_tunnel_interface_spoke" }
                    )
                return JsonResponse(response, safe=False, status=400)
            
            ip = ipaddress.IPv4Address(int_addr.split("/")[0])
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:     
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                logger.error(f"Error: {int_addr} is invalid IP",
                    extra={ "be_api_endpoint": "create_tunnel_interface_spoke" }
                    )
                return JsonResponse(response, safe=False, status=400)
            if not ip.is_private:
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                logger.error(f"Error: {int_addr} is not private IP",
                    extra={ "be_api_endpoint": "create_tunnel_interface_spoke" }
                    )
                return JsonResponse(response, safe=False, status=400)
        #validation for destination ip address:
        ip = ipaddress.IPv4Address(data["destination_ip"].split("/")[0])
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:     
            response = [{"message": f"Error: {data['destination_ip']} is invalid IP"}]
            logger.error(f"Error: {data['destination_ip']} is invalid IP",
                    extra={ "be_api_endpoint": "create_tunnel_interface_spoke" }
                    )
            return JsonResponse(response, safe=False, status=400)
        branch_id = data["tunnel_ip"].split("/")[0]
        cache_key = f"interfaces_branch_{branch_id}"
        cache.delete(cache_key)
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}            
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "create_tunnel_interface", data=json_data, headers=headers)                                
                respstatus = response.status_code
                if response.status_code == 200:           
                    print(response.text)
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)         
                else:
                    response = [{"message":"Error while configuring VLAN interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                respstatus = 504
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}]   
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details, respstatus = microtek_configure.createtunnelinterface(data)  
            return JsonResponse(interface_details,safe=False, status=respstatus) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.createtunnelinterface(data)                   
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):            
            respstatus=400
        else:
            respstatus = 500    
        logger.error(f"Error: Create Tunnel Interface Spoke:{e}")
        response = [{"message": f"Error: While craeting Tunnel interface"}]
    return JsonResponse(response, safe=False, status=respstatus)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Interfaces'],
    request_body=ConfigInterfaceSpokeSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def interface_config_spoke(request):
    try:
        data = json.loads(request.body)
        print(data)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "interface_config_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"interfaces_branch_{branch_id}"
        cache.delete(cache_key)
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
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
                    response = [{"message":"Error while configuring interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}] 
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.interfaceconfig(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.interfaceconfig(data)
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            response = robustel_configure.interface_config(data)
            print(response)
    except Exception as e:
        logger.error(f"Error: Configure Interface Spoke:{e}")
        response = [{"message": f"Error: while configuring interface"}]
    return JsonResponse(response, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Interfaces'],
    request_body=DeleteInterfaceSpokeSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def vlan_interface_delete_spoke(request):
    try:
        data = json.loads(request.body)       
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')        
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "interface_delete" }
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"interfaces_branch_{branch_id}"
        cache.delete(cache_key)
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "vlan_interface_delete", data=json_data, headers=headers)  # Timeout set to 5 seconds
                respstatus = response.status_code             
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)                
                               
                else:
                    response = [{"message":"Error while deleting VLAN interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}]  
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            if "overlay" in data['intfc_name'].lower() or "bridge" in data["intfc_name"].lower():
                response = [{"message": f"Error: Deleting {data['intfc_name']} is prohibited"}]
                respstatus = 200                
            elif "." in data['intfc_name']:
                response, respstatus = microtek_configure.deletevlaninterface(data) 
            else:
                response, respstatus = microtek_configure.deletetunnelinterface(data)             
            return JsonResponse(response,safe=False, status=respstatus) 
        elif "cisco" in data["uuid"]:
            if "virtual-template" in data["intfc_name"].lower() or "dialer1" in data["intfc_name"].lower():
                response = [{"message": f"Error: Deleting {data['intfc_name']} is prohibited"}]
                return JsonResponse(response, safe=False)
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.deletevlaninterface(data)
        elif "robustel" in data["uuid"]:
            if "vlan" in data["intfc_name"].lower():
                data["router_username"] = router_info["router_username"]
                data["router_password"] = router_info["router_password"]
                response = robustel_configure.deletevlaninterface(data)
            else:
                response = [{"message": f"Error: {data['intfc_name']} deletion is prohibited"}]
                logger.info(f"Error: {data['intfc_name']} deletion is prohibited",
                                        extra={
                                                "device_type": "Robustel",
                                                "device_ip": data["tunnel_ip"].split("/")[0],
                                                "be_api_endpoint": "interface_delete",
                                                "exception": ""
                                        }
                                    )
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):            
            respstatus=400
        else:
            respstatus = 500   
        logger.error(
            f"Error while deleting interface",
            extra={
                "device_type": "",
                "device_ip": data["tunnel_ip"],
                "be_api_endpoint": "delete_interface",
                "exception": str(e)
            }
            ) 
        response = [{"message": f"Error: while deleting interface"}]
    return JsonResponse(response, safe=False, status=respstatus)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Routes'],
    request_body=DeviceInfoSerializer,
    responses={200: RouteEntrySerializer(many=True)}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_routing_table_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_routing_table_spoke" }
                    )
        branch_id = data["tunnel_ip"].split("/")[0]
        cache_key = f"routing_branch_{branch_id}"
        routing_table = cache.get(cache_key)
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
        if routing_table:
            return JsonResponse(routing_table, safe=False)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"               
            try:
                response = requests.get(url + "get_routing_table")                                 
                if response.status_code == 200:      
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    routing_table = json.loads(get_response)                               
                else:                    
                    routing_table =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                routing_table = []
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            routing_table = microtek_configure.routingtable(data)                 
        elif "cisco" in data["uuid"]:       
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            routing_table = router_configure.get_routingtable_cisco(data)
        elif "robustel" in data["uuid"]:       
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            routing_table = robustel_configure.get_routingtable_robustel(data)
        # Store in cache for 60 seconds
        cache.set(cache_key, routing_table, timeout=60)
    except Exception as e:
        logger.error(f"Error: Get routing table spoke:{e}")
        routing_table = []
    return JsonResponse(routing_table, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Routes'],
    request_body=AddRouteInfoSerializer,
    responses={200: MessageSerializer(many=True)}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def add_route_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "add_sttaic_route_spoke" }
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"routing_branch_{branch_id}"
        cache.delete(cache_key)
        response = [{"message":"Error in adding route"}]
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
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
                    response = [{"message":"Error while deleting VLAN interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}]  
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            route_details = microtek_configure.addroute(data)                 
            return JsonResponse(route_details,safe=False) 
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            status = router_configure.addroute(data)
            if status:
                response = [{"message": "Route(s) added"}]
            else:
                response = [{"message":"Error in adding route. Pl try again!"}]            
        elif "robustel" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = robustel_configure.addstaticroute(data)         
    except Exception as e:
        logger.error(f"Error: Adding route in Spoke:{e}")
        response = [{"message": f"Error: while adding route. Pl try again!"}]
    return JsonResponse(response, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Routes'],
    request_body=DelRouteInfoSerializer,
    responses={200: MessageSerializer(many=True)}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def del_staticroute_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "delete_static_route_spoke" }
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"routing_branch_{branch_id}"
        cache.delete(cache_key)
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
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
                    response = [{"message":"Error while deleting VLAN interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}]   
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            route_details = microtek_configure.delstaticroute(data)                 
            return JsonResponse(route_details,safe=False) 
        elif "robustel" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            subnets = data["routes_info"]
            for subnet in subnets:
                if "8.8." in subnet["destination"]:
                    route_details = [{"message":f"Error: Deletion of this route ({subnet}) is prohibited"}]
                    break
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            route_details = robustel_configure.delstaticroute(data)                 
            return JsonResponse(route_details,safe=False) 
        elif "cisco" in data["uuid"]:
            #router_info = coll_dialer_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            for subnet in data["routes_info"]:
                if subnet["destination"].split("/")[0] == router_info["dialer_hub_ip"]:
                    response = [{"message":f"Error: This route ({subnet}) not able to delete"}]
                    return JsonResponse(response, safe=False)  
            status = router_configure.delstaticroute(data)
            if status:
                response = [{"message": "Successfully route deleted"}]
            else:
                response = [{"message":"Error in deleting route"}]
    except Exception as e:
        logger.error(f"Error: Delete route in Spoke:{e}")
        response = [{"message": f"Error: while deleting route"}]
    return JsonResponse(response, safe=False)        

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - PBR'],
    request_body=DeviceInfoSerializer,
    responses={200: MessageSerializer(many=True)}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_pbr_info_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_pbr_info_spoke" }
                    )
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
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
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.getconfigurepbr(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
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
@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Diagnostics'],
    request_body=PingHubInfoSerializer,
    responses={200: "Message with RTT(Round Trip Time)"}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated]) 
def diagnostics(request: HttpRequest):
    data = json.loads(request.body)   
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "ping_from_hub" }
                    )
    try:
        if "cisco" in data["uuid"]:                   
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
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
                    response = [{"message":f"Error: Subnet {data['subnet']} Not Reachable"}]
                else:
                    rtt = last_line.split(" ")[9].split("/")[1]
                    print(rtt)
                    response = [{"message":f"Subnet {data['subnet']} Reachable with RTT: {rtt}ms"}]
            else:
                response = [{"message":f"Error: Hub info not found"}]        
        else:
            response = ubuntu_info.diagnostics(data)
    except Exception as e:
        logger.error(f"Error: Ping from HUB:{e}")
    return JsonResponse(response, safe=False)  

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Diagnostics'],
    request_body=PingSpokeInfoSerializer,
    responses={200: "Message with RTT(Round Trip Time)"}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def ping_spoke(request: HttpRequest):  
    try: 
        data = json.loads(request.body) 
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "ping_from_spoke" }
                    )
        if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
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
                    response = [{"message":f"Subnet {data['subnet']} Reachable with RTT: {json_response[0]['avg_rtt']}ms"}]
                else:
                    response = [{"message": f"Error: Subnet {data['subnet']} Not Reachable"}]
            else:
                print("error response", response)
                response =  {"message": f"Error: Subnet {data['subnet']} Not Reachable" }
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            ping_result = microtek_configure.pingspoke(data)          
            if ping_result == "-1":
                response = [{"message":f"Error: Subnet {data['subnet']} Not Reachable"}]
            else:                
                response = [{"message":f"Subnet {data['subnet']} Reachable with RTT: {ping_result}"}]
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            ping_result = router_configure.pingspoke(data)
            re = ping_result.split("\n")
            last_line = re[-2]
            print(last_line)
            out = last_line.split(" ")[3]            
            print(out)
            if out == "0":
                response = [{"message":f"Error: Subnet {data['subnet']} Not Reachable"}]
            else:
                rtt = last_line.split(" ")[9].split("/")[1]
                print(rtt)
                response = [{"message":f"Subnet {data['subnet']} Reachable with RTT: {rtt}ms"}]
        elif "robustel" in data["uuid"]:
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = robustel_configure.pingspoke(data)            
    except Exception as e:    
        logger.error(f"Error: Ping from Spoke:{e}")
        response = [{"message": f"Error: Subnet {data['subnet']} Not Reachable" }]   
    return JsonResponse(response, safe=False)    

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Diagnostics'],
    request_body=TraceSpokeInfoSerializer,
    responses={200: "Trace route output"}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def traceroute_spoke(request):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "trace_from_spoke" }
                    )
    host_ip = data.get('trace_ip', None)
    if ".net" in data.get("uuid", ""):       
            cache1_key = f"branch_details_{data['uuid']}"
            router_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_tunnel_ip.find_one({"uuid": data["uuid"]}),
                        timeout=300
                        )    
    if "microtek" in data["uuid"]:
        #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
        data["router_username"] = router_info["router_username"]
        data["router_password"] = router_info["router_password"]
        trace_result = microtek_configure.traceroute(data)   
        response_msg = [{"message": trace_result}]        
        return JsonResponse(response_msg,safe=False) 
    if "robustel" in data["uuid"]:
        #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
        data["router_username"] = router_info["router_username"]
        data["router_password"] = router_info["router_password"]
        trace_result = robustel_configure.traceroute(data)   
        response_msg = [{"message": trace_result}]           
        return JsonResponse(response_msg,safe=False) 
    if "ciscodevice" in data["uuid"]:        
        #device_info = coll_dialer_ip.find_one({"uuid":data["uuid"]})        
        if router_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = router_info["router_username"]
                data["router_password"] = router_info["router_password"]        
                trace_result = router_configure.traceroute(data)   
                response_msg = [{"message": trace_result} ]  
                print("traceroute spoke",response_msg)    
        else:
            response_msg = [{"message": "Error in connecting HUB"} ]
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
                    response_msg = [{"message": content}]
                    return JsonResponse(response_msg,safe=False)
                except Exception as e:
                   print(e)
                   response = [{"message":e}]       
            else:
                    response = [{"message":"Error while sending route info to spoke"}]
        except requests.exceptions.RequestException as e:
                print("disconnected")
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}] 
    else:
        response = [{"message":"Error:Trace ip is invalid"}]
    return JsonResponse(response, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Diagnostics'],
    request_body=TraceHubInfoSerializer,
    responses={200: "Trace route output"}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def traceroute_hub(request):
    data = json.loads(request.body)
    print("trace hub data", data) 
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "trace_from_hub" }
                    )
    host_ip = data.get('trace_ip', None)
    if "cisco" in data["uuid"]:
        cache1_key = f"HUB_details_{data['uuid']}"
        hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
        #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
        if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]        
                trace_result = router_configure.traceroute(data)   
                response = [{"message": trace_result}]                   
        else:
            response = [{"message": "Error in connecting HUB"}]        
    else:           
            result1 = subprocess.run(['traceroute', '-d', host_ip], capture_output=True, text=True)
            response = [{"message":result1.stdout}]
    return JsonResponse(response,safe=False)

##############Inactive branch##############
@swagger_auto_schema(
    method='post',
    tags=['Branch Info - Activate/Deactivate'],
    request_body=ActivateInfoSerializer,
    responses={200: MessageSerializer(many=True)}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def activate(request: HttpRequest):
    data = json.loads(request.body)     
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "activate" }
                    )
    if ".net" not in data.get("uuid", ""):         
        response = ubuntu_info.activate(data)
    if "ciscodevice" in data.get("uuid", ""):
        cache1_key = f"HUB_details_{data['uuid']}"
        hubinfo = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_ip"]}),
                        timeout=300
                        )    
        #hubinfo = coll_hub_info.find_one({"hub_wan_ip_only": data.get("hub_ip", "")})
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
                    response = [{"message":f"Successfully activated: {data['tunnel_ip']}"}]
                else:
                    response = [{"message":f"Error:while activating data['tunnel_ip']"}]     
    if "microtek" in data.get("uuid", ""):
        response = ubuntu_info.activate(data)
    if "robustel" in data.get("uuid", ""):
        response = ubuntu_info.activate(data)
    return JsonResponse(response, safe=False)

###############HUB info page##############################
@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Routes'],
    request_body=HubInfoSerializer,
    responses={200: RouteEntrySerializer(many=True)}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_routing_table(request):
    try:
        data = json.loads(request.body) 
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_hub_routing_table" }
                    )
        branch_id = data["hub_wan_ip"]
        cache_key = f"routing_hub_{branch_id}"
        routing_table = cache.get(cache_key)
        if routing_table:
            return JsonResponse(routing_table, safe=False)
        if "ciscohub" in data["uuid"]:
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                routing_table = router_configure.get_routingtable_cisco(data)
            else:
                routing_table = []
        elif data["hub_wan_ip"] == hub_ip:
            routing_table =ubuntu_info.get_routing_table_ubuntu() 
        # Store in cache for 60 seconds
        cache.set(cache_key, routing_table, timeout=60)       
    except Exception as e:
        logger.error(f"Error: Get hub routing table:{e}")
        routing_table = []
    return JsonResponse(routing_table, safe=False)

def is_excluded(network):
    return (
        network.is_loopback or
        network.is_link_local or
        network.is_multicast or
        network.network_address.is_reserved or
        network.network_address.is_unspecified
    )

@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Routes'],
    request_body=AddRouteHubSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def addstaticroute_hub(request: HttpRequest):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "add_static_route_hub" }
                    )
        routes = data["routes_info"]    
        branch_id = data["hub_wan_ip"] 
        cache_key = f"routing_hub_{branch_id}"
        cache.delete(cache_key)
        for route in routes:
            network = ipaddress.ip_network(route["destination"], strict=False)
            if is_excluded(network):
                response = [{"message":f"Error Invalid destination {route['destination']}"}]
                logger.error(f"Error Invalid destination {route['destination']}",
                              extra = {"be_api_endpoint": "add_static_route_hub",
                                       "exception": ""
                                       }
                                       )
                return JsonResponse(response, safe=False) 
            if dialernetworkip in route["destination"]:
                response = [{"message":f"Error Route conflict {route['destination']}"}]
                logger.error(f"Error Route conflict {route['destination']}",
                              extra = {"be_api_endpoint": "add_static_route_hub",
                                       "exception": ""
                                       }
                                       )
                return JsonResponse(response, safe=False) 
        if "ciscohub" in data["uuid"]:
            print("hiciscohub")
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                data["subnet_info"] = data["routes_info"]
                status = router_configure.addroute(data)
                if status:
                    response = [{"message": "Successfully route added"}]
                else:
                    response = [{"message":"Error in adding route"}]
            else:
                response = [{"message":"Error in getting hub info"}]
        elif data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.addstaticroute_ubuntu(data)
    except Exception as e:  
        logger.error(f"Error: Add static routing in HUB:{e}")
        response =[{"message": f"Error in adding route, pl try again." }]
    return JsonResponse(response, safe=False) 

@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Routes'],
    request_body=AddRouteHubSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def delstaticroute_hub(request: HttpRequest):
    data = json.loads(request.body)
    response = [{"message":"Successfully deleted"}]
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "delete_static_route_hub" }
                    )
    for delroute in data["routes_info"]:
        if "0.0.0.0/0" in delroute["destination"]:
            logger.info(f"Error: Default route deletion is prohibited.")
            response = [{"message":f"Error: Default route deletion is prohibited."}]
            return JsonResponse(response, safe=False)
    branch_id = data["hub_wan_ip"]
    cache_key = f"routing_hub_{branch_id}"
    cache.delete(cache_key)
    try:         
        data = json.loads(request.body)     
        if "ciscohub" in data["uuid"]:
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                status = router_configure.delstaticroute(data)
                if status:
                    response = [{"message": "Successfully route deleted"}]
                else:
                    response = [{"message":"Error in deleting route"}]
        elif data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.delstaticroute_ubuntu(data)
    except Exception as e:
        logger.error(f"Error: Delete static route HUB:{e}")
        response = [{"message":f"Error while deleting route"}]
    return JsonResponse(response, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Interfaces'],
    request_body=HubInfoSerializer,
    responses={200: InterfaceEntrySerializer(many=True)}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
#@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def get_interface_details_hub(request):
    try:
        data = json.loads(request.body)  
        print(data)  
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_interface_details_hub" }
                    )
        branch_id = data["hub_wan_ip"]
        cache_key = f"interfaces_hub_{branch_id}"
        interface_details = cache.get(cache_key)
        if interface_details:
            return JsonResponse(interface_details, safe=False)
        if "_ciscohub" in data["uuid"]:
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                interface_details = router_configure.get_interface_cisco(data)
            else:
                interface_details = []
        elif data["hub_wan_ip"] == hub_ip:            
            interface_details = ubuntu_info.get_interface_details_ubuntu(data)
        # Store in cache for 60 seconds
        cache.set(cache_key, interface_details, timeout=60)            
    except Exception as e:
        logger.error(f"Error: Get Interface_details of HUB:{e}")
        interface_details = []    
    return JsonResponse(interface_details, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Interfaces'],
    request_body=VlanAddHubSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_vlan_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "create_vlan_interface_hub" }
                    )
        branch_id = data["hub_wan_ip"]
        cache_key = f"interfaces_hub_{branch_id}"
        cache.delete(cache_key)
        if "ciscohub" in data["uuid"]:
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
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

@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Interfaces'],
    request_body=VlanAddHubSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_sub_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "creaate_sub_interface_hub" }
                    ) 
        branch_id = data["hub_wan_ip"]
        cache_key = f"interfaces_hub_{branch_id}"
        cache.delete(cache_key)
        if "ciscohub" in data["uuid"]:
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
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

@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Interfaces'],
    request_body=LoopbackAddHubSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_loopback_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "create_loopback_interface_hub" }
                    )
        branch_id = data["hub_wan_ip"]
        cache_key = f"interfaces_hub_{branch_id}"
        cache.delete(cache_key)
        if "ciscohub" in data["uuid"]:
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.createloopbackinterface(data) 
        elif data["hub_wan_ip"] == hub_ip:
            response = [{"message":"Error: This device doesn't support Loopback interface"}] 
    except Exception as e:
        logger.error(f"Error: Create Loopback Interface HUB:{e}")
        response = [{"message": f"Error: Some issue. Pl try again later."}]
    return JsonResponse(response, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Interfaces'],
    request_body=TunnelAddHubSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def create_tunnel_interface_hub(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "create_tunnel_interface_hub" }
                    )
        branch_id = data["hub_wan_ip"]
        cache_key = f"interfaces_hub_{branch_id}"
        cache.delete(cache_key)
        if "ciscohub" in data["uuid"]:
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
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

@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Interfaces'],
    request_body=DeleteInterfaceHubSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def vlan_interface_delete_hub(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "interface_delete_hub" }
                    )
        branch_id = data["hub_ip"]
        cache_key = f"interfaces_hub_{branch_id}"
        cache.delete(cache_key)
        if "ciscohub" in data["uuid"]:
            if data["intfc_name"].lower() == "loopback1":
                response = [{"message": f"Error Don't try to modify interface interface {data['intfc_name']}"}] 
                return JsonResponse(response, safe=False)
            if "virtual-template" in data["intfc_name"].lower():
                response = [{"message": f"Error: Deleting {data['intfc_name']} is prohibited"}]
                return JsonResponse(response, safe=False)
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]                
                response = router_configure.deletevlaninterface(data)                
        elif data["hub_ip"] == hub_ip:
            response = [] 
            intfc_name = data["intfc_name"] 
            if "basetunnel" in  intfc_name.lower():
                response = [{"message": f"Error: {intfc_name} deletion is prohibited"}]
                logger.error(f"Error: {intfc_name} deletion is prohibited",
                             extra={
                                "device_type": "Reachlink_server",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "delete_interface",
                                "exception": ""
                            })
                return JsonResponse(response, safe=False)
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
                if "tunnel" in data["intfc_name"]:
                    # Ensure the `vlans` section exists
                    if "tunnels" not in network_config["network"]:
                        response = [{"message": f"No such VLAN available"}]
                    # Add VLAN configuration
                    else:
                        if intfc_name in network_config["network"]["tunnels"]:
                            del network_config["network"]["tunnels"][intfc_name]          
                        response = [{"message": f"Successfully deleted the Tunnel Interface: {intfc_name}"}]
                # Write the updated configuration back to the file
                with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                    yaml.dump(network_config, f, default_flow_style=False)
                    f.close()
                os.system("netplan apply")            
                cmd = f"sudo ip link del {intfc_name}"
                result = subprocess.run(
                                cmd, shell=True, text=True
                                )    
            #else:            
            #    cmd = f"sudo ip link del {intfc_name}"
            #    result = subprocess.run(
            #                   cmd, shell=True, text=True
            #                   )            
            response = [{"message": f"Successfully  deleted VLAN Interface: {intfc_name}"}]
    except Exception as e:
        logger.error(f"Error: Delete Interface HUB:{e}")
        response = [{"message": f"Error while deleting the VLAN interface interface {data['intfc_name']}: {e}"}] 
    return JsonResponse(response, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Hub Info - Interfaces'],
    request_body=ConfigInterfaceHubSerializer,
    responses={200: MessageSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def interface_config_hub(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "interface_config_hub" }
                    )
        branch_id = data["hub_wan_ip"] 
        cache_key = f"interfaces_hub_{branch_id}"
        cache.delete(cache_key)
        if data["hub_wan_ip"] == hub_ip:
            response = ubuntu_info.interface_config(data)       
        elif "ciscohub" in data["uuid"]:
            if data["intfc_name"].lower() == "loopback1":
                response = [{"message": f"Error dont try to modify {data['intfc_name']} interface address"}]
                print(response)
                return JsonResponse(response, safe=False)
            cache1_key = f"HUB_details_{data['uuid']}"
            hub_info = cache.get_or_set(
                        cache1_key,
                        lambda: coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]}),
                        timeout=300
                        )    
            #hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]                
            response = router_configure.interfaceconfig(data)            
    except Exception as e:
        logger.error(f"Error: Interface configure HUB:{e}")
        response = [{"message": f"Error: interface config"}]
    return JsonResponse(response, safe=False)
##################HUB COMPLETE#################


####################HUB & Spoke setup end point###############
@swagger_auto_schema(
    method='post',
    tags=['Configure Device'],
    request_body=ConfigCiscoHubSerializer,
    responses={200: ConfigCiscoHubResponseSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_ciscohub_config(request: HttpRequest):
    data = json.loads(request.body) 
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_ciscohub_config" }
                    )
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Authorization header missing or malformed'}, safe=False)

    token = auth_header.split(' ')[1]
    try:
        # Verify and decode the token
        decodedtoken = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])      

    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, safe=False)

    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, safe=False)
    orgname = decodedtoken.get("onboarding_org_name", False)
    orgid = decodedtoken.get("onboarding_org_id", False)
    if not orgname or not orgid:
        logger.error(f"Error: Get Configure Microtek HUB: Error in getting organization name ")
        json_response = {"message": f"Error:Error in getting organization name or id"}
        return JsonResponse(json_response, safe=False)     
    data["uuid"] = data['branch_loc'] + f"_{orgname}_ciscohub.net"
    data["orgid"] = orgid
    data["orgname"] = orgname
    response = hub_config.get_ciscohub_config(data)
    return JsonResponse(response, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Configure Device'],
    request_body=ConfigCiscoSpokeSerializer,
    responses={200: ConfigCiscoSpokeResponseSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_ciscospoke_config(request: HttpRequest):
    data = json.loads(request.body) 
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_ciscospoke_config" }
                    )
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Authorization header missing or malformed'}, safe=False)

    token = auth_header.split(' ')[1]
    try:
        # Verify and decode the token
        decodedtoken = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])      

    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, safe=False)

    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, safe=False)
    orgname = decodedtoken.get("onboarding_org_name", False)
    orgid = decodedtoken.get("onboarding_org_id", False)
    if not orgname or not orgid:
        logger.error(f"Error: Get Configure Microtek HUB: Error in getting organization name ")
        json_response = {"message": f"Error:Error in getting organization name or id"}
        return JsonResponse(json_response, safe=False)     
    data["uuid"] = data['branch_loc'] + f"_{orgname}_{data['ciscohub']}.net" 
    data["orgid"] = orgid
    data["orgname"] = orgname        
    response = hub_config.get_ciscospoke_config(data)
    return JsonResponse(response, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Configure Device'],
    request_body=ConfigMicrotikSpokeSerializer,
    responses={200: ConfigMicrotikSpokeResponseSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_microtekspoke_config(request: HttpRequest):    
    data = json.loads(request.body) 
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_microtekspoke_config" }
                    )
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Authorization header missing or malformed'}, safe=False)

    token = auth_header.split(' ')[1]
    try:
        # Verify and decode the token
        decodedtoken = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])       

    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, safe=False)

    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, safe=False)
    orgname = decodedtoken.get("onboarding_org_name", False)
    orgid = decodedtoken.get("onboarding_org_id", False)
    if not orgname or not orgid:
        logger.error(f"Error: Get Configure Microtek HUB: Error in getting organization name ")
        json_response = {"message": f"Error:Error in getting organization name or id"}
        return JsonResponse(json_response, safe=False)     
    
    data["uuid"] = data['branch_loc'] + f"_{orgname}_microtek.net"
    data["orgid"] = orgid
    data["orgname"] = orgname
    response = onboarding.get_microtek_config(data)
    if "This Microtek Spoke is already Registered" in response[0]["message"]:           
        spokedetails = {"spokedevice_name": response[0]["spokedevice_name"],
                        "router_username": response[0]["router_username"],
                        "router_password": response[0]["router_password"],
                        "message": response[0]["message"],
                        "snmpcommunitystring": snmpcommunitystring
                        }        
        setass_task.apply_async(args=[response, "microtek"], countdown=60)
    else:
        spokedetails= {"message": response[0]["message"]}    
    return JsonResponse(spokedetails, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Configure Device'],
    request_body=ConfigRobustelSpokeSerializer,
    responses={200: ConfigRobustelSpokeResponseSerializer}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_robustelspoke_config(request: HttpRequest):
    global newuser
    data = json.loads(request.body) 
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_robustelspoke_config" }
                    )
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Authorization header missing or malformed'}, safe=False)

    token = auth_header.split(' ')[1]
    try:
        # Verify and decode the token
        decodedtoken = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])      

    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, safe=False)

    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, safe=False)
    orgname = decodedtoken.get("onboarding_org_name", False)
    orgid = decodedtoken.get("onboarding_org_id", False)
    if not orgname or not orgid:
        logger.error(f"Error: Get Configure Microtek HUB: Error in getting organization name ")
        json_response = {"message": f"Error:Error in getting organization name or id"}
        return JsonResponse(json_response, safe=False)     
    data["uuid"] = data['branch_loc'] + f"_{orgname}_robustel.net"
    data["orgid"] = orgid
    data["orgname"] = orgname   
    response = onboarding.get_robustel_config(data)
    if "This Robustel Spoke is already Registered" in response[0]["message"]:
        #spokeinfo = coll_tunnel_ip.find_one({"uuid":data["uuid"]})        
        spokedetails = {"spokedevice_name": response[0]["spokedevice_name"],                        
                        "message": response[0]["message"],
                        "snmpcommunitystring": snmpcommunitystring
                        }        
        setass_task.apply_async(args=[response, "robustel"], countdown=60)
    else:
        spokedetails= {"message": response[0]["message"]}
    
    return JsonResponse(spokedetails, safe=False)

@swagger_auto_schema(
    method='post',
    tags=['Onboarding Action']    
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def onboard_block(request: HttpRequest):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "onboard_block" }
                    )
    response = onboardblock.onboard_block(data)    
    return HttpResponse(response)

@swagger_auto_schema(
    method='post',
    tags=['Onboarding Action']    
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def onboard_unblock(request: HttpRequest):
    data = json.loads(request.body)   
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "onboard_unblock" }
                    )
    response = onboardblock.onboard_unblock(data)
    return HttpResponse(response)
      
@swagger_auto_schema(
    method='post',
    tags=['Onboarding Action']    
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def onboard_delete(request: HttpRequest):
    data = json.loads(request.body)
    # Capture the public IP from the request headers
    public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "onboard_delete" }
                    )
    onboardblock.onboard_delete(data)
    return HttpResponse

@swagger_auto_schema(
    method='post',
    tags=['Authentication']    
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "change_password" }
                    )
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

@swagger_auto_schema(
    method='post',
    tags=['Traffic Report Generate'],
    request_body=TrafficReportInfoSerializer,
    responses={200: "Report in PDF"}
)
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def traffic_report(request):
    try:
        data = json.loads(request.body)
        print(data)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "traffic_report" }
                    )
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        if "icmp" in data["intfcname"].lower():
            data["intfcname"] = 'ICMP Response time'
            data['filename'] = f"ping_report_{timestamp}.pdf"
            report_status = zabbix_ping_report.ping_report_gen(data)
        else:
            data['filename'] = f"traffic_report_{timestamp}.pdf"
            report_status = zabbix_gen_report.traffic_report_gen(data)        
        if not report_status["status"]:
            print("No relevant items found.")
            logger.error(f"Error: Get Traffic report: No relevant items found.")
            response = [{"message": report_status["message"]}]
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(response)
            response1["Access-Control-Expose-Headers"] = "X-Message"
            return response1
        if report_status["status"]:
            with open(data['filename'], "rb") as f:
                trafficdatapdf = f.read()                    
            os.system(f"rm -r {data['filename']}")            
            files_to_send = {
                data['filename']: trafficdatapdf
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
            logger.info(f"Traffic data generated successfully.{data['filename']}",
                    extra={ "be_api_endpoint": "traffic_report" }
                    )
            return response             
    except Exception as e:        
        logger.error(f"Error: Get Traffic report: {e}",
                    extra={ "be_api_endpoint": "traffic_report",
                           "exception": str(e)})
        response = [{"message": "Error Internal server problem."}]
    response1 = HttpResponse(content_type='text/plain')
    response1['X-Message'] = json.dumps(response)
    response1["Access-Control-Expose-Headers"] = "X-Message"
    return response1

#Admin Dashboard
@swagger_auto_schema(
    method='get',
    tags=['Home'],
    responses={200: "Home page info JSON"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def adminhomepage_info(request: HttpRequest):
    try:        
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}",
                    extra={ "be_api_endpoint": "admin_homepage_info" }
                    )
        response = {}        
        total_no_branches = 0
        #organization_id = str(request.GET.get('organization_id'))        
        cache_key = f"admin_home_page_info"
        home_page_details = cache.get(cache_key)
        if home_page_details:
            return JsonResponse(home_page_details, safe=False)
        with open(device_info_path, "r") as f:
            total_devices = json.load(f)
            f.close()
        org_list = []
        org_info = []
        for device in total_devices:
            organization_id = device["organization_id"]
            org_list.append({"organization_name": device["organization_name"],
                             "organization_id": device["organization_id"]})
                
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
            org_info.append({device["organization_name"]: {
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
                                })         
    except Exception as e:
        logger.error(f"Error: Admin Home Page info:{e}")   
    response = {"no_of_registered_organization":len(total_devices),
                    "list_of_organization": org_list,
                    "organization_info":org_info}            
    # Store in cache for 60 seconds
    cache.set(cache_key, response, timeout=60)
    return JsonResponse(response, safe=False)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def logfile_content(request):
    logfile_content = ["ReachLink is not configured yet"]
    log_file_path = "/var/log/reachlink/reach_request.log"

    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as file:
            logfile_content = file.readlines()

    logfile_content.reverse()
    return JsonResponse({'log': logfile_content})