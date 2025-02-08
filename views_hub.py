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
import logging
logger = logging.getLogger(__name__)
import os
import subprocess
import json
import ipaddress
import pymongo
from pymongo.server_api import ServerApi
import reachlinkst
import requests
import uuid
from datetime import datetime
from dateutil.relativedelta import relativedelta
from pyroute2 import IPRoute
ipr = IPRoute()
from netaddr import IPAddress
import psutil
import socket
import threading
import random
import router_configure
import microtek_configure
import time
import yaml
import string
import io
import zipfile
import base64
import re
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
coll_spoke_active = db_tunnel["spoke_active"]
coll_spoke_inactive = db_tunnel["spoke_inactive"]
coll_spoke_disconnect = db_tunnel["spoke_disconnect"]
coll_deleted_organization = db_tunnel["deleted_organization"]
coll_dialer_ip = db_tunnel["dialer_ip"]
coll_hub_info = db_tunnel["hub_info"]
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
routes_protocol_map = {
    -1: '',
    196:'static',
    0: 'unspecified (default)',
    1: 'redirect',
    2: 'kernel',
    3: 'boot/static',
    4: 'static',
    8: 'gated',
    9: 'ra',
    10: 'mrt',
    11: 'zebra',
    12: 'bird',
    13: 'dnrouted',
    14: 'xorp',
    15: 'ntk',
    16: 'dhcp',
    18: 'keepalived',
    42: 'babel',
    186: 'bgp',
    187: 'isis',
    188: 'ospf',
    189: 'rip',
    192: 'eigrp', 
}
#Function to test the tunnel is connected active
def check_tunnel_connection(Remote_tunnel_ip, vrf_name):
    try:
        
        command = (f"ping -I {vrf_name} -c 2  {Remote_tunnel_ip}")
        output = subprocess.check_output(command.split()).decode()
        
        return True          
      
    except subprocess.CalledProcessError:
        return False
    	
def authenticate_user(data):
    try:
        if "access_token" not in data:
            data_login = {
                    "email": data["username"],
                    "password": data["password"]
                 }
            # Send a POST request with the data
            login_response = requests.post(url+"auth/login", json=data_login)
            if login_response.status_code == 200:
            # Parse the JSON response
                loginjson_response = login_response.json()
                access_token = loginjson_response["data"]["access_token"]
            else:
                 return 'Invalid Login & password'
        else:
            access_token = data["access_token"]
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        service_response = requests.get(url+"services/", headers=headers)
        if service_response.status_code == 200:
            servicejson_response = service_response.json()
            services_info = servicejson_response["data"]["services"]
            subscription_status = False
            for service in services_info:
                if service["name"] == "link":
                    subscription_status = True
            if subscription_status:
                get_organization_name = requests.get(url+"org/", headers=headers)
                org_response = get_organization_name.json()
                organization_name = org_response["data"]["company_name"]
                subscription_response = requests.get(url+"subscription_transactions/current", headers=headers)
                subsjson_response = subscription_response.json()
                timestamp = int(subsjson_response["data"]["created_at"])
                # Convert Unix timestamp to datetime
                from_date = datetime.utcfromtimestamp(timestamp)
                # Add Duration to get to_date
                to_date = from_date + relativedelta(months=int(subsjson_response["data"]["duration"]))
                coll_registered_organization.insert_one({
                    "organization_id": subsjson_response["data"]["org_id"],
                    "regusers": [{"username":data["username"]}                                      
                                    ],
                    "subscription_from":from_date,
                    "subscription_to":to_date,                        
                        "total_users": subsjson_response["data"]["users"],
                        "remaining_users": subsjson_response["data"]["users"],
                        "registered_devices":[],
                        "organization_name": organization_name                                           
                })
                return True
            else:
                    return 'Not Subscribed for Reach WAN'
        else:
                return 'Not Subscribed for any services'
    except:
        return 'Internal Server Error'

def get_organization_id(data):
    try:
        if "access_token" not in data:
            data_login = {
                    "email": data["username"],
                    "password": data['password']
                 }
            # Send a POST request with the data
            login_response = requests.post(url+"auth/login", json=data_login)
            if login_response.status_code == 200:
            # Parse the JSON response
                loginjson_response = login_response.json()
                access_token = loginjson_response["data"]["access_token"]
            else:
                return False
        else:
            access_token = data["access_token"]
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        user_response = requests.get(url+"users/me", headers=headers)
        if user_response.status_code == 200:
            userjson_response = user_response.json()
            user_info = userjson_response["data"]["user"]
            if user_info["status"] == "ACTIVE":
                return user_info["org_id"]
            else:
                return False
        else:
            return False        
    except:
        return False
    
def generate_device_name(length,organization_info):
    spokedevice_name =  "Spoke"+ str(length)+"-"+organization_info["organization_name"]
    for device in organization_info["registered_devices"]:
        if device.get("spokedevice_name", "") == spokedevice_name:
            return generate_device_name(length+1, organization_info)
    print(spokedevice_name)
    return spokedevice_name

#Generation of tunnel IP
def tunnel_ip_generation():
    random_no = random.randint(3,250)
    tunnel_ip = gretunnelnetworkip + str(random_no) + "/24"
    for tun_ip in coll_tunnel_ip.find({},{"_id":0}):
        if tunnel_ip == tun_ip["tunnel_ip"]:
            return tunnel_ip_generation()
    return tunnel_ip

#Function to get tunnel IP from cloud database
def get_tunnel_ip(data, spokedevice_name):
    tunnelip = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
    if tunnelip:
        return tunnelip["tunnel_ip"]
    else:           
        tunnel_ip = tunnel_ip_generation()
        coll_tunnel_ip.insert_one({"public_ip": data.get('public_ip', "None"), 
                               "tunnel_ip": tunnel_ip,
                               "branch_location": data["branch_location"],
                               "subnet": [],
                               "vrf":"vrf1",                                                             
                               "uuid": data["uuid"],
                               "router_username": data.get("device_username", "None"),
                               "router_password": data.get("device_password", "None"),
                               "spokedevice_name": spokedevice_name,
                               "hub_ip": data.get("dialer_ip", "")
                              })    
    return tunnel_ip


def check_user_renewed(data, organization_id):
    current_datetime = datetime.now()
    try:
        details = coll_registered_organization.find_one({"organization_id":organization_id})
        if details:            
            if details["remaining_users"] > 0 and current_datetime < details["subscription_to"] :                
                registered_devices_info = details["registered_devices"]
                expiry_date_original = str(details["subscription_to"]).split(" ")[0]
                for device in registered_devices_info:
                    if device['uuid'] == data["uuid"]:                            
                        response =[{ "message": 'This device is already Registered', "expiry_date": expiry_date_original, "spokedevice_name":device["spokedevice_name"], "gretunnel_ip":device["gretunnel_ip"], "remote_ip":openvpnhubip, "hub_gretunnel_endpoint":hub_tunnel_endpoint }]
                        return response 
                length = len(registered_devices_info)+1
                spokedevice_name =  generate_device_name(length, details)
                gretunnel_ip =  get_tunnel_ip(data, spokedevice_name)                  
                new_device_info = {
                                    
                                    "uuid": data["uuid"],
                                    "spokedevice_name":  spokedevice_name,
                                    "gretunnel_ip": gretunnel_ip,
                                    "hub_ip": data.get("dialer_ip", "")                      
                                   }
                registered_devices_info.append(new_device_info)  
                query = {"username": data["user_name"] }
                update_data = {"$set": {"remaining_users":details['remaining_users']-1, 
                                        "registered_devices": registered_devices_info                                                                              
                                        }
                                       }
                coll_registered_organization.update_many(query, update_data)
                response = [{"message":"Successfully Registered", "expiry_date": expiry_date_original, "spokedevice_name":spokedevice_name, "gretunnel_ip":gretunnel_ip, "remote_ip":openvpnhubip, "hub_gretunnel_endpoint":hub_tunnel_endpoint}]
                return response
            else:
                response = [{"message":"Your plan reached the limit. Pl upgrade it", "expiry_date":dummy_expiry_date }]
                return response
    except:
        response = [{"message":"Internal Server Error Try again pl", "expiry_date":dummy_expiry_date }]
        return response
        

def check_subscription_renewed(data, organization_id):
    try:
        if "access_token" not in data:
            data_login = {
                    "email": data["username"],
                    "password": data["password"]
                 }
            # Send a POST request with the data
            login_response = requests.post(url+"auth/login", json=data_login)
            if login_response.status_code == 200:
            # Parse the JSON response
                loginjson_response = login_response.json()
                access_token = loginjson_response["data"]["access_token"]
            else:
                return "Invalid login & password "
        else:
            access_token = data["access_token"]
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        service_response = requests.get(url+"services/", headers=headers)
        if service_response.status_code == 200:
            servicejson_response = service_response.json()
            services_info = servicejson_response["data"]["services"]
            subscription_status = False
            for service in services_info:
                if service["name"] == "link":
                    subscription_status = True
            if subscription_status:
                subscription_response = requests.get(url+"subscription_transactions/current", headers=headers)
                subsjson_response = subscription_response.json()
                timestamp = int(subsjson_response["data"]["created_at"])
                # Convert Unix timestamp to datetime
                from_date = datetime.utcfromtimestamp(timestamp)
                # Add Duration to get to_date
                to_date = from_date + relativedelta(months=int(subsjson_response["data"]["duration"]))
                details = coll_registered_organization.find_one({"organization_id":organization_id})
                if details:
                    if details["subscription_to"] != to_date:
                        query = {"organization_id": organization_id }
                        update_data = {"$set": 
                                       {"subscription_from": from_date, 
                                        "subscription_to": to_date,
                                        "total_users": subsjson_response["data"]["users"]                                        
                                        }
                                       }
                        coll_registered_organization.update_many(query, update_data)
                        return "Subscribtion Renewed"
            else:
                return " Not subscribed for ReachLink"
        else:
            return "not subscribed for any services"          
    except:
        return "Internal Server Error"


           
def check_user(data):
    current_datetime = datetime.now()
    global newuser    
    try:
        organization_id = get_organization_id(data)
        print("orgid", organization_id)  
        if organization_id:            
            details = coll_registered_organization.find_one({"organization_id":organization_id})
            if details:
                newuser = False                                                    
                if details["remaining_users"] > 0 and current_datetime < details["subscription_to"]:
                    registered_devices_info = details["registered_devices"]
                    expiry_date_original = str(details["subscription_to"]).split(" ")[0]                    
                    for device in registered_devices_info:
                        if device['uuid'] == data["uuid"]:                            
                            response =[{ "message": 'This device is already Registered', "expiry_date": expiry_date_original, "spokedevice_name":device["spokedevice_name"], "gretunnel_ip":device["gretunnel_ip"], "remote_ip":openvpnhubip, "hub_gretunnel_endpoint":hub_tunnel_endpoint }]
                            return response 
                    length = len(registered_devices_info)+1
                    spokedevice_name =  generate_device_name(length, details)    
                    gretunnel_ip =  get_tunnel_ip(data, spokedevice_name)               
                    new_device_info = {
                                    
                                    "uuid": data["uuid"],
                                    "spokedevice_name":  spokedevice_name,
                                    "gretunnel_ip": gretunnel_ip,
                                    "hub_ip": data.get("dialer_ip", "")

                                   }
                    registered_devices_info.append(new_device_info)  
                    registered_users = details["regusers"]
                    user_available = False
                    for users in registered_users:
                        if users["username"] == data["username"]:
                            user_available = True
                    if user_available != True:
                        new_user_info = {
                            "username": data["username"]                            
                        }
                        registered_users.append(new_user_info)       
                    query = {"organization_id": organization_id}
                    update_data = {"$set": {"remaining_users":details['remaining_users']-1, 
                                        "registered_devices": registered_devices_info, 
                                        "regusers": registered_users                                       
                                        }
                                       }
                    coll_registered_organization.update_many(query, update_data)
                    response = [{"message":"Successfully Registered", "expiry_date": expiry_date_original, "spokedevice_name":spokedevice_name, "gretunnel_ip":gretunnel_ip, "remote_ip":openvpnhubip, "hub_gretunnel_endpoint":hub_tunnel_endpoint}]
                    return response
                else:
                    userStatus = check_subscription_renewed(data, organization_id)
                    if userStatus == 'Subscribtion Renewed':
                        response = check_user_renewed(data, organization_id)
                        return response
                    else:
                        response = [{"message":"Your plan reached the limit. Pl upgrade it","expiry_date":dummy_expiry_date }]
                        return response
            else:
                newuser = True
                response = [{"message":"New user", "expiry_date":dummy_expiry_date }]
                return response
        else:
            newuser = False
            response =[{"message":"Not Registered", "expiry_date":dummy_expiry_date }]
            return response
    except Exception as e:
        print("Error:", e)
        response =[{"message":"Internal Server Error", "expiry_date":dummy_expiry_date }]
        return response
  

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

def setass(response):    
    try:
        connected_spoke =[]
#        time.sleep(120)   
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
#                    date = data[7].split(" ")[0]
 #                   time = data[7].split(" ")[1]
                    collection = {"Tunnel_ip":data[3], "Public_ip":data[2].split(":")[0], "spokedevice_name": data[1]}
                    connected_spoke.append(collection) 
        for spoke in connected_spoke:
            if spoke["spokedevice_name"] == newspokedevicename:
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
            setass(response)
        else:
            print(f"GRE tunnel created successfully for this {newspokedevicename}.")
    except Exception as e:
        print(f"set ass execption:{e}")

@csrf_exempt
def login(request: HttpRequest):
    data = json.loads(request.body)
    print(data)
    global newuser
    try:
        response = check_user(data)
        print(response)
        print(newuser)
        if newuser:
            userStatus = authenticate_user(data)
            print(userStatus)
            if userStatus:
                response = check_user(data)
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
            background_thread = threading.Thread(target=setass, args=(response,))
            background_thread.start() 
        else:
            response1 = HttpResponse(content_type='text/plain')
            response1['X-Message'] = json.dumps(response)
        
    except:
        response = [{"message": "Internal Server Error", "expiry_date": dummy_expiry_date}]
        response1 = HttpResponse(content_type='text/plain')
        response1['X-Message'] = json.dumps(response)
    return response1

@csrf_exempt
def set_ass(request: HttpRequest):
    try:
        print(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"public_ip:{public_ip}")
        current_datetime = datetime.now()
        data = json.loads(request.body)
        data["public_ip"] = public_ip
        if "domain_name" in data:
            data["uuid"] = data["domain_name"]
        print(data)        
        response = [{"message":"Successfully added"}] 
        tunnel_ip = data["tunnel_ip"].split("/")[0]
        device_block = True
        for regDevice in coll_registered_organization.find({},{"_id":0}):
            for deviceinfo in regDevice["registered_devices"]:
                if deviceinfo["uuid"] == data["uuid"] and current_datetime < regDevice["subscription_to"]:
                    print(deviceinfo)
                    device_block = False  

        for device in coll_spoke_disconnect.find({},{"_id":0}):
            if device["uuid"] == data["uuid"]:
                device_block = True 
        print(device_block)
        if not(device_block):
            if ipaddress.ip_address(tunnel_ip) in ipaddress.ip_network(vrf1_ip):
                try:
                    command = f"sudo ip neighbor replace {tunnel_ip} lladdr {data['public_ip']} dev Reach_link1"
#                    subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                    total_branches = []
                    query = {"uuid": data["uuid"]}
                    update_data = {"$set": {"public_ip":public_ip                        
                                            }
                                  }
                    coll_tunnel_ip.update_many(query, update_data)
                    
                    os.system("systemctl stop reachlink_test") 
                    with open("/root/reachlink/total_branches.json", "r") as f:
                        totalbranches = json.load(f)
                        f.close()
                    new_device = True
                    for dev in totalbranches:
                        if dev["uuid"] == data["uuid"]:
                            new_device = False
                            dev["status"] = "inactive"                    
                    if new_device:
                        data["status"] = "inactive"
                        totalbranches.append(data)
                    with open("/root/reachlink/total_branches.json", "w") as f:
                            json.dump(totalbranches, f)
                            f.close()
                    os.system("systemctl start reachlink_test")       
                    data1 = coll_tunnel_ip.find_one({"uuid": data["uuid"]})
                    for i in data1["subnet"]:
                        try:
                            command = f"sudo ip route replace {i} via {tunnel_ip}"
                            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                            #command = f"ip route replace {i} dev vrf1"
                            #subprocess.run(command, shell=True, check=True, capture_output=True, text=True)                            
                        except Exception as e:
                            print(f"Error occured while adding route for {i}:",e)
                except Exception as e:                    
                    print(f"Error occured while adding {tunnel_ip} as neighbor:", e)
                    response = [{"message":"Device already added"}]  
    except Exception as e:
        print(e)
        response = [{"message":f"Device already added"}]         
    logger.debug(f'Received request: {request.method} {request.path}')
    return HttpResponse(response)

@csrf_exempt
def deactivate(request: HttpRequest):
    try:
        data = json.loads(request.body)   
        print(data)
        response = {"message":f"Successfully disconnected: {data['tunnel_ip']}"}
        tunnel_ip = data["tunnel_ip"].split("/")[0]
        if ipaddress.ip_address(tunnel_ip) in ipaddress.ip_network(vrf1_ip):
            try:
                command = f"sudo ip neighbor del {tunnel_ip} lladdr {data['public_ip']} dev Reach_link1"
                print(command)
                subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
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
                for i in data["subnet"]:
                   try:
                        command = f"sudo ip route del {i} via {tunnel_ip}"
                        print(command)
                        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                        
                        #command = f"ip route del {i} dev vrf1"
                       # subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                   except Exception as e:
                       print(f"Error occured while deleting route for {i}:",e)
            except:
                print(f"Error occured while deleting {tunnel_ip} as neighbor:", e)
                response = {"message":f"Device already disconnected: {data['tunnel_ip']}"} 
          
        coll_spoke_disconnect.insert_one({"public_ip": data["public_ip"], 
                                      "tunnel_ip": data["tunnel_ip"],
                                      "uuid":data["uuid"],                                      
                                      "subnet": data["subnet"]
                                     
                                    })
        print("coll_deactivate")
        dd = coll_spoke_disconnect.find({})
        for d in dd:
            print(d)
    except Exception as e:
        print(e)
        response = {"message":f"Error: {e}"}  
    logger.debug(f'Received request: {request.method} {request.path}')                  
    return JsonResponse(response, safe=False)

@csrf_exempt
def activate(request: HttpRequest):
    try:       
        data = json.loads(request.body)        
        print(data)
        response = {"message":f"Successfully activating...: {data['tunnel_ip']}"}
        tunnel_ip = data["tunnel_ip"].split("/")[0]
    #    device_block = False
#        for regDevice in coll_registered_organization.find({},{"_id":0}):
#            for deviceinfo in regDevice["registered_devices"]:
 #              if deviceinfo["uuid"] == data["uuid"]:
  #                  device_block = False
   #     print(device_block)
        if True:
            if ipaddress.ip_address(tunnel_ip) in ipaddress.ip_network(vrf1_ip):
                try:
                    command = f"sudo ip neighbor replace {tunnel_ip} lladdr {data['public_ip']} dev Reach_link1"
                    subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                    os.system("systemctl stop reachlink_test") 
                    with open("/root/reachlink/total_branches.json", "r") as f:
                        totalbranches = json.load(f)
                        f.close()
                    for dev in totalbranches:
                        if dev["uuid"] == data["uuid"]:
                            dev["status"] = "active"
                    with open("/root/reachlink/total_branches.json", "w") as f:
                        json.dump(totalbranches, f)
                        f.close()
                    os.system("systemctl start reachlink_test") 
                    for i in data["subnet"]:
                        try:
                            command = f"sudo ip route replace {i} via {tunnel_ip}"
                            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                            #command = f"ip route replace {i} dev vrf1"
                            #subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                        except Exception as e:
                            print(f"Error occured while adding route for {i}:", e)
                except Exception as e:
                    print(f"Error occured while adding {tunnel_ip} as neighbor:", e)
                    response = {"message":f"Device already activated: {data['tunnel_ip']}"}
                coll_spoke_disconnect.delete_many({"uuid": data["uuid"]})
    except Exception as e:
        print(e)
        response = {"message":f"Error: {e}"}
    logger.debug(f'Received request: {request.method} {request.path}')
    return JsonResponse(response, safe=False)
    
    
@csrf_exempt
def totalbranches(request: HttpRequest):    
    data = []
    print(f"headers:{request.headers}")
    print(f"body:{request.body.decode('utf-8')}")
    with open("/root/reachlink/total_branches.json", "r") as f:
        data = json.load(f)
        f.close()
    logger.debug(f'Received request: {request.method} {request.path}')
    return JsonResponse(data, safe=False)

def check_available_active():
    if (reachlinkst.resource_notify_active):
        global resource_active 
        resource_active = False
        return True
    else:
        return check_available_active()

@csrf_exempt
def activebranches(request: HttpRequest):
    data = []
    if (check_available_active()):
        with open("/root/reachlink/active_branches.json", "r") as f:
            data = json.load(f)
            f.close()
        global resource_active 
        resource_active = True
    logger.debug(f'Received request: {request.method} {request.path}')
    return JsonResponse(data, safe=False)

def check_available_inactive():
    if (reachlinkst.resource_notify_inactive):
        global resource_inactive
        resource_inactive = False
        return True
    else:
        return check_available_inactive()

@csrf_exempt
def inactivebranches(request: HttpRequest):
    data = []
    if (check_available_inactive()):
        with open("/root/reachlink/inactive_branches.json", "r") as f:
                data = json.load(f)
                f.close()
        global resource_inactive
        resource_inactive = True
    logger.debug(f'Received request: {request.method} {request.path}')
    return JsonResponse(data, safe=False)

def ping_test(data):
  try:
    command = (f"ping -c 5  {data['subnet']}")
    output = subprocess.check_output(command.split()).decode()
    lines = output.strip().split("\n")
    # Extract the round-trip time from the last line of output
    last_line = lines[-1].strip()
    rtt = last_line.split()[3]
    rtt_avg = rtt.split("/")[1]
              
  except subprocess.CalledProcessError:
    rtt_avg = -1
        
  response = [{"avg_rtt":rtt_avg}]	
  return response

def get_ip_addresses(ip_address, netmask):
    # Create an IPv4Network object representing the subnet
    subnet = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    # Extract and return the list of IP addresses (excluding network and broadcast addresses)
    return [str(ip) for ip in subnet.hosts()]

def prefix_length_to_netmask(prefix_length):
    """
    Convert prefix length to netmask.

    Args:
    prefix_length (int): The prefix length.

    Returns:
    str: The netmask in dotted decimal notation.
    """
    netmask = (0xffffffff << (32 - prefix_length)) & 0xffffffff
    return str(ipaddress.IPv4Address(netmask))


@csrf_exempt 
def diagnostics(request: HttpRequest):
  data = json.loads(request.body)  
  ip_addresses = [data["subnet"].split("/")[0]]
#  prefix_length =int(data["subnet"].split("/")[1])
 # netmask = prefix_length_to_netmask(prefix_length)
  #ip_addresses = get_ip_addresses(ip_address, netmask)
  for ip in ip_addresses:    
    try:
        command = (f"ping -c 5  {ip}")
        output = subprocess.check_output(command.split()).decode()
        lines = output.strip().split("\n")
        # Extract the round-trip time from the last line of output
        last_line = lines[-1].strip()
        rtt = last_line.split()[3]
        rtt_avg = rtt.split("/")[1]
        response = {"message": f"Subnet {data['subnet']} Reachable with RTT: {rtt_avg}ms"}
       
        return JsonResponse(response, safe=False)
    except subprocess.CalledProcessError:
        rtt_avg = -1
    response ={"message": f"Error: Subnet {data['subnet']} not Reachable"}
  logger.debug(f'Received request: {request.method} {request.path}')
  return JsonResponse(response, safe=False)

def background_addsubnet(data):
    if ".net" not in data["uuid"]:
            subnets = data["subnet_info"]
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}
            route_add = {"subnet_info": subnets}
            json_data = json.dumps(route_add)
            try:
                response = requests.post(url + "addroute", data=json_data, headers=headers)  # Timeout set to 5 seconds
                response.raise_for_status()
                print(response)
                # response = requests.post(url+"addroute", data=json_data, headers=headers)
                # Check the response
                if response.status_code == 200:           
                    json_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    json_response = json.loads(json_response)
                    print(json_response)
                    response = {"message":json_response["message"]}              
                else:
                    response = {"message":"Error while sending route info to spoke"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = {"message":"Error:Tunnel disconnected in the middle. So pl try again"}   
    elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            status = microtek_configure.addroute(data)
            response = {"message":status}
    elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            status = router_configure.addroute(data)
            response = {"message":status}

def configurepbr_spoke(data):
    try:    
#        data = json.loads(data1)             
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "add_ip_rules", data=json_data, headers=headers)  # Timeout set to 5 seconds                               
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
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            status = microtek_configure.configurepbr(data)
            response = {"message":status}
        elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #status = router_configure.addroute(data)
            response = {"message":"Dummy"}
    except Exception as e:
        response = {"message": f"Error: {e}"}
    print(response)


@csrf_exempt
def addsubnet1(request: HttpRequest):
    try:
        data = json.loads(request.body)         
        subnets = data["subnet_info"]
        tunnel_ip = data["tunnel_ip"].split("/")[0] 
        tunnel_info = coll_tunnel_ip.find_one({"tunnel_ip": data['tunnel_ip']}) 
        past_subnets = tunnel_info["subnet"] 
        subnet_na = []          
        for subnet in subnets:
            if subnet["subnet"].split(".")[0] == "127" or subnet["subnet"].split(".")[0] == "169" or int(subnet["subnet"].split(".")[0]) > 223:
                subnet_na.append(subnet["subnet"])
            else:
                try:
                    command = "sudo ip route add " + subnet["subnet"] + " via " + tunnel_ip          
                    subprocess.run(command, shell=True, check=True, capture_output=True, text=True) 
                    past_subnets.append(subnet["subnet"]) 
                    if subnet["subnet"].split(".")[0] != "10":
                        if subnet["subnet"].split(".")[0] == "172":
                            if 15 < int(subnet["subnet"].split(".")[1]) < 32:
                                private_ip = True
                            else:
                                private_ip = False
                        elif subnet["subnet"].split(".")[0] == "192":
                            if subnet["subnet"].split(".")[1] == "168":
                                private_ip = True
                            else:
                                private_ip = False
                        elif int(subnet["subnet"].split(".")[0]) > 223: 
                            private_ip = True
                        else:
                            private_ip = False
                    else:
                        private_ip = True
                    if not private_ip:
                        pbrresponse = configurepbr_spoke({"tunnel_ip": data["tunnel_ip"],
                                            "uuid":data["uuid"],
                                            "realip_subnet": subnet["subnet"]
                                            })
                        print(pbrresponse)
                    #print(past_subnets)
                except Exception as e:
                    subnet_na.append(subnet["subnet"])
        past_subnets = list(set(past_subnets))         
        past_subnets = [item for item in past_subnets if item != "None"]      
        query = {"tunnel_ip": data["tunnel_ip"] }
        update_data = {"$set": {"subnet":past_subnets 
                                    }
                          }
        coll_tunnel_ip.update_many(query, update_data) 
        #total_branches = []
        #for device in coll_tunnel_ip.find({},{"_id":0}):
          #  total_branches.append(device)
        #with open("/root/reachlink/total_branches.json", "w") as f:
        #    json.dump(total_branches, f)
        #    f.close()

        os.system("systemctl stop reachlink_test") 
        with open("/root/reachlink/total_branches.json", "r") as f:
            totalbranches = json.load(f)
            f.close()
        for dev in totalbranches:
            if dev["uuid"] == data["uuid"]:
                dev["subnet"] = past_subnets
        with open("/root/reachlink/total_branches.json", "w") as f:
            json.dump(totalbranches, f)
            f.close() 
        os.system("systemctl start reachlink_test")        
        past_subnets = list(set(past_subnets))
        background_thread = threading.Thread(target=background_addsubnet, args=(data,))
        background_thread.start() 
        if len(subnet_na) == 0: 
            response = {"message":f"Successfully added {len(data['subnet_info'])} subnet(s)."}    
        else:
            added_subnet = len(data['subnet_info']) - len(subnet_na)
            if added_subnet == 0:
                response = {"message":f"{subnet_na} is already routed."}
            else:
                response = {"message":f"Successfully added {added_subnet} subnet(s). {subnet_na} is already routed."}
    except Exception as e:    
        response = {"message": f"Error in adding route, pl try again {e}" }
    logger.debug(f'Received request: {request.method} {request.path}')   
    print(response) 
    return JsonResponse(response, safe=False) 

def background_deletesubnet(data):
    if ".net" not in data["uuid"]:
            subnets = data["subnet_info"]
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}
            route_add = {"subnet_info": subnets}
            json_data = json.dumps(route_add)
            try:
                response = requests.post(url + "delroute", data=json_data, headers=headers)  # Timeout set to 5 seconds
                response.raise_for_status()
                print(response) 
            #response = requests.post(url+"delroute", data=json_data, headers=headers)
            # Check the response
                if response.status_code == 200:           
                    json_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    json_response = json.loads(json_response)
                    print(json_response)
                    response = {"message":json_response["message"]}                
                else:
                    response = {"message": "Error while adding subnet in spoke side. Pl try again"}
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response ={"message": "Tunnel disconnected in the middle. So, pl try again"} 
    else:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            status = router_configure.delroute(data)
            response = {"message":status}

@csrf_exempt
def delsubnet(request: HttpRequest):
    try:
        data = json.loads(request.body)   
        response = {"message":f"Successfully deleted {len(data['subnet_info'])} subnet(s)"}  
        subnets = data["subnet_info"]
        tunnel_ip = data["tunnel_ip"].split("/")[0] 
        tunnel_info = coll_tunnel_ip.find_one({"tunnel_ip": data['tunnel_ip']}) 
        past_subnets = tunnel_info["subnet"]            
        for subnet in subnets:
            command = "sudo ip route del " + subnet["subnet"] + " via " + tunnel_ip          
            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)   
            past_subnets.remove(subnet["subnet"])
        past_subnets = list(set(past_subnets))        
        query = {"tunnel_ip": data["tunnel_ip"] }
        update_data = {"$set": {"subnet":past_subnets 
                                    }
                          }
        coll_tunnel_ip.update_many(query, update_data) 
        #total_branches = []
        #for device in coll_tunnel_ip.find({},{"_id":0}):
         #   total_branches.append(device)
        #with open("/root/reachlink/total_branches.json", "w") as f:
         #  json.dump(total_branches, f)
         #  f.close()
        os.system("systemctl stop reachlink_test") 
        with open("/root/reachlink/total_branches.json", "r") as f:
            totalbranches = json.load(f)
            f.close()
        for dev in totalbranches:
            if dev["uuid"] == data["uuid"]:
                dev["subnet"] = past_subnets
        with open("/root/reachlink/total_branches.json", "w") as f:
            json.dump(totalbranches, f)
            f.close() 
        os.system("systemctl start reachlink_test")        
        background_thread = threading.Thread(target=background_deletesubnet, args=(data,))
        background_thread.start()       
       
    except Exception as e:
        response = {"message":f"Error: {e}"}                   
    logger.debug(f'Received request: {request.method} {request.path}')
    return JsonResponse(response, safe=False)


def get_routing_table_ubuntu(request):
    routing_table = []
    try:        
        ipr = IPRoute()
        routes = ipr.get_routes(family=socket.AF_INET)
        for route in routes:            
            if route['type'] == 1:
                destination = "0.0.0.0"
                metric = 0
                gateway = "-"
                protocol = int(route['proto'])
                multipath = 0
                dst_len = route['dst_len']
                for attr in route['attrs']:
                    if attr[0] == 'RTA_OIF':
                        intfc_name = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                        if str(table) != "Main Routing Table":
                            command = (f"ip link show {intfc_name}")
                            output = subprocess.check_output(command.split()).decode()
                            lines = output.strip().split("\n")
                            try:
                                table = lines[0].split("master")[1].split(" ")[1]
                            except IndexError:
                                table = table
                    if attr[0] == 'RTA_GATEWAY':
                        gateway = attr[1]
                    if attr[0] == 'RTA_PRIORITY':
                        metric = attr[1]
                    if attr[0] == 'RTA_DST':
                        destination = attr[1]
                    if attr[0] == 'RTA_TABLE':
                        if attr[1] == 254:
                            table = "Main Routing Table"
                        else:
                            table = attr[1]                            
                    if attr[0] == 'RTA_MULTIPATH':
                        for elem in attr[1]:
                            intfc_name = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                            for attr2 in elem['attrs']:
                                if attr2[0] == 'RTA_GATEWAY':
                                    gateway = attr2[1] 
                                    multipath = 1                                    
                                    if str(intfc_name) == "Reach_link1":
                                        intfc_name = "Overlay Tunnel"
                                    if str(intfc_name) == "tun0":
                                        intfc_name = "Base Tunnel"
                                    routing_table.append({"outgoing_interface_name":str(intfc_name),
                                                    "gateway":str(gateway),
                                                    "destination":str(destination)+"/"+str(dst_len),
                                                    "metric":int(metric),
                                                    "protocol":routes_protocol_map.get(protocol, "unknown"),
                                                    "table_id": table
                                                    })
                if multipath == 0:      
                    if str(intfc_name) == "Reach_link1":
                        intfc_name = "Overlay Tunnel"
                    if str(intfc_name) == "tun0":
                        intfc_name = "Base Tunnel"   
                    routing_table.append({"outgoing_interface_name":str(intfc_name),
                                  "gateway":str(gateway),
                                  "destination":str(destination)+"/"+str(dst_len),
                                  "metric":int(metric),
                                  "protocol":routes_protocol_map.get(protocol, "unknown"),
                                  "table_id": table
                                })     
        
    except Exception as e:
        print(e)
    return JsonResponse(routing_table, safe=False)

@csrf_exempt
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
            response = []
            ipr = IPRoute()
            routes = ipr.get_routes(family=socket.AF_INET)
            for route in routes:            
                if route['type'] == 1:
                    destination = "0.0.0.0"
                    metric = 0
                    gateway = "-"
                    protocol = int(route['proto'])
                    multipath = 0
                    dst_len = route['dst_len']
                    for attr in route['attrs']:
                        if attr[0] == 'RTA_OIF':
                            intfc_name = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                            if str(table) != "Main Routing Table":
                                command = (f"ip link show {intfc_name}")
                                output = subprocess.check_output(command.split()).decode()
                                lines = output.strip().split("\n")
                                try:
                                    table = lines[0].split("master")[1].split(" ")[1]
                                except IndexError:
                                    table = table
                        if attr[0] == 'RTA_GATEWAY':
                            gateway = attr[1]
                        if attr[0] == 'RTA_PRIORITY':
                            metric = attr[1]
                        if attr[0] == 'RTA_DST':
                            destination = attr[1]
                        if attr[0] == 'RTA_TABLE':
                            if attr[1] == 254:
                                table = "Main Routing Table"
                            else:
                                table = attr[1]                            
                        if attr[0] == 'RTA_MULTIPATH':
                            for elem in attr[1]:
                                intfc_name = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                                for attr2 in elem['attrs']:
                                    if attr2[0] == 'RTA_GATEWAY':
                                        gateway = attr2[1] 
                                        multipath = 1                                    
                                        if str(intfc_name) == "Reach_link1":
                                            intfc_name = "Overlay Tunnel"
                                        if str(intfc_name) == "tun0":
                                            intfc_name = "Base Tunnel"
                                        response.append({"outgoing_interface_name":str(intfc_name),
                                                    "gateway":str(gateway),
                                                    "destination":str(destination)+"/"+str(dst_len),
                                                    "metric":int(metric),
                                                    "protocol":routes_protocol_map.get(protocol, "unknown"),
                                                    "table_id": table
                                                    })
                    if multipath == 0:      
                        if str(intfc_name) == "Reach_link1":
                            intfc_name = "Overlay Tunnel"
                        if str(intfc_name) == "tun0":
                            intfc_name = "Base Tunnel"   
                        response.append({"outgoing_interface_name":str(intfc_name),
                                  "gateway":str(gateway),
                                  "destination":str(destination)+"/"+str(dst_len),
                                  "metric":int(metric),
                                  "protocol":routes_protocol_map.get(protocol, "unknown"),
                                  "table_id": table
                                })     
        
    except Exception as e:
        print(e)
        response = []
    return JsonResponse(response, safe=False)

@csrf_exempt
def ping_spoke(request: HttpRequest):  
    try: 

        data = json.loads(request.body) 
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


@csrf_exempt
def autofix(request: HttpRequest):  
    try:       
        data = json.loads(request.body)        
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


    
def deactivate_spoke(data):
    try:     
        print(data)
        tunnel_ip = data["tunnel_ip"].split("/")[0]
        if ipaddress.ip_address(tunnel_ip) in ipaddress.ip_network(vrf1_ip):
            try:
                command = f"sudo ip neighbor del {tunnel_ip} lladdr {data['public_ip']} dev Reach_link1"
                subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                for i in data["subnet"]:
                   try:
                        command = f"sudo ip route del {i} via {tunnel_ip}"
                        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)                 

                        #command = f"ip route del {i} dev vrf1"
                       # subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                   except Exception as e:
                       print(f"Error occured while deleting route for {i}:{e}")


            except:
                print(f"Error occured while deleting {tunnel_ip} as neighbor:{e}")
                response = [{"message":"Device already disconnected"}]    
        coll_spoke_disconnect.insert_one({"public_ip": data["public_ip"], 
                                      "tunnel_ip": data["tunnel_ip"],
                                      "branch_location": data["branch_location"],
                                      "subnet": data["subnet"],
                                     "vrf": data["vrf"],
                                     "hub_ip": data.get("dialer_ip", "")
                                    })
    except Exception as e:
        print(e)
        response = [{"message":"Device already disconnected"}]                    
    return 

@csrf_exempt
def onboard_block(request: HttpRequest):
    data = json.loads(request.body)
    response = [{"message": "Organization spokes disconnected successfully"}]
    with open("/root/reachlink/total_branches.json", "r") as f:
       total_branches = json.load(f)
       f.close()
    try:
        details = coll_registered_organization.find_one({"organization_id":data['organization_id']})
        if details:
                registered_devices_info = details["registered_devices"]                                     
                for device in registered_devices_info:                                       
                    spoke_details = coll_tunnel_ip.find_one({"uuid":device["uuid"]})
                    if spoke_details is not None:
                        deactivate_spoke(spoke_details)
                        total_branches = [item for item in total_branches if item.get("tunnel_ip") != spoke_details["tunnel_ip"]]
        with open("/root/reachlink/total_branches.json", "w") as f:
            json.dump(total_branches, f)
            f.close()

    except Exception as e:
        response = [{"message": f"Error getting while disconnection pl try again:{e}"}]
    logger.debug(f'Received request: {request.method} {request.path}')
    return HttpResponse(response)

def activate_spoke(data):
    try:       
        
        response = [{"message":"Successfully connected"}] 
        tunnel_ip = data["tunnel_ip"].split("/")[0]

        if True:
            if ipaddress.ip_address(tunnel_ip) in ipaddress.ip_network(vrf1_ip):
                try:
                    command = f"sudo ip neighbor replace {tunnel_ip} lladdr {data['public_ip']} dev Reach_link1"
                    subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                    for i in data["subnet"]:
                        try:
                            command = f"sudo ip route replace {i} via {tunnel_ip}"
                            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                            #command = f"ip route replace {i} dev vrf1"
                            #subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                        except Exception as e:
                            print(f"Error occured while adding route for {i}:", e)
                except Exception as e:
                    print(f"Error occured while adding {tunnel_ip} as neighbor:", e)
                    response = [{"message":"Device already added"}]    
                coll_spoke_disconnect.delete_many({"public_ip": data["public_ip"], 
                                       "tunnel_ip": data["tunnel_ip"],
                                       "branch_location": data["branch_location"],
                                       "subnet": data["subnet"],
                                        "vrf": data["vrf"],
                                        "hub_ip": data.get("dialer_ip", "")
                                       })
    except Exception as e:
        print(e)
        response = [{"message":"Device already added"}]
    return 
@csrf_exempt
def onboard_unblock(request: HttpRequest):
    data = json.loads(request.body)    
    response = [{"message": "Organization spokes activated successfully"}]
    with open("/root/reachlink/total_branches.json", "r") as f:
       total_branches = json.load(f)
       f.close()
    print(total_branches)
    try:
        details = coll_registered_organization.find_one({"organization_id":data['organization_id']})
        if details:
                registered_devices_info = details["registered_devices"]                                     
                for device in registered_devices_info:                                       
                    spoke_details = coll_tunnel_ip.find_one({"uuid":device["uuid"]})
                    if spoke_details:                        
                        activate_spoke(spoke_details)
                        total_branches.append({"public_ip": spoke_details["public_ip"], 
                                       "tunnel_ip": spoke_details["tunnel_ip"],
                                       "branch_location": spoke_details["branch_location"],
                                       "subnet": spoke_details["subnet"],
                                        "vrf": spoke_details["vrf"],
                                        "hub_ip": data.get("dialer_ip", "")
                                       })
        print(total_branches)
        # Use a set to keep track of unique tuples (a, b)
        seen = set()
        # Use a list comprehension to filter out duplicates
        total_branches = [entry for entry in total_branches if (entry["tunnel_ip"]) not in seen and not seen.add((entry["tunnel_ip"]))]

        with open("/root/reachlink/total_branches.json", "w") as f:            
            json.dump(total_branches, f)
            f.close()

    except Exception as e:
        response = [{"message": f"Error getting while activating pl try again:{e}"}]
    logger.debug(f'Received request: {request.method} {request.path}')
    return HttpResponse(response)      

def background_delete(data1):
    spoke_not_connected = []
    total_spoke_deleted = []
    spoke_deleted = []
    with open("/root/reachlink/total_branches.json", "r") as f:
       total_branches = json.load(f)
       f.close()
    try:
        details = coll_registered_organization.find_one({"organization_id":data1['organization_id']})
        if details:
                registered_devices_info = details["registered_devices"]                                     
                for device in registered_devices_info:                                       
                    data = coll_tunnel_ip.find_one({"uuid":device["uuid"]})
                    if data is not None:
                        tunnel_ip = data["tunnel_ip"].split("/")[0]
                        if ipaddress.ip_address(tunnel_ip) in ipaddress.ip_network(vrf1_ip):
                            try:
                                command = (f"ping -c 5  {tunnel_ip}")
                                output = subprocess.check_output(command.split()).decode()
                                url = f"http://{tunnel_ip}:5000/"              
                                response1 = requests.get(url + "delete", timeout = 5)  # Short connect timeout, longer read timeout  
                            except subprocess.CalledProcessError:
                                print("not connected", data)
                                spoke_not_connected.append(data)                                
                            except requests.exceptions.Timeout:
                                print("timeout", data)
                                spoke_deleted.append(data)   
                            try:                                       
                                command = f"sudo ip neighbor del {tunnel_ip} lladdr {data['public_ip']} dev Reach_link1"
                                subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                                for i in data["subnet"]:
                                    try:
                                        command = f"sudo ip route del {i} via {tunnel_ip}"
                                        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                                        #command = f"ip route del {i} dev vrf1"
                                        # subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                                    except Exception as e:
                                        print(f"Error occured while deleting route for {i}:{e}")  
                            except Exception as e:
                                print("Device already disconnected")   
                            total_spoke_deleted.append({"public_ip": data["public_ip"], 
                                      "tunnel_ip": data["tunnel_ip"],
                                      "branch_location": data["branch_location"],
                                      "subnet": data["subnet"],
                                     "vrf": data["vrf"],
                                     "hub_ip": data.get("dialer_ip", "")
                                    })  
                            coll_tunnel_ip.delete_many({"uuid":device["uuid"]})                               
                        total_branches = [item for item in total_branches if item.get("tunnel_ip") != data["tunnel_ip"]]
                coll_deleted_organization.insert_one({"organization_id": data1['organization_id'],
                                                          "deleted_devices": total_spoke_deleted
                                                         })
        with open("/root/reachlink/total_branches.json", "w") as f:
            json.dump(total_branches, f)
            f.close()
        print("spoke_not connected:", spoke_not_connected)
        print("spoke deleted:", spoke_deleted)
    except Exception as e:
        response = [{"message": f"Error getting while disconnection pl try again:{e}"}]

@csrf_exempt
def onboard_delete(request: HttpRequest):
    data = json.loads(request.body)
    response = [{"message": "Organization spokes disconnected successfully"}]
    background_thread = threading.Thread(target=background_delete, args=(data,))
    background_thread.start()    
    return HttpResponse(response)
def background_update(data1):
    spoke_not_connected = []
    spoke_not_updated  = []
    spoke_updated = []
    with open("/root/reachlink/total_branches.json", "r") as f:
       total_branches = json.load(f)
       f.close()
    try:
        details = coll_registered_organization.find_one({"organization_id":data1['organization_id']})
        if details:
                registered_devices_info = details["registered_devices"]                                     
                for device in registered_devices_info:                                       
                    data = coll_tunnel_ip.find_one({"uuid":device["uuid"]})
                    if data is not None:
                        tunnel_ip = data["tunnel_ip"].split("/")[0]
                        if ipaddress.ip_address(tunnel_ip) in ipaddress.ip_network(vrf1_ip):
                            try:
                                command = (f"ping -c 5  {tunnel_ip}")
                                output = subprocess.check_output(command.split()).decode()
                                url = f"http://{tunnel_ip}:5000/"              
                                collect = {"file_name": data1["file_name"],
                                            "url": data1["url"]}
                                headers = {"Content-Type": "application/json"}
                                json_data = json.dumps(collect)
                                response1 = requests.post(url + "update", data=json_data, headers=headers) 
                                if response1.status_code == 200:                          		
                                    spoke_updated.append(device)  
                            except subprocess.CalledProcessError:
                                print("not connected", data)
                                spoke_not_connected.append(data)                                
                            except requests.exceptions.Timeout:
                                print("timeout", data)
                                spoke_not_updated.append(data)           
        
        print("spoke_not connected:", spoke_not_connected)
        print("spoke deleted:", spoke_updated)
        print("spoke deleted:", spoke_not_updated)
    except Exception as e:
        response = [{"message": f"Error getting while disconnection pl try again:{e}"}]

@csrf_exempt
def spoke_update(request: HttpRequest):
    data = json.loads(request.body)
    response = [{"message": "Organization spokes updated successfully"}]
    background_thread = threading.Thread(target=background_update, args=(data,))
    background_thread.start()    
    logger.debug(f'Received request: {request.method} {request.path}')
    return HttpResponse(response)
           
@csrf_exempt
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
                    data.append(branch)
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
        response = {    "data":data,
                        "total_branches":total_no_branches,
                        "inactive_branches":inactive_branches,
                        "active_branches": active_branches,
                        "organization_id": organization_id
                    }
    return JsonResponse(response, safe=False)


def check_public_ip(REMOTE_HOSTNAME):
    try:
        # Resolve the hostname to an IP address
        REMOTE_IP = socket.gethostbyname(REMOTE_HOSTNAME)
        if REMOTE_IP:
            logging.info(f"Resolved IP for {REMOTE_HOSTNAME}: {REMOTE_IP}")
            print(f"Resolved IP for {REMOTE_HOSTNAME}: {REMOTE_IP}")
            return REMOTE_IP
        else:
            logging.error("No IP address returned")
            return False
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {REMOTE_HOSTNAME}")
        logging.error(f"Error: Could not resolve hostname {REMOTE_HOSTNAME}")
        return False

@csrf_exempt
def add_cisco_deviceold(request: HttpRequest):
    data = json.loads(request.body)    
    data["uuid"] = data['system_name']
    print(data)
    data["public_ip"] = check_public_ip(data['system_name'])
    data["username"] = "none"
    data["password"] = "none"
    with open("/root/reachlink/total_branches.json", "r") as f:
            total_branches = json.load(f)
            f.close()
    for dev in total_branches:
        if dev["uuid"] == data["uuid"]:
            if dev["status"] == "active":
                response = [{"message": f"Already configured & Active", "tunnel_ip":dev["tunnel_ip"]}]
                return JsonResponse(response, safe=False)
            elif dev["status"] == "inactive":
                response = [{"message": f"Already configured but Inactive",  "tunnel_ip":dev["tunnel_ip"]}]
                return JsonResponse(response, safe=False)
    if data["public_ip"]:
        global newuser
        try:
            response = check_user(data)
            print(response)
            print(newuser)
            if newuser:
                userStatus = authenticate_user(data)
                print(userStatus)
                if userStatus:
                    response = check_user(data)
                else:
                    response = [{"message": userStatus,"expiry_date": dummy_expiry_date}]
            print(response)
            if response[0]["message"] == "Successfully Registered" or response[0]["message"] == "This device is already Registered":
                devicename = response[0]["spokedevice_name"]
                tunnel_ip = get_tunnel_ip(data, devicename)
                tunnel_ip1 = tunnel_ip.split("/")[0]
                print(tunnel_ip)                
                list1 = [ "{tunnelIp}", "{domainName}", "{deviceName}", "{deviceLocation}"]
                list2 = [ tunnel_ip1, data['system_name'], devicename, data["branch_location"]]
                with open("reachlink.txt", "r") as f:
                    data1 = f.read()
                    f.close()
                for i in range(0, len(list1)):
                    data1 = data1.replace(list1[i], list2[i])  
                domain_name = data['system_name'].split(".")[0]
                file_name = f"reachlink_{domain_name}.tcl"    
                with open(file_name, "w")as f:
                    f.write(f"{data1}")
                    f.close()
                command = f"sudo cp {file_name} /home/ftpuser/"               
                subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                command = f"sudo ip neighbor replace {tunnel_ip1} lladdr {data['public_ip']} dev Reach_link1"  
                print(command)             
                subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                data1 = {"router_ip":data["system_name"],
                    "device_username": data["device_username"],
                    "device_password": data["device_password"],
                    "tunnel_ip": tunnel_ip1,
                    "file_name": file_name,
                    "wan_interface":"Vlan100",
                    "hub_ip": hub_ip,
                    "default_gw": "192.168.1.1",
                    "hub_tunnel_ip": hub_tunnel_endpoint
                    }
                print(data1)
                status = router_configure.create_tunnel(data1)
                json_response = [{"message": "Successfully Registered. Configured this tunnel_ip in your device.", "tunnel_ip":tunnel_ip}]
            else:
                json_response = [{"message": f"Error:{response[0]['message']}"}]
        except Exception as e:
            json_response = [{"message": f"Error:Internal Server Error{e}"}]
    else:
        json_response = [{"message": f"Error:{data['system_name']} is not reachable"}]
    print(json_response)
    return JsonResponse(json_response, safe=False)
@csrf_exempt
def traceroute_hub(request):
    data = json.loads(request.body)
    host_ip = data.get('trace_ip', None)
    if host_ip:           
            result1 = subprocess.run(['traceroute', '-d', host_ip], capture_output=True, text=True)
            response = {"message":result1.stdout}
            return JsonResponse(response, safe=False)
    response = {"message":"Invalid trace ip"}
    return JsonResponse(response,safe=False)

@csrf_exempt
def traceroute_spoke(request):
    data = json.loads(request.body)
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
            response = requests.post(url + "traceroute_spoke", data=json_data, headers=headers)  # Timeout set to 5 seconds
            
            #print(response)
#            print("hi", response.content)
                # response = requests.post(url+"addroute", data=json_data, headers=headers)
                # Check the response
           # if response.status_code == 200:           
                    #response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
            if response.status_code == 200:
              #if response.headers.get('Content-Type') == 'text/plain':
                   # Try to decode manually in case of encoding issues
                try:
                    content = response.content.decode(response.encoding or 'utf-8', errors='ignore')
                    response_msg = {"message": content}

            # Log the Content-Type header for debugging
              #  return response.text  # Get plain text response body
                #    print(response.text())
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

@csrf_exempt
def lan_info(request):
    try:
        data = json.loads(request.body)
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
        
@csrf_exempt
def lan_config(request):
    try:
        data = json.loads(request.body)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "lan_config", data=json_data, headers=headers)  # Timeout set to 5 seconds
                               
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
#            response = {"message":response_microtek["message"]}
    except Exception as e:
        response = {"message": f"Error: {e}"}
    print(response)
    return JsonResponse(response, safe=False)

@csrf_exempt
def dhcp_config(request):
    try:
        data = json.loads(request.body)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "dhcp_config", data=json_data, headers=headers)  # Timeout set to 5 seconds
                               
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

@csrf_exempt
def add_ip_rule_spoke(request):
    try:
        data = json.loads(request.body)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "add_ip_rule", data=json_data, headers=headers)  # Timeout set to 5 seconds
                               
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

@csrf_exempt
def get_routing_table_spoke(request):
    try:
        data = json.loads(request.body)
        print(data)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.get(url + "get_routing_table")  # Timeout set to 5 seconds
                               
                if response.status_code == 200:           
#                    print("hi",response.text)
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    routing_table_response = json.loads(get_response)
 #                   print(routing_table_response)
                    response = routing_table_response           
                else:
                    print("hi")
                    response =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = []
        elif "microtek" in data["uuid"]:
  #          print("hiiiiiiiiiiiiiiiiiiiiii")
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
#            response = []
    except Exception as e:
        print(e)
        response = []
    print(response)
    return JsonResponse(response, safe=False)

@csrf_exempt
def get_interface_details_spoke(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of branch info:{public_ip}")
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            #headers = {"Content-Type": "application/json"} 
           
            #json_data = json.dumps(data)           
            try:
                response = requests.get(url + "get_interface_details")  # Timeout set to 5 seconds
                               
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)
                    #print(response)      
                else:
                    response =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = []
        elif "microtek" in data["uuid"]:
            print("hi")
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
#            response = []
    except Exception as e:
        print(e)
        response = []
#    print(response)
    return JsonResponse(response, safe=False)


@csrf_exempt
def create_vlan_interface_spoke(request):
    try:
        data = json.loads(request.body)
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
            interface_details = microtek_configure.createvlaninterface(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            print("vlan data", data)
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            if data["interface_type"].lower() == "vlan":
                response = router_configure.createvlaninterface(data)
            if data["interface_type"].lower() == "sub interface":
                response = router_configure.createsubinterface(data)
           
           
    except Exception as e:
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@csrf_exempt
def interface_config_spoke(request):
    try:
        data = json.loads(request.body)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "interface_config", data=json_data, headers=headers)  # Timeout set to 5 seconds
                               
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
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #status = router_configure.addroute(data)
            response = {"message":"Dummy"}
    except Exception as e:
        response = {"message": f"Error: {e}"}
    return JsonResponse(response, safe=False)

@csrf_exempt
def vlan_interface_delete_spoke(request):
    try:
        data = json.loads(request.body)
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

@csrf_exempt
def add_route_spoke(request):
    try:
        data = json.loads(request.body)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "addstaticroute", data=json_data, headers=headers)  # Timeout set to 5 seconds
                               
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

@csrf_exempt
def get_pbr_info_spoke(request):
    try:
        data = json.loads(request.body)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"                   
            try:
                response = requests.get(url + "getpbrinfo")  # Timeout set to 5 seconds
                               
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)
                    #print(response)      
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

def configurepbr_spoke_new(realipdata):
    try:    
        realipsubnet = realipdata["realip_subnet"]
        tunneinfo = coll_tunnel_ip.find({})
        datacollected=[]
        for realips in realipsubnet:
            realips["tunnel_ip"] = realips["gateway"] + "/24"
            tunnelinfo = coll_tunnel_ip.find_one({"tunnel_ip":realips["tunnel_ip"]})
            realips["uuid"] = tunnelinfo["uuid"]
            datacollected.append(realips)
        for data in datacollected:
            if ".net" not in data.get("uuid", ""):            
                tunnel_ip = data["tunnel_ip"].split("/")[0] 
                url = "http://" + tunnel_ip + ":5000/"
                # Set the headers to indicate that you are sending JSON data
                headers = {"Content-Type": "application/json"}           
                json_data = json.dumps(data)           
                try:
                    response = requests.post(url + "add_ip_rule", data=json_data, headers=headers)  # Timeout set to 5 seconds                               
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
            elif "microtek" in data["uuid"]:
                router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
#                data["router_username"] = router_info["router_username"]
 #               data["router_password"] = router_info["router_password"]

  #              status = microtek_configure.configurepbr(data)
                microtek_pbr_data = {}
                microtek_pbr_data["router_username"] = router_info["router_username"]
                microtek_pbr_data["router_password"] = router_info["router_password"]
                microtek_pbr_data["uuid"] = data["uuid"]
                microtek_pbr_data["tunnel_ip"] = data["tunnel_ip"]
                microtek_pbr_data["realip_subnet"] = [{"subnet":data["subnet"]}]
                status = microtek_configure.configurepbr(microtek_pbr_data)
                response = {"message":status}
            elif "cisco" in data["uuid"]:
                router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
                data["router_username"] = router_info["router_username"]
                data["router_password"] = router_info["router_password"]
                #status = router_configure.addroute(data)
                response = {"message":"Dummy"}
    except Exception as e:
        response = {"message": f"Error: {e}"}
    print(response)        

@csrf_exempt
def addstaticroute_hub(request: HttpRequest):
    try:
        data = json.loads(request.body)
        routes = data["routes_info"]    
        for route in routes:
            if route["destination"].split(".")[0] == "127" or route["destination"].split(".")[0] == "169" or int(route["destination"].split(".")[0]) > 223:
                response = {"message":"Error Invalid destination"}
                return JsonResponse(response, safe=False) 
            print("hiiiiiiii")
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
            real_routes = []
            past_subnets = []
            for route in routes: 
                past_subnets.append(route["destination"]) 
                if route["destination"].split(".")[0] != "10":
                    if route["destination"].split(".")[0] == "172":
                        if 15 < int(route["destination"].split(".")[1]) < 32:
                            private_ip = True
                        else:
                            private_ip = False
                    elif route["destination"].split(".")[0] == "192":
                        if route["destination"].split(".")[1] == "168":
                            private_ip = True
                        else:
                            private_ip = False
                    elif int(route["destination"].split(".")[0]) > 223: 
                        private_ip = True
                    else:
                        private_ip = False
                else:
                    private_ip = True
                if not private_ip:
                    real_routes.append(route)                     
            #  interface_addresses = configured_address_interface()
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                data1 = yaml.safe_load(f)
                f.close()
            dat=[]
            for rr in data1["network"]["tunnels"]["Reach_link1"]:
                if rr == "routes":
                    dat = data1["network"]["tunnels"]["Reach_link1"]["routes"]
            for r in routes:
                try:                    
                    if (ipaddress.ip_network(r["destination"], strict=False) and ipaddress.ip_address(r["gateway"])):
                        dat.append({"to": r["destination"],
                                    "via": r["gateway"]}
                                )
                    
                except ValueError:
                    response = [{"message":"Either subnet or Gateway is not valid IP"}]        
            data1["network"]["tunnels"]["Reach_link1"]["routes"] = dat
            with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                yaml.dump(data1, f, default_flow_style=False)
                f.close()
            os.system("sudo netplan apply")  
            for branch in coll_tunnel_ip.find({}):
                try:
                    tunip = branch["tunnel_ip"].split("/")[0]
                    os.system(f"ip neighbor add {tunip} lladdr {branch['public_ip']} dev Reach_link1") 
                except Exception as e:
                    print(f"Neighbor add error: {e}")
            if len(real_routes) > 0:
                pbr_spoke_data = { "realip_subnet": real_routes
                              }
                background_thread = threading.Thread(target=configurepbr_spoke_new, args=(pbr_spoke_data,))
                background_thread.start() 
            response = {"message":f"Successfully added {len(data['routes_info'])} subnet(s)."}
    except Exception as e:    
        response = {"message": f"Error in adding route, pl try again {e}" }
    logger.debug(f'Received request: {request.method} {request.path}')   
    print(response) 
    return JsonResponse(response, safe=False) 

@csrf_exempt
def get_interface_details_hub(request):
    try:
        data = json.loads(request.body)  
        print(data)  
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        print(f"requested ip of get interface:{public_ip}")
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
            interface_details = []
            interface = psutil.net_if_addrs()
            intfc_ubuntu = []
            for intfc_name in interface:            
                if intfc_name == "gre0" or intfc_name == "gretap0" or intfc_name == "erspan0" or intfc_name =="lo":   
                    continue
                colect = {"interface_name":intfc_name}
                if intfc_name == "eth1":
                    colect.update({"type":"ether"})
                addresses = interface[intfc_name]
                interface_addresses = []
                for address in addresses:      
                    if address.family == 2:
                        pre_len = IPAddress(address.netmask).netmask_bits()
                        ipaddr_prefix = str(address.address)+"/"+str(pre_len)
                        interface_addresses.append({
                                    "IPv4address_noprefix":str(address.address),
                                    "IPv4address":ipaddr_prefix,
                                    "netmask":str(address.netmask),
                                    "broadcast":str(address.broadcast)
                                  })
                    if address.family == 17:
                        colect.update({
                                    "mac_address":str(address.address)
                                   })         
                colect.update({"addresses":interface_addresses})   
                intfc_ubuntu.append(colect)
                interface_details.append(colect)
            #By using pyroute module, we get the default route info & conclude which interface is WAN.  
            # And about its Gateway
            default_route = ipr.get_default_routes(family = socket.AF_INET)
            for route in default_route:
                multipath = 0
                for attr in route['attrs']:
                    if attr[0] == 'RTA_OIF':
                        intfc_name = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                    if attr[0] == 'RTA_GATEWAY':
                        gateway = attr[1]
                    if attr[0] == 'RTA_MULTIPATH':
                        multipath = 1
                        for elem in attr[1]:
                            intfc_name = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                            for attr2 in elem['attrs']:
                                if attr2[0] == 'RTA_GATEWAY':
                                    gateway = attr2[1] 
                                    for intfc in interface_details:
                                        if intfc["interface_name"] == intfc_name:
                                            intfc["gateway"] = gateway
                                            intfc["type"] = "ether"
                if multipath == 0:
                    for intfc in interface_details:
                        if intfc["interface_name"] == intfc_name:
                            intfc["gateway"] = gateway
                            intfc["type"] = "ether" 
                        if "." in intfc["interface_name"]:
                            intfc["type"] = "VLAN"
                        elif "eth" in intfc["interface_name"]:
                            intfc["type"] = "ether"
                        if intfc["interface_name"] == "Reach_link1" or intfc["interface_name"] == "tun0":
                            intfc["type"] = "tunnel"
                        if "vrf" in intfc["interface_name"]:
                            intfc["type"] = "VRF"
                        if intfc["interface_name"] == "Reach_link1":
                            intfc["interface_name"] = "Overlay Tunnel"
                        if intfc["interface_name"] == "tun0":
                            intfc["interface_name"] = "Base Tunnel"

            response = interface_details
    except Exception as e:
        print(e)
        response = []
#    print("hub interface details", response)
    return JsonResponse(response, safe=False)

@csrf_exempt
def delstaticroute_hub(request: HttpRequest):
    response = [{"message":"Successfully deleted"}]
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
            subnet_info = data["routes_info"]
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                data1 = yaml.safe_load(f)
                f.close()
            dat=[]
            for rr in data1["network"]["tunnels"]["Reach_link1"]:
                if rr == "routes":
                    dat = data1["network"]["tunnels"]["Reach_link1"]["routes"]
        
            for r in subnet_info:            
                dat = [item for item in dat if item.get('to') != r['destination']]
            data1["network"]["tunnels"]["Reach_link1"]["routes"] = dat
            with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                yaml.dump(data1, f, default_flow_style=False)
                f.close()
            os.system("sudo netplan apply")
            for branch in coll_tunnel_ip.find({}):
                try:
                    tunip =  branch['tunnel_ip'].split("/")[0]
                    os.system(f"ip neighbor add {tunip} lladdr {branch['public_ip']} dev Reach_link1") 
                except Exception as e:
                    print(f"Neighbor add error: {e}")  
            response = {"message": "Successfully route deleted"}
    except Exception as e:
        print(e)
        response = {"message":f"Error while deleting route: {e}"}
    return JsonResponse(response, safe=False)

@csrf_exempt
def del_staticroute_spoke(request):
    try:
        data = json.loads(request.body)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "delstaticroute", data=json_data, headers=headers)  # Timeout set to 5 seconds
                               
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

@csrf_exempt
def addsubnet(request: HttpRequest):
    try:
        data = json.loads(request.body)         
        subnets = data["subnet_info"]
        tunnel_ip = data["tunnel_ip"].split("/")[0] 
        tunnel_info = coll_tunnel_ip.find_one({"tunnel_ip": data['tunnel_ip']}) 
        past_subnets = tunnel_info["subnet"] 
        subnet_na = [] 
        real_routes = []
        with open("/etc/netplan/00-installer-config.yaml", "r") as f:
            data1 = yaml.safe_load(f)
            f.close()
        dat=[]
        for rr in data1["network"]["tunnels"]["Reach_link1"]:
            if rr == "routes":
                dat = data1["network"]["tunnels"]["Reach_link1"]["routes"]         
        for subnet in subnets:
            if subnet["subnet"].split(".")[0] == "127" or subnet["subnet"].split(".")[0] == "169" or int(subnet["subnet"].split(".")[0]) > 223:
                subnet_na.append(subnet["subnet"])
            else:
                try:                    
                    if (ipaddress.ip_network(subnet["subnet"], strict=False) and ipaddress.ip_address(subnet["gateway"])):
                        dat.append({"to": subnet["subnet"],
                                    "via": tunnel_ip}
                                )
                        past_subnets.append(subnet["subnet"]) 
                    
                except ValueError:
                    response = [{"message":"Either subnet or Gateway is not valid IP"}]  
                    subnet_na.append(subnet["subnet"])         
                    
                if subnet["subnet"].split(".")[0] != "10":
                    if subnet["subnet"].split(".")[0] == "172":
                        if 15 < int(subnet["subnet"].split(".")[1]) < 32:
                                private_ip = True
                        else:
                                private_ip = False
                    elif subnet["subnet"].split(".")[0] == "192":
                        if subnet["subnet"].split(".")[1] == "168":
                            private_ip = True
                        else:
                            private_ip = False
                    elif int(subnet["subnet"].split(".")[0]) > 223: 
                        private_ip = True
                    else:
                        private_ip = False
                else:
                    private_ip = True
                if not private_ip:
                    real_routes.append(subnet)
        data1["network"]["tunnels"]["Reach_link1"]["routes"] = dat
        with open("/etc/netplan/00-installer-config.yaml", "w") as f:
            yaml.dump(data1, f, default_flow_style=False)
            f.close()
        os.system("sudo netplan apply")  
        for branch in coll_tunnel_ip.find({}):
            try:
                os.system(f"ip neighbor add {branch['tunnel_ip'].split('/')[0]} lladdr {branch['public_ip']} dev Reach_link1") 
            except Exception as e:
                print(f"Neighbor add error: {e}")     
        if len(real_routes) > 0:
            pbr_spoke_data = {"tunnel_ip": data["tunnel_ip"],
                              "uuid": data["uuid"],
                              "realip_subnet": real_routes }
            #pbrresponse = configurepbr_spoke_new(pbr_spoke_data)
            background_thread = threading.Thread(target=configurepbr_spoke, args=(pbr_spoke_data,))
            background_thread.start() 
            #print(pbrresponse)        
                    
        past_subnets = list(set(past_subnets))         
        past_subnets = [item for item in past_subnets if item != "None"]      
        query = {"tunnel_ip": data["tunnel_ip"] }
        update_data = {"$set": {"subnet":past_subnets 
                                    }
                          }
        coll_tunnel_ip.update_many(query, update_data)

        os.system("systemctl stop reachlink_test") 
        with open("/root/reachlink/total_branches.json", "r") as f:
            totalbranches = json.load(f)
            f.close()
        for dev in totalbranches:
            if dev["uuid"] == data["uuid"]:
                dev["subnet"] = past_subnets
        with open("/root/reachlink/total_branches.json", "w") as f:
            json.dump(totalbranches, f)
            f.close() 
        os.system("systemctl start reachlink_test")        
        past_subnets = list(set(past_subnets))
        background_thread = threading.Thread(target=background_addsubnet, args=(data,))
        background_thread.start() 
        if len(subnet_na) == 0: 
            response = {"message":f"Successfully added {len(data['subnet_info'])} subnet(s)."}    
        else:
            added_subnet = len(data['subnet_info']) - len(subnet_na)
            if added_subnet == 0:
                response = {"message":f"{subnet_na} is already routed."}
            else:
                response = {"message":f"Successfully added {added_subnet} subnet(s). {subnet_na} is already routed."}
    except Exception as e:    
        response = {"message": f"Error in adding route, pl try again {e}" }
    logger.debug(f'Received request: {request.method} {request.path}')   
    print(response) 
    return JsonResponse(response, safe=False) 

def generate_dialerip(dialerips):
    random_no = random.randint(3,250)
    newdialerip = dialernetworkip + str(random_no)
    for dialerip in dialerips:
        if dialerip == newdialerip:
            return generate_dialerip(dialerips)
    return newdialerip

def generate_dialer_password():
    # Define character pools
    char_pool = ""
    char_pool += string.ascii_lowercase
    char_pool += string.digits
    if not char_pool:
        raise ValueError("At least one character type must be selected.")

    # Ensure the password contains at least one character of each selected type
    password = []
    password.append(random.choice(string.ascii_lowercase))
    password.append(random.choice(string.digits))
    password.append('@')
    # Fill the rest of the password length with random choices
    remaining_length = 8 - len(password)
    password.extend(random.choices(char_pool, k=remaining_length))
    
    # Shuffle the password to avoid predictable patterns
    random.shuffle(password)    
    return ''.join(password)


def get_dialer_ip(devicename):
    try:
        with open("/etc/ppp/chap-secrets", "r") as f:
            chapsecret = f.read()
            f.close()
        usernames = []
        dialer_ips = []
        newdialerip = False
        newdialerpassword = False
        chapsecrets = chapsecret.split("\n")
        for sec in chapsecrets:
            if "#" not in sec:
                username = sec.strip().split(" ")[0]
                usernames.append(username)
                if username == devicename:
                    print("User Already available")
                    dialerip = sec.strip().split(" ")[-1]
                    dialerpassword= sec.strip().split(" ")[2]
                    return ({"dialerip":dialerip,
                             "dialerpassword": dialerpassword,
                             "dialerusername": devicename,
                             "message": "olduser"})                    
                dialer_ips.append(sec.strip().split(" ")[-1])
        newdialerip = generate_dialerip(dialer_ips)
        newdialerpassword = generate_dialer_password()
        with open("/etc/ppp/chap-secrets", "a") as f:
            f.write(f'\n{devicename}   *   {newdialerpassword}    {newdialerip}\n')
            f.close()
        #os.system("systemctl restart pptpd")
        return ({"dialerip":newdialerip,
                "dialerpassword": newdialerpassword,
                "dialerusername": devicename,
                "message": "newuser"})        
    except Exception as e:
        print(e)
    return ({"dialerip":newdialerip,
                "dialerpassword": newdialerpassword,
                "dialerusername": devicename,
                "message": "error"})    
             

                
@csrf_exempt
def add_cisco_device_spoke(request: HttpRequest):
    data = json.loads(request.body)    
    data["uuid"] = data['system_name'] + "_cisco.net"
    print(data)
    data["username"] = "none"
    data["password"] = "none"
    with open("/root/reachlink/total_branches.json", "r") as f:
            total_branches = json.load(f)
            f.close()
    for dev in total_branches:
        if dev["uuid"] == data["uuid"]:
            if dev["status"] == "active":
                response = [{"message": f"Already configured & Active", "tunnel_ip":dev["tunnel_ip"]}]
                
            elif dev["status"] == "inactive":
                response = [{"message": f"Already configured but Inactive",  "tunnel_ip":dev["tunnel_ip"]}]
            domain_name = data['system_name'].split(".")[0]
            output_file = f"{domain_name}.py"    
            with open(output_file, 'r') as file:
                conffile_content = file.read()
                file.close()
            with open("reachlink_config.py", "w")as f:
                f.write(f"{conffile_content}")
                f.close()
            with open("install_python.bat", "r")as f:
                installscript = f.read()
                f.close()
            files_to_send = {
                    "reachlink_config.py":f"{conffile_content}",
                    "install_python.bat": f"{installscript}",
                    }

            # Create a buffer for the ZIP file
            buffer = io.BytesIO()

            # Create a ZIP archive
            with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for filename, content in files_to_send.items():
                    zip_file.writestr(filename, content)

            # Prepare the response
            buffer.seek(0)
            json_response = [{"message": "Already Registered"}]
            response = HttpResponse(buffer, content_type='application/zip')
            response['Content-Disposition'] = 'attachment; filename="reachlink_conf.zip"'
            response['X-Message'] = json.dumps(json_response)
            return response
    
    global newuser
    try:
        response = check_user(data)
        print(response)
        print(newuser)
        if newuser:
            userStatus = authenticate_user(data)
            print(userStatus)
            if userStatus:
                response = check_user(data)
            else:
                response = [{"message": userStatus,"expiry_date": dummy_expiry_date}]
        print(response)
        if response[0]["message"] == "Successfully Registered" or response[0]["message"] == "This device is already Registered":
            devicename = response[0]["spokedevice_name"]
            dialerinfo = get_dialer_ip(devicename)  
            if dialerinfo["message"] == "error":
                json_response = [{"message": f"Error:while generating dialerip"}]
                response = HttpResponse(content_type='application/zip')
                response['X-Message'] = json.dumps(json_response)
                return response

            list1 = ["{dialer_client_ip}", "{dialer_username}", "{dialer_password}", "{dialer_netmask}", "{dialerserverip}"]
            list2 = [ dialerinfo['dialerip'], dialerinfo['dialerusername'], dialerinfo['dialerpassword'], dialer_netmask, hub_ip]
            with open("com_router_config.py", "r") as f:
                data1 = f.read()
                f.close()
            for i in range(0, len(list1)):
                data1 = data1.replace(list1[i], list2[i])  
            domain_name = data['system_name'].split(".")[0]
            file_name = f"{domain_name}.py"    
            with open(file_name, "w")as f:
                f.write(f"{data1}")
                f.close()
            orgid = get_organization_id(data)
            details = coll_registered_organization.find_one({"organization_id":orgid})
            registered_devices_info = details["registered_devices"]
            for device in registered_devices_info:
                if device["uuid"] == data["uuid"]:
                    device["gretunnel_ip"] = dialerinfo["dialerip"]
            query = {"organization_id": orgid}
            update_data = {"$set": {"registered_devices": registered_devices_info } }
            coll_registered_organization.update_many(query, update_data)
            
            with open("reachlink_config.py", "w")as f:
                f.write(f"{data1}")
                f.close()
            query = {"uuid": data["uuid"]}
            update_data = {"$set": {"tunnel_ip": dialerinfo["dialerip"]  } }
            coll_tunnel_ip.update_many(query, update_data)
            with open("install_python.bat", "r")as f:
                installscript = f.read()
                f.close()
            files_to_send = {
                    "reachlink_config.py": f"{data1}",
                    "install_python.bat": f"{installscript}",
                    }

            # Create a buffer for the ZIP file
            buffer = io.BytesIO()

            # Create a ZIP archive
            with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for filename, content in files_to_send.items():
                    zip_file.writestr(filename, content)

            # Prepare the response
            buffer.seek(0)
            json_response = [{"message": "Successfully Registered"}]
            print("lastbefore",json_response)
            response = HttpResponse(buffer, content_type='application/zip')
            response['Content-Disposition'] = 'attachment; filename="reachlink_conf.zip"'
            response['X-Message'] = json.dumps(json_response)
            return response
        else:
            json_response = [{"message": f"Error:{response[0]['message']}"}]
    except Exception as e:
        json_response = [{"message": f"Error:Internal Server Error{e}"}]
    print("last", json_response)
    response = HttpResponse(content_type='application/zip')
    response['X-Message'] = json.dumps(json_response)
    return response

@csrf_exempt
def create_subinterface_interface_spoke(request):
    try:
        data = json.loads(request.body)
        if ".net" not in data.get("uuid", ""):            
            tunnel_ip = data["tunnel_ip"].split("/")[0] 
            url = "http://" + tunnel_ip + ":5000/"
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"} 
           
            json_data = json.dumps(data)           
            try:
                response = requests.post(url + "create_sub_interface", data=json_data, headers=headers)  # Timeout set to 5 seconds
                               
                if response.status_code == 200:           
                    print(response.text)
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)                
                               
                else:
                    response = [{"message":"Error while configuring sub-interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}]   
        elif "microtek" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.createsubinterface(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            status = router_configure.createsubinterface(data)
            if status:
                response = [{"message": "Successfully sub-interface created"}]
            else:
                response = [{"message":"Error in creating sub-interfaces"}]
    except Exception as e:
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

def generate_dialerip_cisco(networkip, netmaskip):
    network = ipaddress.IPv4Network(f"{networkip}/{netmaskip}", strict=False)
    newdialerip =  str(random.choice(list(network.hosts())))
    for dialerip in coll_dialer_ip.find({},{"_id":0}):
        if dialerip["dialerip"] == newdialerip:
            return generate_dialerip(networkip, netmaskip)
    return newdialerip

def generate_dialer_password_cisco():
    # Define character pools
    char_pool = ""
    char_pool += string.ascii_lowercase
    char_pool += string.digits
    if not char_pool:
        raise ValueError("At least one character type must be selected.")

    # Ensure the password contains at least one character of each selected type
    password = []
    password.append(random.choice(string.ascii_lowercase))
    password.append(random.choice(string.digits))
    password.append('@')
    # Fill the rest of the password length with random choices
    remaining_length = 8 - len(password)
    password.extend(random.choices(char_pool, k=remaining_length))
    
    # Shuffle the password to avoid predictable patterns
    random.shuffle(password)    
    return ''.join(password)


def get_dialer_ip_fromciscohub(devicename, dialerip):
    try:
        
        newdialerpassword = generate_dialer_password_cisco()
        hub_info = coll_hub_info.find_one({"hub_wan_ip_only": dialerip})       
        if hub_info:
            newdialerip = generate_dialerip_cisco(hub_info["hub_dialer_network"], hub_info["hub_dialer_netmask"])            
            if (router_configure.adduser({"username":devicename,
                                  "password":newdialerpassword,
                                  "tunnel_ip": dialerip,
                                "router_username": hub_info["router_username"],
                                "router_password": hub_info["router_password"]})):   
                return ({"dialerip":newdialerip,
                            "dialerpassword": newdialerpassword,
                            "dialerusername": devicename,
                            "hub_dialer_network":hub_info["hub_dialer_network"],
                            "hub_dialer_netmask":hub_info["hub_dialer_netmask"]
                        })        
    except Exception as e:
        print(e)
    return False


def generate_router_password_cisco():
    # Define character pools
    char_pool = ""
    char_pool += string.ascii_lowercase
    char_pool += string.digits
    if not char_pool:
        raise ValueError("At least one character type must be selected.")

    # Ensure the password contains at least one character of each selected type
    password = []
    password.append(random.choice(string.ascii_lowercase))
    password.append(random.choice(string.digits))
    password.append('@')
    # Fill the rest of the password length with random choices
    remaining_length = 8 - len(password)
    password.extend(random.choices(char_pool, k=remaining_length))
    
    # Shuffle the password to avoid predictable patterns
    random.shuffle(password)    
    return ''.join(password)

@csrf_exempt
def add_cisco_device(request: HttpRequest):
    data = json.loads(request.body)   
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
    global newuser
    try:
        response = check_user(data)
        print(response)
        print(newuser)
        if newuser:
            userStatus = authenticate_user(data)
            print(userStatus)
            if userStatus:
                response = check_user(data)
            else:
                response = [{"message": userStatus,"expiry_date": dummy_expiry_date}]
        print(response)
        if response[0]["message"] == "Successfully Registered" or response[0]["message"] == "This device is already Registered":
            devicename = response[0]["spokedevice_name"]
            devicedialerinfo = coll_dialer_ip.find_one({"dialerusername":devicename})
            dialer_ip = data.get("dialer_ip", "")
            if not devicedialerinfo:
                newdialerinfo = get_dialer_ip_fromciscohub(devicename, dialer_ip )
                if newdialerinfo:
                    newdialerinfo["router_username"] = devicename.lower()
                    newdialerinfo["router_password"] = generate_router_password_cisco()
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
                    orgid = get_organization_id(data)
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

@csrf_exempt
def add_cisco_hub(request: HttpRequest):
    data = json.loads(request.body)    
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
        response = check_user(data)
        print(response)
        print(newuser)
        if newuser:
            userStatus = authenticate_user(data)
            print(userStatus)
            if userStatus:
                response = check_user(data)
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
                devicehubinfo["router_password"] = generate_router_password_cisco() 
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

def configured_address():
    try:
        interface_addresses= []
        interface = psutil.net_if_addrs()        
        for intfc_name in interface:  
            if intfc_name == "gre0" or intfc_name == "gretap0" or intfc_name == "erspan0" or intfc_name =="lo":   
                continue
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:
                    pre_len = IPAddress(address.netmask).netmask_bits()
                    ipaddr_prefix = str(address.address)+"/"+str(pre_len)
                    interface_addresses.append(ipaddr_prefix)
    except Exception as e:
        print(e)
    return interface_addresses

def create_vlan_interface(data):
    try:
        interface_addresses = configured_address()
        for vlan_address in data["addresses"]:
            for address in interface_addresses:
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(vlan_address.split("/")[0])
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring VLAN interface due to address conflict {vlan_address}"}]
                    return JsonResponse(response, safe=False)
        if os.path.exists("/etc/netplan/00-installer-config.yaml"):
            # Open and read the Netplan configuration
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()           
            # Ensure the `vlans` section exists
            if "vlans" not in network_config["network"]:
                network_config["network"]["vlans"] = {}

            # Create the VLAN interface name
            vlan_int_name = f"{data['link']}.{data['vlan_id']}"
            if vlan_int_name not in network_config["network"]["vlans"]:
            # Add VLAN configuration
                network_config["network"]["vlans"][vlan_int_name] = {
                                                                "id": int(data["vlan_id"]),
                                                                "link": data["link"],
                                                                "addresses": data["addresses"],
                                                                "nameservers": {"addresses": data["nameservers"]},
                                                                }

                # Write the updated configuration back to the file
                with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                    yaml.dump(network_config, f, default_flow_style=False)
                os.system("netplan apply")
                response = [{"message": f"Successfully configured VLAN Interface: {vlan_int_name}"}]
            else:
                response = [{"message": f"Error already VLAN: {vlan_int_name} exist."}]
        else:
            vlan_int_name = data["link"] + "." + str(data["vlan_id"])
            cmd = f"sudo ip link add link {data['link']} name {vlan_int_name} type vlan id {str(data['vlan_id'])}"
            result = subprocess.run(
                                cmd, shell=True, text=True
                                )
            for ip_addr in data["addresses"]:
                cmd = f"sudo ip addr add {ip_addr} dev eth1.100"
                result = subprocess.run(
                                cmd, shell=True, text=True
                                )
            cmd = f"sudo ip link set dev {vlan_int_name} up"
            result = subprocess.run(
                                cmd, shell=True, text=True
                                )
            response = [{"message": f"Successfully configured VLAN Interface: {vlan_int_name}"}]

    except Exception as e:
        response = [{"message": f"Error while configuring VLAN interface with id {data['vlan_id']}: {e}"}]
    return response


@csrf_exempt
def create_vlan_interface_hub(request):
    try:
        data = json.loads(request.body)
        #data["hub_wan_ip"] = "78.110.5.90"
        if "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.createvlaninterface(data)
        elif data["hub_wan_ip"] == hub_ip:
            response = create_vlan_interface(data)        
    except Exception as e:
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@csrf_exempt
def create_sub_interface_hub(request):
    try:
        data = json.loads(request.body)
        #data["hub_wan_ip"] = "78.110.5.90"
        if "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.createsubinterface(data) 
        elif data["hub_wan_ip"] == hub_ip:
            response = create_vlan_interface(data)        
    except Exception as e:
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)

@csrf_exempt
def create_loopback_interface_hub(request):
    try:
        data = json.loads(request.body)
        #data["hub_wan_ip"] = "78.110.5.90"
        if "ciscohub" in data["uuid"]:
            hub_info = coll_hub_info.find_one({"hub_wan_ip_only": data["hub_wan_ip"]})
            if hub_info:
                data["tunnel_ip"] = data["hub_wan_ip"]
                data["router_username"] = hub_info["router_username"]
                data["router_password"] = hub_info["router_password"]
                response = router_configure.createloopbackinterface(data) 
        elif data["hub_wan_ip"] == hub_ip:
            response = [] 
    except Exception as e:
        response = [{"message": f"Error: {e}"}]
    return JsonResponse(response, safe=False)


@csrf_exempt
def get_configured_hub(request):
    try:
        hubips = []
        for hubinfo in coll_hub_info.find({}):
            hubips.append(hubinfo["hub_wan_ip_only"])
    except Exception as e:
        print("error in fetch hubips:", e)
    return JsonResponse(hubips, safe=False)

@csrf_exempt
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

@csrf_exempt
def get_ciscohub_config(request: HttpRequest):
    data = json.loads(request.body)  
    current_datetime = datetime.now()
    try:
        organization_id = get_organization_id(data)
        print("orgid", organization_id)  
        if organization_id:            
            details = coll_registered_organization.find_one({"organization_id":organization_id})
            if details:                                                   
                if current_datetime < details["subscription_to"]:
                    registered_devices_info = details["registered_devices"]                  
                    for device in registered_devices_info:
                        if device['uuid'] == data["uuid"]:  
                            hubinfo = coll_hub_info.find_one({"uuid": data["uuid"]})
                            if hubinfo:
                                response ={ "message": 'This device is already Registered',
                                            "interface_wan_ip":hubinfo["hub_wan_ip_only"],
                                            "interface_wan_netmask":hubinfo["hub_wan_ip_netmask"],
                                            "interface_wan_gateway":hubinfo["hub_wan_ip_gateway"],
                                            "dialernetwork": hubinfo["hub_dialer_network"],
                                            "dialernetmask": hubinfo["hub_dialer_netmask"],
                                            "dialerhubip": hubinfo["hub_dialer_ip"],
                                            "ubuntuhubip": hub_ip,
                                            "router_username": hubinfo["router_username"],
                                            "router_password": hubinfo["router_password"],
                                            "snmpcommunitystring": snmpcommunitystring,
                                            }
                                return JsonResponse(response) 
                    response = {"message": "This HUB location was not configuared yet."}
                else:
                    response = {"message": "Your subscription was expired. Kindly renew it"} 
            else:
                response = {"message": "This organization is not registered with ReachLink"} 
        else:
            response = {"message": "This username is not registered with CloudEtel"} 
    except Exception as e:
        print(f"Exception while get_hub_config end point: {e}")
        response = {"message": "Some internal error. Pl try again"}
    return JsonResponse(response)

@csrf_exempt
def get_ciscospoke_config(request: HttpRequest):
    data = json.loads(request.body)  
    current_datetime = datetime.now()
    try:
        organization_id = get_organization_id(data)
        print("orgid", organization_id)  
        if organization_id:            
            details = coll_registered_organization.find_one({"organization_id":organization_id})
            if details:                                                   
                if current_datetime < details["subscription_to"]:
                    registered_devices_info = details["registered_devices"]                  
                    for device in registered_devices_info:
                        if device['uuid'] == data["uuid"]:  
                            spokeinfo = coll_dialer_ip.find_one({"uuid": data["uuid"]})
                            if spokeinfo:
                                response ={ "message": 'This device is already Registered',
                                            "interface_wan_ip": spokeinfo["router_wan_ip_only"],
                                            "interface_wan_netmask":spokeinfo["router_wan_ip_netmask"],
                                            "dialerserverip":spokeinfo["dialer_hub_ip"],
                                            "interface_wan_gateway": spokeinfo["router_wan_ip_gateway"],
                                            "dialer_client_ip": spokeinfo["dialerip"],
                                            "dialer_netmask": spokeinfo["hub_dialer_netmask"],
                                            "dialer_username": spokeinfo["dialerusername"],
                                            "dialer_password": spokeinfo["dialerpassword"],
                                            "router_username": spokeinfo["router_username"],
                                            "router_password": spokeinfo["router_password"],
                                            "ubuntu_dialerclient_ip": spokeinfo["ubuntu_dialerclient_ip"],
                                            "snmpcommunitystring": snmpcommunitystring,
                                            }
                                return JsonResponse(response) 
                    response = {"message": "This Branch location was not configuared yet."}
                else:
                    response = {"message": "Your subscription was expired. Kindly renew it"} 
            else:
                response = {"message": "This organization is not registered with ReachLink"} 
        else:
            response = {"message": "This username is not registered with CloudEtel"} 
    except Exception as e:
        print(f"Exception while get_hub_config end point: {e}")
        response = {"message": "Some internal error. Pl try again"}
    return JsonResponse(response)
