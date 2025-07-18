import requests
from datetime import datetime
from dateutil.relativedelta import relativedelta
import pymongo
import random
import json
import ipaddress
import os
import subprocess
import hub_config
import logging
logger = logging.getLogger('reachlink')
from decouple import config
mongo_uri = config('DB_CONNECTION_STRING')
snmpcommunitystring = config('SNMP_COMMUNITY_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_spoke_disconnect = db_tunnel["spoke_disconnect"]
coll_registered_organization = db_tunnel["registered_organization"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]
url = config('ONBOARDING_API_URL')
openvpnhubip = config('HUB_OPENVPN_ENDPOINT')
hub_tunnel_endpoint = config('HUB_GRE_END_POINT')
dummy_expiry_date = ""
gretunnelnetworkip = config('HUB_GRE_NETWORKIP')
hub_ip = config('HUB_IP')
hub_host_id = config('HUB_HOSTID')
hub_item_id_sent = config('HUB_ITEM_ID_SENT')
hub_item_id_received = config('HUB_ITEM_ID_RECEIVED')
def organization_name(data):
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
                 return 'Invalid Login & password', False
        else:
            access_token = data["access_token"]
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        get_organization_name = requests.get(url+"org/", headers=headers)
        org_response = get_organization_name.json()
        organization_name = org_response["data"]["company_name"].replace(" ", "")
        return organization_name, True
    except Exception as e:
        logger.error(
                        f"Error in getting organization name",
                        extra={
                            "device_type": "NA",
                            "device_ip": "NA",
                            "be_api_endpoint": "organization_",
                            "exception": str(e)
                        }
            )         
        return 'Internal Server Error', False


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
                logger.warning(
                        f"Invalid Login/Password",
                        extra={
                            "device_type": "NA",
                            "device_ip": "NA",
                            "be_api_endpoint": "authenticat_user",
                            "exception": ""
                        }
                ) 
                return 'Invalid Login or Password'
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
                organization_name = org_response["data"]["company_name"].replace(" ", "")
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
                        "registered_devices":[{"reachlink_hub_info": {
                                                "uuid": "reachlinkserver.net",
                                                "host_id": hub_host_id,
                                                "itemid_received": hub_item_id_received,
                                                "itemid_sent": hub_item_id_sent,
                                                "branch_location": "Reachlink_server",
                                                "hub_ip": hub_ip
                                                },
                                                "microtek_spokes_info":[],
                                                "robustel_spokes_info": [],
                                                "cisco_spokes_info": [],
                                                "ubuntu_spokes_info": []
                                                }
                                                ],
                        "organization_name": organization_name                                           
                })
                logger.info(
                        f"New organization Registered {organization_name}",
                        extra={
                            "device_type": "NA",
                            "device_ip": "NA",
                            "be_api_endpoint": "authenticat_user",
                            "exception": ""
                        }
                ) 
                return True
            else:
                logger.info(
                        f"Not Subscribed for ReachLink",
                        extra={
                            "device_type": "NA",
                            "device_ip": "NA",
                            "be_api_endpoint": "authenticat_user",
                            "exception": ""
                        }
                ) 
                return 'Not Subscribed for ReachLink'
        else:
            logger.info(
                        f"Not Subscribed for any services",
                        extra={
                            "device_type": "NA",
                            "device_ip": "NA",
                            "be_api_endpoint": "authenticat_user",
                            "exception": ""
                        }
                ) 
            return 'Not Subscribed for any services'
    except:
        logger.error(
                        f"Error during authentication",
                        extra={
                            "device_type": "NA",
                            "device_ip": "NA",
                            "be_api_endpoint": "authenticat_user",
                            "exception": str(e)
                        }
                )
        return 'Temporary issue. Please retry after some time.'


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
                return False, data
        else:
            access_token = data["access_token"]
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        user_response = requests.get(url+"users/me", headers=headers)
        if user_response.status_code == 200:
            userjson_response = user_response.json()
            print("user me info", userjson_response)
            user_info = userjson_response["data"]["user"]
            if user_info["status"] == "ACTIVE":
                data["username"] = user_info["email"]
                return user_info["org_id"], data
            else:
                return False, data
        else:
            print(user_response)
            return False, data 
    except Exception as e:
        logger.error(
                        f"Error during get organization id",
                        extra={
                            "device_type": "NA",
                            "device_ip": "NA",
                            "be_api_endpoint": "get_organization_id",
                            "exception": str(e)
                        }
                )
        return False, data

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
                               "hub_ip": data.get("dialer_ip", hub_ip)
                              })    
    return tunnel_ip          

def check_user(data, newuser):
    current_datetime = datetime.now() 
    try:  
        if "organization_id" not in data:      
            organization_id, data = get_organization_id(data)        
            print("orgid", organization_id)  
        else:
            organization_id = data["organization_id"]
        if organization_id:            
            details = coll_registered_organization.find_one({"organization_id":organization_id})
            if details:
                newuser = False                                                    
                if details["remaining_users"] > 0 and current_datetime < details["subscription_to"]:
                    registered_devices_info = details["registered_devices"]
                    expiry_date_original = str(details["subscription_to"]).split(" ")[0]                    
                    for device in registered_devices_info:                        
                        if "ciscohub" in data["uuid"]:                            
                            if "cisco_hub_info" in device:
                                if data["uuid"] == device["cisco_hub_info"]["uuid"]:
                                    response =[{ "message": 'This Cisco HUB is already Registered',
                                                "expiry_date": expiry_date_original, 
                                                "spokedevice_name":device["cisco_hub_info"]["spokedevice_name"],
                                                "organization_id":organization_id
                                                }]
                                    logger.info(
                                                f"This Cisco HUB is already Registered",
                                                extra={
                                                        "device_type": "Cisco",
                                                        "device_ip": device["cisco_hub_info"]["hub_ip"],
                                                        "be_api_endpoint": "add_cisco_hub",
                                                        "exception": ""
                                                    }
                                    )
                                    return response, newuser
                        elif "ciscodevice" in data["uuid"]:
                            if "cisco_hub_info" in device:
                                if data["dialer_ip"] == device["cisco_hub_info"]["hub_ip"].split("/")[0]:
                                    for cispoke in device["cisco_spokes_info"]:
                                        if data["uuid"] == cispoke["uuid"]:
                                            response =[{ "message": 'This Cisco Spoke is already Registered',
                                                "expiry_date": expiry_date_original, 
                                                "spokedevice_name":cispoke["spokedevice_name"],
                                                "organization_id":organization_id
                                                }]
                                            logger.info(
                                                f"This Cisco Spoke is already Registered",
                                                extra={
                                                        "device_type": "CiscoSpoke",
                                                        "device_ip": cispoke.get("dialerip", ""),
                                                        "be_api_endpoint": "add_cisco_device",
                                                        "exception": ""
                                                    }
                                            )
                                            return response, newuser
                        elif "robustel" in data["uuid"]:
                            if "reachlink_hub_info" in device:
                                for rospoke in device["robustel_spokes_info"]:
                                        if data["uuid"] == rospoke["uuid"]:
                                            response =[{ "message": 'This Robustel Spoke is already Registered',
                                                "expiry_date": expiry_date_original, 
                                                "spokedevice_name":rospoke["spokedevice_name"],
                                                "organization_id":organization_id
                                                }]
                                            logger.info(
                                                f"This Robustel Spoke is already Registered",
                                                extra={
                                                        "device_type": "Robustel",
                                                        "device_ip": rospoke["spokedevice_name"],
                                                        "be_api_endpoint": "add_cisco_device",
                                                        "exception": ""
                                                    }
                                            )
                                            return response, newuser
                        elif "microtek" in data["uuid"]:
                            if "reachlink_hub_info" in device:
                                for mispoke in device["microtek_spokes_info"]:
                                        if data["uuid"] == mispoke["uuid"]:
                                            response =[{ "message": 'This Microtek Spoke is already Registered',
                                                "expiry_date": expiry_date_original, 
                                                "spokedevice_name":mispoke["spokedevice_name"],
                                                "organization_id":organization_id,
                                                "router_username": mispoke["router_username"],
                                                "router_password": mispoke["router_password"]
                                                }]
                                            logger.info(
                                                f"This Microtek Spoke is already Registered",
                                                extra={
                                                        "device_type": "Microtek",
                                                        "device_ip": mispoke["spokedevice_name"],
                                                        "be_api_endpoint": "add_cisco_device",
                                                        "exception": ""
                                                    }
                                            )
                                            return response, newuser
                        elif "cisco_ubuntu" in data["uuid"]:
                            if "reachlink_hub_info" in device:
                                for cispoke in device["cisco_spokes_info"]:
                                        if data["uuid"] == cispoke["uuid"]:
                                            response =[{ "message": 'This Cisco Spoke is already Registered',
                                                "expiry_date": expiry_date_original, 
                                                "spokedevice_name":cispoke["spokedevice_name"],
                                                "organization_id":organization_id
                                                }]
                                            logger.info(
                                                f"This Cisco Spoke - Ubuntu hub is already Registered",
                                                extra={
                                                        "device_type": "CiscoSpoke",
                                                        "device_ip": cispoke["spokedevice_name"],
                                                        "be_api_endpoint": "add_cisco_device",
                                                        "exception": ""
                                                    }
                                            )
                                            return response, newuser
                        else:
                            if "reachlink_hub_info" in device:
                                for ubspoke in device["ubuntu_spokes_info"]:
                                        if data["uuid"] == ubspoke["uuid"]:
                                            response =[{ "message": 'This ubuntu Spoke is already Registered',
                                                "expiry_date": expiry_date_original, 
                                                "spokedevice_name":ubspoke["spokedevice_name"],
                                                "organization_id":organization_id,
                                                "gretunnel_ip":ubspoke["gretunnel_ip"], 
                                                "remote_ip":openvpnhubip, 
                                                "hub_gretunnel_endpoint":hub_tunnel_endpoint,
                                                }]
                                            logger.info(
                                                f"This ReachLink Spoke is already Registered",
                                                extra={
                                                        "device_type": "ReachLinkSpoke",
                                                        "device_ip": ubspoke["spokedevice_name"],
                                                        "be_api_endpoint": "login",
                                                        "exception": ""
                                                    }
                                            )
                                            return response, newuser
                    #length = len(registered_devices_info)+1
                    #spokedevice_name =  generate_device_name(length, details)
                    gretunnel_ip =  "None"
                    if "ciscohub" in data["uuid"]:
                        no_of_hubs = 1
                        for dev in registered_devices_info:
                            print("dev", dev)
                            if "cisco_hub_info" in dev:
                                no_of_hubs = no_of_hubs + 1
                        print("number of hubs", no_of_hubs)
                        spokedevice_name =  "ciscohub"+ str(no_of_hubs)+"-"+details["organization_name"]
                        print("spokedevice_name", spokedevice_name)                
                        new_hub_info = {"cisco_hub_info": {
                                                "uuid": data["uuid"],
                                                "spokedevice_name":  spokedevice_name,                                
                                                "hub_ip": data.get("hub_ip", ""),
                                                "branch_location": data.get("branch_location", "")
                                                },
                                            "cisco_spokes_info":[]
                                            }
                        registered_devices_info.append(new_hub_info) 
                    elif "ciscodevice" in data["uuid"]:
                        for devinfo in registered_devices_info:
                            if "cisco_hub_info" in devinfo:
                                if data["dialer_ip"] == devinfo["cisco_hub_info"]["hub_ip"].split("/")[0]:
                                    spokedevice_name =  "ciscospoke"+ str(len(devinfo["cisco_spokes_info"])+1)+"-"+details["organization_name"]
                                    new_spoke_info = {"uuid": data["uuid"],
                                                      "branch_location":data["branch_location"],
                                                      "spokedevice_name":spokedevice_name
                                                      }
                                    devinfo["cisco_spokes_info"].append(new_spoke_info)                                    
                    elif "robustel" in data["uuid"]:
                        for devinfo in registered_devices_info:
                            if "reachlink_hub_info" in devinfo:
                                spokedevice_name =  "robustelspoke"+ str(len(devinfo["robustel_spokes_info"])+1)+"-"+details["organization_name"]
                                new_spoke_info = {"uuid": data["uuid"],
                                                      "branch_location":data["branch_location"],
                                                      "spokedevice_name":spokedevice_name,
                                                      "router_username":"admin",
                                                      "router_password": "admin",
                                                      "hub_ip": hub_ip,
                                                      "tunnel_ip": "None"
                                                      
                                                      }
                                devinfo["robustel_spokes_info"].append(new_spoke_info)
                                coll_tunnel_ip.insert_one(new_spoke_info)
                    elif "microtek" in data["uuid"]:
                        for devinfo in registered_devices_info:
                            if "reachlink_hub_info" in devinfo:
                                spokedevice_name =  "microtekspoke"+ str(len(devinfo["microtek_spokes_info"])+1)+"-"+details["organization_name"]
                                routerpassword = hub_config.generate_router_password_cisco()
                                new_spoke_info = {"uuid": data["uuid"],
                                                      "branch_location":data["branch_location"],
                                                      "spokedevice_name":spokedevice_name,
                                                      "hub_ip": hub_ip,
                                                      "tunnel_ip": "None",
                                                      "public_ip": "None",
                                                      "router_username":spokedevice_name.lower(),
                                                      "router_password": routerpassword
                                                      }
                                devinfo["microtek_spokes_info"].append(new_spoke_info)
                                coll_tunnel_ip.insert_one(new_spoke_info)
                    elif "cisco_ubuntu" in data["uuid"]:
                        for devinfo in registered_devices_info:
                            if "reachlink_hub_info" in devinfo:
                                spokedevice_name =  "ciscoubuntuspoke"+ str(len(devinfo["cisco_spokes_info"])+1)+"-"+details["organization_name"]
                                new_spoke_info = {"uuid": data["uuid"],
                                                      "branch_location":data["branch_location"],
                                                      "spokedevice_name":spokedevice_name,
                                                      "hub_ip": hub_ip,
                                                      "tunnel_ip": "None",
                                                      "public_ip": "None",
                                                      "router_username":"admin",
                                                      "router_password": "admin"
                                                      }
                                devinfo["cisco_spokes_info"].append(new_spoke_info)                                
                    else:
                        for devinfo in registered_devices_info:
                            if "reachlink_hub_info" in devinfo:
                                spokedevice_name =  "ubuntuspoke"+ str(len(devinfo["ubuntu_spokes_info"])+1)+"-"+details["organization_name"]
                                gretunnel_ip =  get_tunnel_ip(data, spokedevice_name)
                                new_spoke_info = {"uuid": data["uuid"],
                                                      "branch_location":data["branch_location"],
                                                      "spokedevice_name":spokedevice_name,
                                                      "hub_ip": hub_ip,
                                                      "gretunnel_ip": gretunnel_ip,
                                                      "tunnel_ip": "None",
                                                      "public_ip": "None"
                                                       
                                                      }
                                devinfo["ubuntu_spokes_info"].append(new_spoke_info)    
                                coll_tunnel_ip.insert_one(new_spoke_info)                 
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
                    response = [{"message":"Successfully Registered",
                                 "expiry_date": expiry_date_original, 
                                 "spokedevice_name":spokedevice_name, 
                                 "gretunnel_ip":gretunnel_ip, 
                                 "remote_ip":openvpnhubip, 
                                 "hub_gretunnel_endpoint":hub_tunnel_endpoint,
                                 "organization_id":organization_id
                                 }]
                    logger.info(
                                    f"Successfully Registered",
                                    extra={
                                            "device_type": spokedevice_name,
                                            "device_ip": spokedevice_name,
                                            "be_api_endpoint": "login, add_cisco_device, add_cisco_hub",
                                            "exception": ""
                                    }
                                )
                    return response, newuser
                else:
                    userStatus = check_subscription_renewed(data, organization_id)
                    if userStatus == 'Subscribtion Renewed':
                        response = check_user_renewed(data, organization_id)
                        return response, newuser
                    else:
                        response = [{"message":"Your plan reached the limit. Pl upgrade it","expiry_date":dummy_expiry_date }]
                        logger.info(
                                    f"Plan reached the limit",
                                    extra={
                                            "device_type": "",
                                            "device_ip": "",
                                            "be_api_endpoint": "login, add_cisco_device, add_cisco_hub",
                                            "exception": ""
                                    }
                                )
                        return response, newuser
            else:
                newuser = True
                response = [{"message":"New user", "expiry_date":dummy_expiry_date }]
                return response, newuser
        else:
            newuser = False
            response =[{"message":"Not Registered", "expiry_date":dummy_expiry_date }]
            logger.info(
                        f"Not Registered",
                        extra={
                                "device_type": "",
                                "device_ip": "",
                                "be_api_endpoint": "login, add_cisco_device, add_cisco_hub",
                                "exception": ""
                            }
            )
            return response, newuser
    except Exception as e:
        print("Error:", e)
        logger.error(
                        f"Error during check user",
                        extra={
                                "device_type": "",
                                "device_ip": "",
                                "be_api_endpoint": "login, add_cisco_device, add_cisco_hub",
                                "exception": str(e)
                            }
            )
        response =[{"message":"Internal Server Error", "expiry_date":dummy_expiry_date }]
        return response, newuser
  
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
                        response =[{ "message": 'This device is already Registered', 
                                    "expiry_date": expiry_date_original, 
                                    "spokedevice_name":device["spokedevice_name"], 
                                    "gretunnel_ip":device["gretunnel_ip"], 
                                    "remote_ip":openvpnhubip, 
                                    "hub_gretunnel_endpoint":hub_tunnel_endpoint,
                                    "organization_id":organization_id
                                    }]
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
                response = [{"message":"Successfully Registered", 
                             "expiry_date": expiry_date_original, 
                             "spokedevice_name":spokedevice_name, 
                             "gretunnel_ip":gretunnel_ip, 
                             "remote_ip":openvpnhubip, 
                             "hub_gretunnel_endpoint":hub_tunnel_endpoint,
                             "organization_id":organization_id
                             }]
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
                    new_remaining_users = int(subsjson_response["data"]["users"]) - details["total_users"] + details["remaining_users"]
                    if details["subscription_to"] != to_date or new_remaining_users > 0:
                        query = {"organization_id": organization_id }
                        update_data = {"$set": 
                                       {"subscription_from": from_date, 
                                        "subscription_to": to_date,
                                        "total_users": subsjson_response["data"]["users"],
                                        "remaining_users": new_remaining_users                                    
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
    
def check_onboarding(username, password):
    try:
        data_login = {
                    "email": username,
                    "password": password
                 }
        # Send a POST request with the data
        login_response = requests.post(url+"auth/login", json=data_login)
        if login_response.status_code == 200:
        # Parse the JSON response
            loginjson_response = login_response.json()
            access_token = loginjson_response["data"]["access_token"]
        else:
            return 'Invalid Login & password'
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        user_response = requests.get(url+"users/me", headers=headers)
        if user_response.status_code == 200:
            userjson_response = user_response.json()            
            user_info = userjson_response["data"]["user"]
            user_role = user_info["role"]
        service_response = requests.get(url+"services/", headers=headers)
        if service_response.status_code == 200:
            servicejson_response = service_response.json()
            services_info = servicejson_response["data"]["services"]
            subscription_status = False
            for service in services_info:
                if service["name"] == "link":
                    subscription_status = True
            if subscription_status:
                current_datetime = datetime.now() 
                subscription_response = requests.get(url+"subscription_transactions/current", headers=headers)
                subsjson_response = subscription_response.json()
                timestamp = int(subsjson_response["data"]["created_at"])
                # Convert Unix timestamp to datetime
                from_date = datetime.utcfromtimestamp(timestamp)
                # Add Duration to get to_date
                to_date = from_date + relativedelta(months=int(subsjson_response["data"]["duration"]))
                if current_datetime < to_date:
                    return 'True', user_role
            else:
                    return 'Not Subscribed for ReachLink', False
        else:
                return 'Not Subscribed for any services', False
    except:
        return 'Internal Server Error', False
    
def check_login_onboarding(username, password):
    try:
        data_login = {
                    "email": username,
                    "password": password
                 }
        # Send a POST request with the data
        login_response = requests.post(url+"auth/login", json=data_login)
        if login_response.status_code == 200:
        # Parse the JSON response
            loginjson_response = login_response.json()
            access_token = loginjson_response["data"]["access_token"]
        else:
            return 'Invalid Login & password'
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        user_response = requests.get(url+"users/me", headers=headers)
        if user_response.status_code == 200:
            userjson_response = user_response.json()            
            user_info = userjson_response["data"]["user"]
            user_role = user_info["role"]
            org_id = user_info["org_id"]
            user_id = user_info["id"]
            first_name = user_info["first_name"]
            last_name = user_info["last_name"]
        get_organization_name = requests.get(url+"org/", headers=headers)
        org_response = get_organization_name.json()
        org_name = org_response["data"]["company_name"].replace(" ", "")
        service_response = requests.get(url+"services/", headers=headers)
        if service_response.status_code == 200:
            servicejson_response = service_response.json()
            services_info = servicejson_response["data"]["services"]
            subscription_status = False
            for service in services_info:
                if service["name"] == "link":
                    subscription_status = True
            if subscription_status:
                current_datetime = datetime.now() 
                subscription_response = requests.get(url+"subscription_transactions/current", headers=headers)
                subsjson_response = subscription_response.json()
                timestamp = int(subsjson_response["data"]["created_at"])
                # Convert Unix timestamp to datetime
                from_date = datetime.utcfromtimestamp(timestamp)
                # Add Duration to get to_date
                to_date = from_date + relativedelta(months=int(subsjson_response["data"]["duration"]))
                if current_datetime < to_date:                               
                    return 'True', user_role, org_id, user_id, first_name, last_name, org_name, str(to_date)
            else:
                    return 'Not Subscribed for ReachLink', False, False, False, False, False, False, False
        else:
                return 'Not Subscribed for any services', False, False, False, False, False, False, False
    except Exception as e:
        logger.error(f"New user: {username} not added.",
                            extra={                
                                "be_api_endpoint": "login",
                                "exception": str(e)
                            }
                    )  
        return str(e), False, False, False, False, False, False, False
    
def check_login_onboarding_new(username, password):
    try:
        data_login = {
                    "email": username,
                    "password": password
                 }
        # Send a POST request with the data
        login_response = requests.post(url+"auth/login", json=data_login)
        if login_response.status_code == 200:
        # Parse the JSON response
            loginjson_response = login_response.json()
            access_token = loginjson_response["data"]["access_token"]
        else:
            return 'Invalid Login & password', False, False, False, False, False, False, False
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        user_response = requests.get(url+"users/me", headers=headers)
        current_datetime = datetime.now() 
        if user_response.status_code == 200:
            userjson_response = user_response.json()            
            user_info = userjson_response["data"]["user"]
            user_role = user_info["role"]
            org_id = user_info["org_id"]
            user_id = user_info["id"]
            first_name = user_info["first_name"]
            last_name = user_info["last_name"]
            details = coll_registered_organization.find_one({"organization_id":org_id})
            if details:
                if current_datetime < details["subscription_to"]:
                    registered_users = details["regusers"]
                    user_already_reg = False
                    for reguser in registered_users:
                        if reguser["username"] == username:
                            user_already_reg = True
                            break
                    if not user_already_reg:
                        registered_users.append({"username":username,
                                                "userid":user_id,
                                                "first_name":first_name,
                                                "last_name": last_name,
                                                "user_role": user_role
                                            })
                        query = {"organization_id": org_id}
                        update_data = {"$set": {"regusers": registered_users}
                                       }
                        coll_registered_organization.update_many(query, update_data)
                    org_name = details["organization_name"]
                    return 'True', user_role, org_id, user_id, first_name, last_name, org_name, str(details["subscription_to"])        
            else:
                get_organization_name = requests.get(url+"org/", headers=headers)
                org_response = get_organization_name.json()
                org_name = org_response["data"]["company_name"].replace(" ", "")
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
                        if current_datetime < to_date:
                            coll_registered_organization.insert_one({
                                "organization_id": subsjson_response["data"]["org_id"],
                                "regusers": [{  "username":username,
                                                "userid":user_id,
                                                "first_name":first_name,
                                                "last_name": last_name,
                                                "user_role": user_role
                                            }],
                                "subscription_from":from_date,
                                "subscription_to":to_date,                        
                                "total_users": subsjson_response["data"]["users"],
                                "remaining_users": subsjson_response["data"]["users"],
                                "registered_devices":[{"reachlink_hub_info": {
                                                "uuid": "reachlinkserver.net",
                                                "host_id": hub_host_id,
                                                "itemid_received": hub_item_id_received,
                                                "itemid_sent": hub_item_id_sent,
                                                "branch_location": "Reachlink_server",
                                                "hub_ip": hub_ip
                                                },
                                                "microtek_spokes_info":[],
                                                "robustel_spokes_info": [],
                                                "cisco_spokes_info": [],
                                                "ubuntu_spokes_info": []
                                                }
                                                ],
                                "organization_name": org_name                                           
                                })
                            return 'True', user_role, org_id, user_id, first_name, last_name, org_name, str(to_date)
                        else:
                            return 'Subscription expired', False, False, False, False, False, False, False
                    else:
                        return 'Not Subscribed for ReachLink', False, False, False, False, False, False, False
                else:
                    return 'Not Subscribed for any services', False, False, False, False, False, False, False
        else:
            return 'Error in getting User Info', False, False, False, False, False, False, False
    except Exception as e:
        return str(e), False, False, False, False, False, False, False

def check_subscription_renewed_login(username, password, organization_id):
    try:
        data_login = {
                    "email": username,
                    "password": password
                 }
            # Send a POST request with the data
        login_response = requests.post(url+"auth/login", json=data_login)
        if login_response.status_code == 200:
            # Parse the JSON response
            loginjson_response = login_response.json()
            access_token = loginjson_response["data"]["access_token"]
        else:
            return "Invalid login & password"        
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
                    new_remaining_users = int(subsjson_response["data"]["users"]) - details["total_users"] + details["remaining_users"]
                    if details["subscription_to"] != to_date or new_remaining_users > 0:
                        query = {"organization_id": organization_id }
                        update_data = {"$set": 
                                       {"subscription_from": from_date, 
                                        "subscription_to": to_date,
                                        "total_users": subsjson_response["data"]["users"],
                                        "remaining_users": new_remaining_users                                    
                                        }
                                       }
                        coll_registered_organization.update_many(query, update_data)
                        return True, "subscription_renewed", to_date
            else:
                return False, "Not subscribed for ReachLink", False
        else:
            return False, "not subscribed for any services", False         
    except:
        return False, "Internal Server Error", False

def get_microtek_config(data):
    current_datetime = datetime.now()
    try:
        details = coll_registered_organization.find_one({"organization_id":data["orgid"]})
        if details:                                                   
            if current_datetime < details["subscription_to"]:
                registered_devices_info = details["registered_devices"]  
                expiry_date_original = str(details["subscription_to"]).split(" ")[0]                 
                for devices in registered_devices_info:
                    if "microtek_spokes_info" in devices:
                        for device in devices["microtek_spokes_info"]:
                            if device['uuid'] == data["uuid"]:  
                                response =[{ "message": 'This Microtek Spoke is already Registered',
                                                "expiry_date": expiry_date_original, 
                                                "spokedevice_name":device["spokedevice_name"],
                                                "organization_id":data["orgid"],
                                                "router_username": device["router_username"],
                                                "router_password": device["router_password"]
                                                }]                                   
                                return response
                        response = [{"message": f"This Branch location ({data['branch_loc']}) was not configured in {data['orgname']} organization."}]
            else:
                response = [{"message": "Your subscription was expired. Kindly renew it"}]
        else:
            response = [{"message": "This organization is not registered with ReachLink"}]  
        logger.error(f"{response}",
                    extra={ "be_api_endpoint": "get_microtek_config",
                           "exception": ""}
                    )       
    except Exception as e:
        logger.error(f"Error in get Microtek spoke",
                    extra={ "be_api_endpoint": "get_microtek_config",
                           "exception": str(e)}
                    )
        response = [{"message": "Some internal error. Pl try again"}]
    return response

def get_robustel_config(data):
    current_datetime = datetime.now()
    try:
        details = coll_registered_organization.find_one({"organization_id":data["orgid"]})
        if details:                                                   
            if current_datetime < details["subscription_to"]:
                registered_devices_info = details["registered_devices"]  
                expiry_date_original = str(details["subscription_to"]).split(" ")[0]                 
                for devices in registered_devices_info:
                    if "robustel_spokes_info" in devices:
                        for device in devices["robustel_spokes_info"]:
                            if device['uuid'] == data["uuid"]:  
                                response =[{ "message": 'This Robustel Spoke is already Registered',
                                                "expiry_date": expiry_date_original, 
                                                "spokedevice_name":device["spokedevice_name"],
                                                "organization_id":data["orgid"],
                                                "router_username": device["router_username"],
                                                "router_password": device["router_password"]
                                                }]                                   
                                return response
                        response = [{"message": f"This Branch location ({data['branch_loc']}) was not configured in {data['orgname']} organization."}]
            else:
                response = [{"message": "Your subscription was expired. Kindly renew it"}]
        else:
            response = [{"message": "This organization is not registered with ReachLink"}]  
        logger.error(f"{response}",
                    extra={ "be_api_endpoint": "get_robustel_config",
                           "exception": ""}
                    )       
    except Exception as e:
        logger.error(f"Error in get Microtek spoke",
                    extra={ "be_api_endpoint": "get_robustel_config",
                           "exception": str(e)}
                    )
        response = [{"message": "Some internal error. Pl try again"}]
    return response