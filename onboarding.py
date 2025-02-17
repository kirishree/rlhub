import requests
from datetime import datetime
from dateutil.relativedelta import relativedelta
import pymongo
import random
import json
import ipaddress
import os
import subprocess
from decouple import config
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_spoke_disconnect = db_tunnel["spoke_disconnect"]
coll_registered_organization = db_tunnel["registered_organization"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]

url = "https://dev-api.cloudetel.com/api/v1/"
openvpnhubip = "10.8.0.1"
hub_tunnel_endpoint = "10.200.202.2"
dummy_expiry_date = ""
gretunnelnetworkip = "10.200.202."

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

def check_user(data, newuser):
    current_datetime = datetime.now() 
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
                            response =[{ "message": 'This device is already Registered',
                                         "expiry_date": expiry_date_original, 
                                         "spokedevice_name":device["spokedevice_name"],
                                         "gretunnel_ip":device["gretunnel_ip"],
                                         "remote_ip":openvpnhubip, 
                                         "hub_gretunnel_endpoint":hub_tunnel_endpoint,
                                         "organization_id":organization_id
                                         }]
                            return response, newuser
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
                    response = [{"message":"Successfully Registered",
                                 "expiry_date": expiry_date_original, 
                                 "spokedevice_name":spokedevice_name, 
                                 "gretunnel_ip":gretunnel_ip, 
                                 "remote_ip":openvpnhubip, 
                                 "hub_gretunnel_endpoint":hub_tunnel_endpoint,
                                 "organization_id":organization_id
                                 }]
                    return response, newuser
                else:
                    userStatus = check_subscription_renewed(data, organization_id)
                    if userStatus == 'Subscribtion Renewed':
                        response = check_user_renewed(data, organization_id)
                        return response, newuser
                    else:
                        response = [{"message":"Your plan reached the limit. Pl upgrade it","expiry_date":dummy_expiry_date }]
                        return response, newuser
            else:
                newuser = True
                response = [{"message":"New user", "expiry_date":dummy_expiry_date }]
                return response, newuser
        else:
            newuser = False
            response =[{"message":"Not Registered", "expiry_date":dummy_expiry_date }]
            return response, newuser
    except Exception as e:
        print("Error:", e)
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
