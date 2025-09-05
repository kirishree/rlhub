from django.http import HttpRequest, HttpResponse,  JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
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
import json
import logging
from decouple import config
import pymongo
logger = logging.getLogger('reachlink')
import os
import ipaddress
import onboarding
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
snmpcommunitystring = config('SNMP_COMMUNITY_STRING')
hub_ip = config('HUB_IP')
dummy_expiry_date = ""
import hub_config
import microtek_hub
reachlink_zabbix_path = config('REACHLINK_ZABBIX_PATH')
newuser = False

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_microtik_hub(request: HttpRequest):
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
                json_response = [{"message": f"Error: This Overlay network ID already available, pl choose different one."}]                
                logger.error(
                            "Error: This Overlay network ID already available",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": "",
                                "be_api_endpoint": "configure Microtek HUB",
                                "exception": ""
                            }
                        )             
                response = HttpResponse(content_type='application/zip')
                response['X-Message'] = json.dumps(json_response)
                response["Access-Control-Expose-Headers"] = "X-Message"
                return response
    orgstatus = False
    #print("Microtek hub data", data)    
    if "organization_id" in data:
        org_info = coll_registered_organization.find_one({"organization_id": data["organization_id"]})
        if org_info:
            orgname = org_info["organization_name"]
            data["username"] = org_info["regusers"][0]["username"]
            orgstatus = True
        else:
            orgstatus = False
    #elif "access_token" in data:
    #    print("hiiiiiii")
    #    orgname, orgstatus = onboarding.organization_name(data)
    #    print(orgname, orgstatus)
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
        return JsonResponse(json_response, safe=False, status=500)
    
    data["uuid"] = data['branch_location'] + f"_{orgname}_microtikhub.net"
    #data["username"] = "none"
    #data["password"] = "none" 
    global newuser
    try:
        response, newuser = onboarding.check_user(data, newuser)        
        if newuser:
            userStatus = onboarding.authenticate_user(data)            
            if userStatus:
                response, newuser = onboarding.check_user(data, newuser)
            else:
                response = [{"message": userStatus,"expiry_date": dummy_expiry_date}]        
        if response[0]["message"] == "Successfully Registered" or response[0]["message"] == "This Microtik HUB is already Registered":
            devicename = response[0]["spokedevice_name"]   
            #ping the dialer ip if it is reachable, already configured
            

            #No, still not configured.
            
            configuredhubinfo = coll_hub_info.find_one({"uuid": data["uuid"]})            
            coll_tunnel_ip.delete_many({"uuid":data["uuid"]}) 
            devicehubinfo = {}           
            if  configuredhubinfo: #old HUB
                devicehubinfo["router_password"] = configuredhubinfo["router_password"]                
                devicehubinfo["router_username"] = configuredhubinfo["router_username"]                
            else:
                devicehubinfo["router_password"] = hub_config.generate_router_password_cisco()
                devicehubinfo["router_username"] = devicename.lower() 
            data["new_username"] =  devicehubinfo["router_username"]
            data["new_password"] =  devicehubinfo["router_password"]
            data["snmpcommunitystring"] = snmpcommunitystring
            status = microtek_hub.openvpnserverconfig(data)    
            if not status:
                logger.error(
                            f"Error while configuring HUB",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure Microtik HUB",
                                "exception": ""
                            }
                        ) 
                json_response = [{"message": f"Error:Internal Server Error, pl try again!"}]    
                return JsonResponse(json_response, safe=False)
            
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
                                                'branch_location': data["branch_location"],
                                                "hub_dialer_ip_cidr": data["hub_dialer_ip"]
                                                }
                                        }, #update
                                        upsert=True                  # this enables "insert if not found"
                                        ) 
            organizationid = response[0]["organization_id"]
            regdevices = coll_registered_organization.find_one({"organization_id":organizationid}) 
            for dev in regdevices["registered_devices"]:                    
                if "microtik_hub_info" in dev:
                    if data["uuid"] == dev["microtik_hub_info"]["uuid"]:
                            dev["microtik_hub_info"]["router_username"] = devicehubinfo["router_username"]
                            dev["microtik_hub_info"]["router_password"] = devicehubinfo["router_password"]
                            dev["microtik_hub_info"]["hubdevice_name"] = devicename
                            dev["microtik_hub_info"]["hub_dialer_ip"] =  devicehubinfo["hub_dialer_ip"]
                            dev["microtik_hub_info"]["hub_dialer_netmask"] = devicehubinfo["hub_dialer_netmask"]
                            dev["microtik_hub_info"]["hub_dialer_network"] = devicehubinfo["hub_dialer_network"]
                            dev["microtik_hub_info"]["hub_ip"] = data["hub_ip"]
                            dev["microtik_hub_info"]["hub_wan_ip_only"] = devicehubinfo["hub_wan_ip_only"]
                            dev["microtik_hub_info"]["hub_wan_ip_netmask"] = devicehubinfo["hub_wan_ip_netmask"]
                                                
                            dev["microtik_hub_info"]["hub_dialer_ip_cidr"] = data["hub_dialer_ip"]
            query = {"organization_id": organizationid}
            update_data = {"$set": {
                                        "registered_devices": regdevices["registered_devices"]                                                                           
                                        }
                                       }
            coll_registered_organization.update_many(query, update_data)
            #os.system(cp ../client.ovpn /etc/openvpn/client/client.conf)
            #os.system("systemctl openvpn-client@client.service")
            os.system(f"python3 {reachlink_zabbix_path}")                
            os.system("systemctl restart reachlink_test")             
            logger.info(
                            f"{response[0]['message']}:{devicename}",
                            extra={
                                "device_type": "ReachlinkServer",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "configure Microtik HUB",
                                "exception": ""
                            }
                        )
            json_response = [{"message": f"Microtik HUB Configured Successfully"}]
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
    
    return JsonResponse(json_response, safe=False)
