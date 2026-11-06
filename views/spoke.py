import json
import requests
from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
import logging
logger = logging.getLogger('reachlink')
from django.core.cache import cache
import router_configure
import microtek_configure
import robustel_configure
import hub_config
import jwt
import onboarding
import pymongo
from decouple import config
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
m2m_exe_path = config('M2M_EXE_PATH')


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


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_m2mspoke_config(request: HttpRequest):    
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
    
    data["uuid"] = data['branch_loc'] + f"_{orgname}_m2m.net"
    data["orgid"] = orgid
    data["orgname"] = orgname
    response = onboarding.get_m2mspoke_config(data)
    if "This Microtek Spoke is already Registered" in response[0]["message"]:           
        spokedetails = {"spokedevice_name": response[0]["spokedevice_name"],
                        "router_username": response[0]["router_username"],
                        "router_password": response[0]["router_password"],
                        "hub_ip":response[0]["hub_ip"],
                        "message": response[0]["message"],
                        "snmpcommunitystring": snmpcommunitystring
                        }        
        #setass_task.apply_async(args=[response, "microtek"], countdown=60)
    else:
        spokedetails= {"message": response[0]["message"]}    
    return JsonResponse(spokedetails, safe=False)



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
            if (validate_ip(int_addr)):
                continue
            else:
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                return JsonResponse(response, safe=False)
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
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.createvlaninterface(data)                 
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.createvlaninterface(data)   
        elif "robustel" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = robustel_configure.createvlaninterface(data) 
    except Exception as e:          
        logger.error(f"Error: Create VLAN interface in HUB:{e}")
        response = [{"message": f"Error: While creating VLAN interface"}]
    return JsonResponse(response, safe=False)


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


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_firewall_filter_details_spoke(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_firewall_details" }
                    )
        branch_id = data["tunnel_ip"].split("/")[0]
        cache_key = f"firewall_branch_{branch_id}"
        firewall_details = cache.get(cache_key)
        if firewall_details:
            return JsonResponse(firewall_details, safe=False)
        firewall_details = []
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
                response = requests.get(url + "get_firewall_details")                                
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    firewall_details = json.loads(get_response)
                    #print(response)      
                else:
                    firewall_details =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")  
                logger.error(f"Connection timeout ",
                     extra={
                                "device_type": "ReachlinkSpoke",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "get_firewall_info",
                                "exception": str(e)
                            }
                    )     
                firewall_details =[]         
        elif "microtek" in data["uuid"]:           
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            firewall_details = microtek_configure.firewalldetails(data)                 
            #return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #interface_details = router_configure.get_interface_cisco(data)
            firewall_details = []
        elif "robustel" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #interface_details = robustel_configure.get_interface_robustel(data)
            firewall_details = []
        # Store in cache for 60 seconds
        cache.set(cache_key, firewall_details, timeout=60)
    except Exception as e:
        logger.error(f"{str(e)} ",
                     extra={
                                "device_type": "",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "get_firewall_info",
                                "exception": str(e)
                            }
                    )        
    return JsonResponse(firewall_details, safe=False)



#Firewall for Microtek
@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_firewall_nat_details_spoke(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_firewall_nat_details" }
                    )
        branch_id = data["tunnel_ip"].split("/")[0]
        cache_key = f"firewall_nat_branch_{branch_id}"
        firewall_details = cache.get(cache_key)
        if firewall_details:
            return JsonResponse(firewall_details, safe=False)
        firewall_details = []
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
                response = requests.get(url + "get_firewall_nat_details")                                
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    firewall_details = json.loads(get_response)
                    #print(response)      
                else:
                    firewall_details =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")  
                logger.error(f"Connection timeout ",
                     extra={
                                "device_type": "ReachlinkSpoke",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "get_firewall_nat_info",
                                "exception": str(e)
                            }
                    )     
                firewall_details =[]         
        elif "microtek" in data["uuid"]:           
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            firewall_details = microtek_configure.firewallnatdetails(data)                 
            #return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #interface_details = router_configure.get_interface_cisco(data)
            firewall_details = []
        elif "robustel" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #interface_details = robustel_configure.get_interface_robustel(data)
            firewall_details = []
        # Store in cache for 60 seconds
        cache.set(cache_key, firewall_details, timeout=60)
    except Exception as e:
        logger.error(f"{str(e)} ",
                     extra={
                                "device_type": "",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "get_firewall_nat_info",
                                "exception": str(e)
                            }
                    )        
    return JsonResponse(firewall_details, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def get_blocked_app_details_spoke(request):
    try:
        data = json.loads(request.body)
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "get_blocked_app_details" }
                    )
        branch_id = data["tunnel_ip"].split("/")[0]
        cache_key = f"blocked_app_branch_{branch_id}"
        app_details = cache.get(cache_key)
        if app_details:
            return JsonResponse(app_details, safe=False)
        app_details = []
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
                response = requests.get(url + "get_blocked_app_details")                                
                if response.status_code == 200:           
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    app_details = json.loads(get_response)
                    #print(response)      
                else:
                    app_details =[]
            except requests.exceptions.RequestException as e:
                print("disconnected")  
                logger.error(f"Connection timeout ",
                     extra={
                                "device_type": "ReachlinkSpoke",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "get_blocked_app_info",
                                "exception": str(e)
                            }
                    )     
                app_details =[]         
        elif "microtek" in data["uuid"]:           
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            app_details = microtek_configure.blockedappdetails(data)                 
            #return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #interface_details = router_configure.get_interface_cisco(data)
            app_details = []
        elif "robustel" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #interface_details = robustel_configure.get_interface_robustel(data)
            app_details = []
        # Store in cache for 60 seconds
        cache.set(cache_key, app_details, timeout=60)
    except Exception as e:
        logger.error(f"{str(e)} ",
                     extra={
                                "device_type": "",
                                "device_ip": hub_ip,
                                "be_api_endpoint": "get_blocked_app_info",
                                "exception": str(e)
                            }
                    )        
    return JsonResponse(app_details, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def add_app_spoke(request):
    try:
        data = json.loads(request.body)
        print(data)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "add_app_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"blocked_app_branch_{branch_id}"        
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
                response = requests.post(url + "app_config", data=json_data, headers=headers)                           
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
            app_details = microtek_configure.addapp(data)                 
            return JsonResponse(app_details,safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #response = router_configure.interfaceconfig(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            #response = robustel_configure.interface_config(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
    except Exception as e:
        logger.error(f"Error: Configure app Spoke:{e}")
        response = [{"message": f"Error: while configuring interface"}]
    return JsonResponse(response, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def add_firewall_filter_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "add_firewall_filter_rule_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"firewall_branch_{branch_id}"              
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
                response = requests.post(url + "app_config", data=json_data, headers=headers)                           
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
            response = microtek_configure.addfirewallrule(data)                 
            return JsonResponse(response, safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #response = router_configure.interfaceconfig(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            #response = robustel_configure.interface_config(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
    except Exception as e:
        logger.error(f"Error: Add Firewall Filter Rule in Spoke:{e}")
        response = [{"message": f"Error: while adding filter rule"}]
    return JsonResponse(response, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def add_firewall_nat_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "add_firewall_nat_rule_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"firewall_nat_branch_{branch_id}"            
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
                response = requests.post(url + "app_config", data=json_data, headers=headers)                           
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
            response = microtek_configure.addfirewallnatrule(data)                 
            return JsonResponse(response, safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #response = router_configure.interfaceconfig(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            #response = robustel_configure.interface_config(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
    except Exception as e:
        logger.error(f"Error: Add Firewall NAT Rule in Spoke:{e}")
        response = [{"message": f"Error: while adding Filter NAT rule"}]
    return JsonResponse(response, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def del_app_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "del_app_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"blocked_app_branch_{branch_id}"              
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
                response = requests.post(url + "app_config", data=json_data, headers=headers)                           
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
            response = microtek_configure.delapprule(data)                 
            return JsonResponse(response, safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #response = router_configure.interfaceconfig(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            #response = robustel_configure.interface_config(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
    except Exception as e:
        logger.error(f"Error: Remove App Rule in Spoke:{e}")
        response = [{"message": f"Error: while removing App rule"}]
    return JsonResponse(response, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def del_filter_rule_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "del_filter_rule_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"firewall_branch_{branch_id}"               
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
                response = requests.post(url + "app_config", data=json_data, headers=headers)                           
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
            response = microtek_configure.delfilterrule(data)                 
            return JsonResponse(response, safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #response = router_configure.interfaceconfig(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            #response = robustel_configure.interface_config(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
    except Exception as e:
        logger.error(f"Error: Remove Filter Rule Rule in Spoke:{e}")
        response = [{"message": f"Error: while deleting filter rule"}]
    return JsonResponse(response, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def del_nat_rule_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "del_nat_rule_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"firewall_nat_branch_{branch_id}"            
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
                response = requests.post(url + "app_config", data=json_data, headers=headers)                           
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
            response = microtek_configure.delnatrule(data)                 
            return JsonResponse(response, safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #response = router_configure.interfaceconfig(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            #response = robustel_configure.interface_config(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
    except Exception as e:
        logger.error(f"Error: Remove NAT Rule in Spoke:{e}")
        response = [{"message": f"Error: while deleting NAT rule"}]
    return JsonResponse(response, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def move_filter_rule_spoke(request):
    try:
        data = json.loads(request.body)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "move_filter_rule_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0]         
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
                response = requests.post(url + "app_config", data=json_data, headers=headers)                           
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
            response = microtek_configure.movefilterrule(data)    
            cache_key = f"firewall_branch_{branch_id}"               
            cache.delete(cache_key)             
            return JsonResponse(response, safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #response = router_configure.interfaceconfig(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            #response = robustel_configure.interface_config(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
    except Exception as e:
        logger.error(f"Error: Move Filter Rule Rule in Spoke:{e}")
        response = [{"message": f"Error: while moving filter rule"}]
    return JsonResponse(response, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def edit_filter_rule_spoke(request):
    try:
        data = json.loads(request.body)        
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "del_nat_rule_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"firewall_branch_{branch_id}"         
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
                response = requests.post(url + "app_config", data=json_data, headers=headers)                           
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
            response = microtek_configure.editfilterrule(data)                 
            return JsonResponse(response, safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #response = router_configure.interfaceconfig(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            #response = robustel_configure.interface_config(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
    except Exception as e:
        logger.error(f"Error: Edit NAT Rle in Spoke:{e}")
        response = [{"message": f"Error: while editting firewall rule"}]
    return JsonResponse(response, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def edit_nat_rule_spoke(request):
    try:
        data = json.loads(request.body)
        #print(data)
        # Capture the public IP from the request headers
        public_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        logger.debug(f"Requested_ip:{public_ip}, payload: {data}",
                    extra={ "be_api_endpoint": "edit_nat_rule_spoke" }                    
                    )
        branch_id = data["tunnel_ip"].split("/")[0] 
        cache_key = f"firewall_nat_branch_{branch_id}"      
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
                response = requests.post(url + "app_config", data=json_data, headers=headers)                           
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
            response = microtek_configure.editnatrule(data)                 
            return JsonResponse(response, safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            #response = router_configure.interfaceconfig(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
        elif "robustel" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            data["spokedevice_name"] = router_info["spokedevice_name"]
            #response = robustel_configure.interface_config(data)
            response = [{"message": f"Error: This device doesn't support this feature"}]
            print(response)
    except Exception as e:
        logger.error(f"Error: Edit NAT Rule in Spoke:{e}")
        response = [{"message": f"Error: while editing NAT rule"}]
    return JsonResponse(response, safe=False)


@api_view(['POST'])  
@permission_classes([IsAuthenticated])
def vlan_interface_delete_spoke(request):
    try:
        data = json.loads(request.body)
        print("vlan delete ", data)
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
            elif "." in data['intfc_name']:
                response = microtek_configure.deletevlaninterface(data) 
            else:
                response = microtek_configure.deletetunnelinterface(data)             
            return JsonResponse(response,safe=False) 
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
        logger.error(f"Error: Delete Interface Spoke:{e}")
        response = [{"message": f"Error: "}]
    return JsonResponse(response, safe=False)


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
            return JsonResponse(response, safe=False)
        for int_addr in data["addresses"]:
            if (validate_ip(int_addr)):
                continue
            else:
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                return JsonResponse(response, safe=False)
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
        logger.error(f"Error: Create Loopback Interface Spoke:{e}")
        response = [{"message": f"Error: while creating Loopback Interface"}]
    return JsonResponse(response, safe=False)


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
            return JsonResponse(response, safe=False)
        for int_addr in data["addresses"]:
            if (validate_ip(int_addr)):
                continue
            else:
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                return JsonResponse(response, safe=False)
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
        response = [{"message": f"Error: while creating Sub interface"}]
        logger.error(f"Error: Create Sub Interface spoke:{e}")
    return JsonResponse(response, safe=False)


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
            return JsonResponse(response, safe=False)
        for int_addr in data["addresses"]:
            if (validate_ip(int_addr)):
                continue
            else:
                response = [{"message": f"Error: {int_addr} is invalid IP"}]
                return JsonResponse(response, safe=False)
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
                if response.status_code == 200:           
                    print(response.text)
                    get_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                    response = json.loads(get_response)         
                else:
                    response = [{"message":"Error while configuring VLAN interface in spoke"}]
            except requests.exceptions.RequestException as e:
                print("disconnected")
                response = [{"message":"Error:Tunnel disconnected in the middle. So pl try again"}]   
        elif "microtek" in data["uuid"]:
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            interface_details = microtek_configure.createtunnelinterface(data)   
            #interface_details = [{"message":"Tunnel interface created successfully"}]              
            return JsonResponse(interface_details,safe=False) 
        elif "cisco" in data["uuid"]:            
            #router_info = coll_tunnel_ip.find_one({"uuid":data["uuid"]})
            data["router_username"] = router_info["router_username"]
            data["router_password"] = router_info["router_password"]
            response = router_configure.createtunnelinterface(data)                   
    except Exception as e:
        logger.error(f"Error: Create Tunnel Interface Spoke:{e}")
        response = [{"message": f"Error: While craeting Tunnel interface"}]
    return JsonResponse(response, safe=False)


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