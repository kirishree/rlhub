
from django.http import HttpRequest, HttpResponse,  JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
import json 
import logging
logger = logging.getLogger('reachlink')
from django.core.cache import cache
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