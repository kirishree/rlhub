import json
import requests
import router_configure
import pymongo
import subprocess
import os
import threading
from decouple import config
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_registered_organization = db_tunnel["registered_organization"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]

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


def delsubnet(data):
    try:     
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
    return response, 
