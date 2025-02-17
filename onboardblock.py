import requests
from datetime import datetime
from dateutil.relativedelta import relativedelta
import pymongo
import random
import json
import ipaddress
import os
import subprocess
import threading
from decouple import config
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_spoke_disconnect = db_tunnel["spoke_disconnect"]
coll_registered_organization = db_tunnel["registered_organization"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]

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

def onboard_unblock(data):    
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
    return response  

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

def onboard_block(data):
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
    return response

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

def onboard_delete(data):
    background_thread = threading.Thread(target=background_delete, args=(data,))
    background_thread.start()    
    return 

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

def spoke_update(data):
    response = [{"message": "Organization spokes updated successfully"}]
    background_thread = threading.Thread(target=background_update, args=(data,))
    background_thread.start()    
    return response