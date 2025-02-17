import os
import subprocess
import socket
import json
import requests
import microtek_configure
import router_configure
import ipaddress
import threading
from netaddr import IPAddress
import psutil
from pyroute2 import IPRoute
from decouple import config
import onboarding
import pymongo
import yaml
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]
coll_spoke_active = db_tunnel["spoke_active"]
coll_spoke_inactive = db_tunnel["spoke_inactive"]
coll_spoke_disconnect = db_tunnel["spoke_disconnect"]
vrf1_ip = '10.200.202.0/24'

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
def get_routing_table_ubuntu():
    response = []
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
    return response 

def deactivate(data):
    try:
        
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
    except Exception as e:
        print(e)
        response = {"message":f"Error:while deactivating data['tunnel_ip']"}                  
    return response

def activate(data):
    try:       
        response = {"message":f"Successfully activating...: {data['tunnel_ip']}"}
        tunnel_ip = data["tunnel_ip"].split("/")[0]   
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
    return response

def diagnostics(data):
    ip_addresses = [data["subnet"].split("/")[0]]
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
            return response
        except subprocess.CalledProcessError:
            rtt_avg = -1
    response ={"message": f"Error: Subnet {data['subnet']} not Reachable"}
    return response

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
    return response

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

def addstaticroute_ubuntu(data):
    try:
        real_routes = []
        past_subnets = []
        routes = data["routes_info"] 
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
        print(e)
        response = {"message": "Error while adding route"}
    return response

def get_interface_details_ubuntu(data):
    try:
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
        response = []
    return response

def addsubnet(data):
    try:       
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
            background_thread = threading.Thread(target=configurepbr_spoke, args=(pbr_spoke_data,))
            background_thread.start()     
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

def interface_config(data):  
    try:
        if data["intfc_name"] == "enp0s3" or data["intfc_name"] == "Base Tunnel" or data["intfc_name"] == "Overlay Tunnel":
            response = [{"message": f"Error dont try to modify {data['intfc_name']} interface address"}]
            print(response)
            return response
        for addr in data["current_addresses"]:
            os.system(f"sudo ip addr del {addr} dev {data['intfc_name']}")
        interface_addresses = configured_address()
        #print(interface_address)
        for int_addr in data["new_addresses"]:
            for address in interface_addresses:
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(int_addr.split("/")[0])
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring interface due to address conflict {int_addr}"}]
                    return response
        intfc_name = data["intfc_name"]
        if os.path.exists("/etc/netplan/00-installer-config.yaml"):
            # Open and read the Netplan configuration
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()             
            if "." in data["intfc_name"]:
                # Ensure the `vlans` section exists
                if "vlans" not in network_config["network"]:
                    network_config["network"]["vlans"] = {}
                # Add VLAN configuration
                network_config["network"]["vlans"][intfc_name]["addresses"] = data["new_addresses"]                
            elif "enp" in data["intfc_name"]:                
                network_config["network"]["ethernets"][intfc_name]["addresses"] = data["new_addresses"]                                                                 
            # Write the updated configuration back to the file
            with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                yaml.dump(network_config, f, default_flow_style=False)
            os.system("netplan apply")
            response = [{"message": f"Successfully configured Interface: {intfc_name}"}]
        else:            
            for ip_addr in data["addresses"]:
                cmd = f"sudo ip addr add {ip_addr} dev {intfc_name}"
                result = subprocess.run(
                                cmd, shell=True, text=True
                                )            
            response = [{"message": f"Successfully configured Interface: {intfc_name}"}]
    except Exception as e:
        print(e)
        response = [{"message": f"Error while configuring interface with  {data['intfc_name']}: {e}"}]
        print("excep", response)
    return response

def create_vlan_interface(data):
    try:
        interface_addresses = configured_address()
        for vlan_address in data["addresses"]:
            for address in interface_addresses:
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(vlan_address.split("/")[0])
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring VLAN interface due to address conflict {vlan_address}"}]
                    return response
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

def create_tunnel_interface(data):
    try:
        interface_addresses = configured_address()
        for vlan_address in data["addresses"]:
            for address in interface_addresses:
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(vlan_address.split("/")[0])
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring VLAN interface due to address conflict {vlan_address}"}]
                    return response
        if os.path.exists("/etc/netplan/00-installer-config.yaml"):
            # Open and read the Netplan configuration
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()           
            # Ensure the `vlans` section exists
            if "tunnels" not in network_config["network"]:
                network_config["network"]["tunnels"] = {}

            # Create the VLAN interface name
            
            if data["tunnel_intfc_name"] not in network_config["network"]["tunnels"]:
            # Add VLAN configuration
                network_config["network"]["tunnels"][data['tunnel_intfc_name']] = {
                                                                "local": "0.0.0.0",
                                                                "mode": "gre",
                                                                "addresses": data["addresses"],
                                                                "mtu":"1476",
                                                                "remote": data["destination_ip"]                                                                
                                                                }

                # Write the updated configuration back to the file
                with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                    yaml.dump(network_config, f, default_flow_style=False)
                os.system("netplan apply")
                response = [{"message": f"Successfully configured tunnel Interface: {data['tunnel_intfc_name']}"}]
            else:
                response = [{"message": f"Error already interface: {data['tunnel_intfc_name']} exist."}]
        
    except Exception as e:
        response = [{"message": f"Error while configuring tunnel interface with id {data['tunnel_intfc_name']}: {e}"}]
    return response

def delstaticroute_ubuntu(data):
    try:
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
        response = {"message": "Error while deleting route"}
    return response
        