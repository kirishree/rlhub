import paramiko
import time
import ipaddress
import re
import logging
from decouple import config
openvpn_network = config('OPENVPN_NETWORK')
logger = logging.getLogger('reachlink')
def pingspoke(data):   
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "pingspoke",
                "exception": str(e)
            }
            )
        # Execute the ping command
        stdin, stdout, stderr = ssh_client.exec_command(f'/ping {data["subnet"]} count 5')
        final_output = " "
        # Read the output in real-time
        start_time = time.time()
        timeout = 8  # Stop after 10 seconds
        while True:
            line = stdout.readline()
            if not line:  # No more output
                break            
            out = line.strip()            
            if "sent=" in out:
                final_output = out
                break
            # Stop the loop after the timeout
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the ping command.")
                break
    except Exception as e:
        logger.error(
            f"Error while ping spoke",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "pingspoke",
                "exception": str(e)
            }
            )
    finally:
        # Close the SSH connection
        ssh_client.close() 
    if "avg-rtt=" in final_output:
        avg_rtt = final_output.split(" ")[4].split("=")[1]        
    elif "packet-loss=100%" in final_output:
        avg_rtt = "-1"
    else:
        avg_rtt = "0"
    logger.info(
            f"ping result {final_output}",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "pingspoke",
                "exception": ""
            }
            )
    return avg_rtt

def addroute(data):   
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "addroute",
                "exception": str(e)
            }
            )
        # Execute the ping command
        subnets = data["subnet_info"]
        not_added_route = []
        route_conflict = False
        for subnet in subnets:
            corrected_dst = str(ipaddress.ip_network(subnet["subnet"], strict=False))        
            corrected_subnet = ipaddress.ip_network(openvpn_network, strict=False)
            dstip = corrected_dst.split("/")[0]
            ip_obj = ipaddress.ip_address(dstip)
            if ip_obj in corrected_subnet:
                    response = [{"message": f"Error while adding route due to route conflict {openvpn_network}"}]
                    route_conflict = True
                    break  
            stdin, stdout, stderr = ssh_client.exec_command(f'/ip route add dst-address={corrected_dst} gateway={subnet["gateway"]}')
            # Read the actual output and errors
            output = stdout.read().decode()
            if output:
                not_added_route.append(corrected_dst)
        if not route_conflict:
            if len(not_added_route) == 0:       
                response = [{"message": "Route(s) added"}]
            else:
                response = [{"message": f"Error: {not_added_route} not added"}]
        logger.info(
            f"{response}",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "addroute",
                "exception": ""
            }
            )
    except Exception as e:        
        logger.error(
            f"Error occured when adding route",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "addroute",
                "exception": str(e)
            }
            )
        response = [{"message":"Error while adding route. Pl try again!"}] 
    finally:
        # Close the SSH connection
        ssh_client.close()        
        return response

def clean_traceroute_output(raw_output):
    # This regex matches ANSI escape sequences
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', raw_output)
    return cleaned_output

def traceroute(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "traceroute",
                "exception": str(e)
            }
            )
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/tool traceroute {data["trace_ip"]}')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(1024).decode()  # Read available data

                if data["trace_ip"] in output:
                    break
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break         
    except Exception as e:
        logger.error(
            f"Error while traceroute in Microtek Spoke",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "traceroute",
                "exception": str(e)
            }
            )        
        return "Error while traceroute in Microtek Spoke"        
    finally:
        # Close the SSH connection
        ssh_client.close()
        #return output.strip()
        i = 0
        cleaned_output = clean_traceroute_output(output) 
        out = cleaned_output.split("/n")
        print(out)
        final = out[0]
        for out1 in out:
            if not out1.strip():             
                i = 1
            if i == 1:
                final +=out1 
              
        return cleaned_output

def routingtable1(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "routingtable1",
                "exception": str(e)
            }
            )
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip route print')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break         
    except Exception as e:
        print(f"An error occurred: {e}")
        return "Error while traceroute in Microtek Spoke"        
    finally:
        # Close the SSH connection
        ssh_client.close()        
        routes = output.split("\n")
        i = 0
        collect = []
        for route in routes:
#           print("hi")
            if i < 5:
                i = i+1
            if i > 4:
                newroutes = []
                route_info = route.strip().split(" ")
                for info in route_info:
                    if info:
                        newroutes.append(info)
                if len(newroutes) > 2:
                    if newroutes[1] == "ADC":
                        collect.append({"protocol":newroutes[1],
                                "destination": newroutes[2],
                                "gateway": "None",
                                "metric":newroutes[-1],
                                "outgoint_interface_name": newroutes[4],
                                "table_id": "Main Routing table"

                                })
                    if newroutes[1] == "ADS" or newroutes[1] == "S" or newroutes[1] =="DS":
                        collect.append({"protocol":newroutes[1],
                                "destination": newroutes[2],
                                "gateway": newroutes[3],
                                "metric":newroutes[-1],
                                "outgoint_interface_name": "None",
                                "table_id": "Main Routing table"

                                })
                    if newroutes[1] == "A" or newroutes[1] == "X":
                        collect.append({"protocol":newroutes[2],
                                "destination": newroutes[3],
                                "gateway": newroutes[4],
                                "metric":newroutes[-1],
                                "outgoint_interface_name": "None",
                                "table_id": "Main Routing table"

                                })
        return collect
        
def routingtable(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "routingtable",
                "exception": str(e)
            }
            )
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip route print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break         
    except Exception as e:
        logger.error(
            f"Error while getting routing table",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "routingtable",
                "exception": str(e)
            }
            )
        return "Error while getting routing table in Microtek Spoke"        
    finally:
        # Close the SSH connection
        ssh_client.close()        
        routes_info = output.split("\n")[3:]
        routesinfo = []
        data =[]      
        for route in routes_info:
            if route.strip():
                routesinfo.append(route)
            else:
                data.append(routesinfo)
                routesinfo = []
        collect = []
        for info in data:
            routingtableava = False
            interface = " "
            for routeinfo in info:
                routeinfostrip = routeinfo.strip()
                if "dst-address=" in routeinfostrip:
                    destination = routeinfostrip.split("dst-address=")[1].split(" ")[0]
                    protocolinfo = routeinfostrip.split("dst-address=")[0].split(" ")[1:-1]
                    protocol = " "
                    for proto in protocolinfo:
                        protocol = protocol + proto
                    if "s" in protocol or "S" in protocol:
                        protocol = "static"
                if " gateway=" in routeinfostrip:
                    gateway = routeinfostrip.split("gateway=")[1].split(" ")[0]
                    if gateway == "ovpn1":
                        gateway = "Base Tunnel"                       
                    if gateway == "reachlink":
                        gateway = "Overlay Tunnel"
                if "distance=" in routeinfostrip:
                    distance = routeinfostrip.split("distance=")[1].split(" ")[0]
                if "reachable via" in routeinfostrip:
                    interface = routeinfostrip.split("reachable via")[1].split(" ")[2]
                    if interface == "ovpn1":
                        interface = "Base Tunnel"                       
                    if interface == "reachlink":
                        interface = "Overlay Tunnel"
                if "routing-mark=" in routeinfostrip:
                    routingtable = routeinfostrip.split("routing-mark=")[1].split(" ")[0]
                    routingtableava = True
            if not routingtableava:
                routingtable = "Main Routing table"
            collect.append({"protocol":protocol,
                                "destination": destination,
                                "gateway": gateway,
                                "metric":distance,
                                "outgoint_interface_name": interface,
                                "table_id": routingtable

                                })
        return collect

def interfacedetails(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:
            logger.error(
            f"SSH Connection error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "get_interface_details",
                "exception": str(e)
            }
            )
            return []
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/interface print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break         
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        addressoutput = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                addressoutput += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break         
    except Exception as e:
        logger.error(
            f"Error while getting interface details",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "get_interface_details",
                "exception": str(e)
            }
            )
        return []        
    finally:
        # Close the SSH connection
        ssh_client.close()            
        interface_info = output.split("\n")[1:-1]
        intfcinfo = []
        data =[]      
        for intfc in interface_info:
            if intfc.strip():
                intfcinfo.append(intfc)
            else:
                data.append(intfcinfo)
                intfcinfo = []
        collect = []
        for info in data:           
            for intinfo in info:
                intinfostrip = intinfo.strip()
                # Clean up extra spaces or non-visible characters using regex
                intinfostrip = re.sub(r'\s+', ' ', intinfostrip)  # Replace multiple spaces with a single space
                if " name=" in intinfostrip:
                    interfacename = intinfostrip.split(" name=")[1].split('"')[1]                   
                    status_info = intinfostrip.split(" ")[1]
#                    print("status_info", status_info)
                    if status_info == "R":
                        intfc_status = "up"
                    else:
                        intfc_status = "down" 
                if "defconf" in intinfostrip:
                    status_info = intinfostrip.split(" ")[1]
                    print("status_info", status_info)
                    if status_info == "R":
                        intfc_status = "up"
                    else:
                        intfc_status = "down"

                if "type=" in intinfostrip:
                    typeinfo = intinfostrip.split("type=")[1].split('"')[1]
                    if typeinfo == "bridge":
                       interfacename = "bridge"
                    if typeinfo == "vlan":
                       typeinfo = "VLAN"
                if "mac-address=" in intinfostrip:
                    macaddress = intinfostrip.split("mac-address=")[1].split(" ")[0]
                if "actual-mtu=" in intinfostrip:
                    mtu = intinfostrip.split("actual-mtu")[1].split(" ")[0]
            if intfc_status == "up":
                statusintfc = "up"    
            else:
                statusintfc = "down"
            if interfacename != "ether2" and interfacename != "ether3" and interfacename != "ether4" and interfacename != "ether5":
                collect.append({"interface_name":interfacename,
                                "mac_address": macaddress,
                                "type": typeinfo,
                                "mtu": mtu,
                                "addresses": [{"IPv4address":" "}],
                                "status":intfc_status
                                })        
        addresses_info = addressoutput.split("\n")[1:-1]
        addressinfo = []
        data1 =[]      
        for addr in addresses_info:            
            if addr.strip():
                addressinfo.append(addr)
            else:
                data1.append(addressinfo)
                addressinfo = []
        collectaddr = []
        for info1 in data1:             
            for addrinfo in info1:
                addrinfostrip = addrinfo.strip()            
                if "address=" in addrinfostrip:
                    intfcaddress = addrinfostrip.split("address=")[1].split(" ")[0]
                    
                if " interface=" in addrinfostrip:
                    intfc = addrinfostrip.split(" interface=")[1].split(" ")[0]             
            collectaddr.append({"interface_name":intfc,
                                "address": intfcaddress                                            

                                })     
        for interface in collect:
            for intfci in collectaddr:
                if interface["interface_name"] == intfci["interface_name"]:                 
                    if intfci["address"] != " ":
                       interface["addresses"].append({"IPv4address":intfci["address"]})
        for interface in collect:
            if interface["interface_name"] == "ovpn1":
                interface["interface_name"] = "Base Tunnel"
                interface["type"] = "tunnel"
            if interface["interface_name"] == "reachlink":
                interface["interface_name"] = "Overlay Tunnel"
                interface["type"] = "tunnel"
            interface["addresses"] = [addr for addr in interface["addresses"] if addr["IPv4address"].strip()]    
        return collect

def interfaceconfig(data):   
   # Define the router details       
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
     # Create an SSH client instance
    
    if data["intfc_name"] == "ether1" or data["intfc_name"] == "Base Tunnel" or data["intfc_name"] == "Overlay Tunnel":
        response = [{"message": f"Error don't try to modify {data['intfc_name']} interface address"}]
        return response
    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:
            logger.error(
            f"SSH Connection error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "interface_config",
                "exception": str(e)
            }
            )
            response = [{"message":"Error: SSH connection error"}]
            return response
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        addresses_info = output.split("\n")   
        for addr in addresses_info:
            addr = addr.strip()
                # Clean up extra spaces or non-visible characters using regex
            addr = re.sub(r'\s+', ' ', addr)  # Replace multiple spaces with a single space
            if "address=" in addr:
                    intfcname = addr.split("interface=")[1].split(" ")[0] 
                    #print(intfcname)
                    if intfcname == data["intfc_name"]:                                               
                            removeitemno = addr.split(" ")[0]                                                    
                            stdin, stdout, stderr = ssh_client.exec_command(f'/ip address remove {removeitemno}')
        
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        addresses_info = output.split("\n")  
        interface_addresses = [] 
        for addr in addresses_info:
            if "address=" in addr:
                    intfcname = addr.split("interface=")[1].split(" ")[0] 
                    if intfcname != data["intfc_name"]:
                        intfcaddress = addr.split("address=")[1].split(" ")[0]  
                        interface_addresses.append(intfcaddress) 
        for int_addr in data["new_addresses"]:
            for address in interface_addresses:
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(int_addr["address"].split("/")[0])
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring interface due to address conflict {int_addr['address']}"}]
                    ssh_client.close()            
                    return response
        for newaddr in data["new_addresses"]:
            stdin, stdout, stderr = ssh_client.exec_command(f'/ip address add address={newaddr["address"]} interface={data["intfc_name"]}')
            
            if newaddr["address"].split(".")[0] != "10":
                if newaddr["address"].split(".")[0] == "172":
                    if 15 < int(newaddr["address"].split(".")[1]) < 32:
                        private_ip = True
                    else:
                        private_ip = False
                elif newaddr["address"].split(".")[0] == "192":
                    if newaddr["address"].split(".")[1] == "168":
                        private_ip = True
                    else:
                        private_ip = False
                elif int(newaddr["address"].split(".")[0]) > 223: 
                    private_ip = True
                else:
                    private_ip = False
            else:
                private_ip = True
            if not private_ip:
                routerrealip = newaddr["address"].split("/")[0]
                routersubnet = str(ipaddress.ip_network(newaddr["address"], strict=False))
                stdin, stdout, stderr = ssh_client.exec_command(f'/ip firewall mangle add chain=output src-address={routerrealip} dst-address=!{routersubnet} action=mark-routing new-routing-mark=reachlink')
        response = [{"message": f"Interface {data['intfc_name']} updated"}]
        logger.info(
            f"{response}",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "interface_config",
                "exception": ""
            }
            )
    except Exception as e:
        logger.error(
            f"Error in interface config",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "interface_config",
                "exception": str(e)
            }
            )
        response = [{"message": f"Error while updating interface {data['intfc_name']}"}]          
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response

def createvlaninterface(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)               
        except Exception as e:
            logger.error(
            f"SSH Connection error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "create_interface",
                "exception": str(e)
            }
            )
            return [{"message":"Error: SSH connection timeout"}]
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data               
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        addresses_info = output.split("\n")  
        interface_addresses = [] 
        for addr in addresses_info:
            if "address=" in addr:
                    if " I " in addr:
                        continue
                    intfcaddress = addr.split("address=")[1].split(" ")[0]  
                    interface_addresses.append(intfcaddress) 
        for int_addr in data["addresses"]:
            for address in interface_addresses:                   
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(int_addr.split("/")[0])                
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring interface due to address conflict {int_addr}"}]
                    ssh_client.close()            
                    return response
        vlan_int_name = f"{data['link']}.{data['vlan_id']}"
        stdin, stdout, stderr = ssh_client.exec_command(f'/interface vlan add name={vlan_int_name} vlan-id={data["vlan_id"]} interface={data["link"]}')  
        for newaddr in data["addresses"]:
            stdin, stdout, stderr = ssh_client.exec_command(f'/ip address add address={newaddr} interface={vlan_int_name}')  
        response = [{"message": f"Interface {vlan_int_name} created "}]
        logger.info(
            f"{response}",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "create_interface",
                "exception": " "
            }
            )
    except Exception as e:
        logger.error(
            f"Error in interface create",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "create_interface",
                "exception": str(e)
            }
            )
        response = [{"message": f"Error while creating interface {data['link']}"}]          
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response

def createtunnelinterface(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    greintfcname = "gretunnel" + data["tunnel_intfc_name"] 
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)               
        except Exception as e:
            logger.error(
            f"SSH Connection time out",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "create_tunnel_interface",
                "exception": str(e)
            }
            )
            return [{"message": "Error: SSH connection timeout"}]
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data               
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        addresses_info = output.split("\n")  
        interface_addresses = [] 
        for addr in addresses_info:
            if "address=" in addr:
                    if " I " in addr:
                        continue
                    intfcaddress = addr.split("address=")[1].split(" ")[0] 
                    if data["link"] == addr.split("interface=")[1].split(" ")[0]:
                        local_address = intfcaddress.split("/")[0]
                    interface_addresses.append(intfcaddress) 
        for int_addr in data["addresses"]:
            for address in interface_addresses:                   
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(int_addr.split("/")[0])                
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while creating Tunnel interface due to address conflict {int_addr}"}]
                    ssh_client.close()            
                    return response             
        stdin, stdout, stderr = ssh_client.exec_command(f'/interface gre add name={greintfcname} local-address={local_address} remote-address={data["destination_ip"]}')  
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address add address={data["addresses"][0]} interface={greintfcname}')  
        response = [{"message": f"Tunnel interface {greintfcname} created "}]
        logger.info(
            f"{response}",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "create_tunnel_interface",
                "exception": " "
            }
            )

    except Exception as e:
        logger.error(
            f"Error in tunnel interface create",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "create_tunnel_interface",
                "exception": str(e)
            }
            )
        response = [{"message": f"Error while creating Tunnel interface {greintfcname}. Pl try again!"}]          
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response

def deletevlaninterface(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:
            logger.error(
            f"SSH Connection timeout",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "delete_interface",
                "exception": str(e)
            }
            )
            return [{"message":"Error: SSH Connection timeout"}]
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/interface vlan print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        vlan_info = output.split("\n")   
        for addr in vlan_info:
            if "name=" in addr:
                    vlanname = addr.split("name=")[1].split(" ")[0].split('"')[1]                    
                    print("vlanname", vlanname)
                    print(data["intfc_name"])
                    if vlanname == data['intfc_name']:
                            print("hi")
                            removeitemno = addr.split(" ")[1]
                            print("vlan item", removeitemno)
                            stdin, stdout, stderr = ssh_client.exec_command(f'/interface vlan remove {removeitemno}')
                            response = [{"message": f"Interface {data['intfc_name']} deleted"}]
                            ssh_client.close()       
                            return response
        response = [{"message": f"Error no such interface {data['intfc_name']}"}]
        logger.info(
            f"{response}",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "delete_interface",
                "exception": " "
            }
            )
    except Exception as e:
        logger.error(
            f"Error while deleting interface",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "delete_interface",
                "exception": str(e)
            }
            )
        response = [{"message": f"Error while deleting interface {data['intfc_name']}. Pl try again!"}]
          
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response

def deletetunnelinterface(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/interface gre print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data               
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        gre_info = output.split("\n")   
        for addr in gre_info:
            if "name=" in addr:
                    tunnelname = addr.split("name=")[1].split(" ")[0].split('"')[1]                    
                    print("tunnelname", tunnelname)
                    print(data["intfc_name"])
                    if tunnelname == data['intfc_name']:                            
                            removeitemno = addr.split(" ")[1]                            
                            stdin, stdout, stderr = ssh_client.exec_command(f'/interface gre remove {removeitemno}')
                            response = [{"message": f"Interface {data['intfc_name']} deleted"}]
                            ssh_client.close()       
                            return response
        response = [{"message": f"Error no such Tunnel interface {data['intfc_name']}"}]
    except Exception as e:
        print(f"An error occurred: {e}")
        response = [{"message": f"Error while deleting Tunnel interface {data['intfc_name']}. Pl try again!"}]          
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response

def configurepbr(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        # Execute the command to add rule in mangle for PBR
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip firewall mangle print')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data             
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        mangle_info = output.split("\n")[1:-1]
        mangleinfo = []
        data_pbr =[]      
        for intfc in mangle_info:
            if intfc.strip():
                mangleinfo.append(intfc)
            else:
                data_pbr.append(mangleinfo)
                mangleinfo = []
        collect = []
        for info in data_pbr:            
            new_routing_mark = " "  
            src_address = "any"
            dst_address = "any"     
            for pbrinfo in info:                
                pbrinfostrip = pbrinfo.strip()
                if "new-routing-mark=" in pbrinfostrip:
                    new_routing_mark = pbrinfostrip.split("new-routing-mark=")[1].split(" ")[0]                   
                if "src-address=" in pbrinfostrip:
                    src_address = pbrinfostrip.split("src-address=")[1].split(" ")[0]   
                if "dst-address=" in pbrinfostrip:
                    dst_address = pbrinfostrip.split("dst-address=")[1].split(" ")[0]                 
            if new_routing_mark != " ":   
                collect.append({"new_routing_mark":new_routing_mark,
                            "src_address": src_address,
                            "dst_address": dst_address})    
        
        # Execute the command to add rule in mangle for PBR
        for subnet in data["realip_subnet"]:          
            subnet_key = "destination" if "destination" in subnet else "subnet" if "subnet" in subnet else None
            alreadyconfigured = False
            if subnet_key:
                for pbr in collect:                    
                    if pbr["src_address"] == subnet[subnet_key]:
                        alreadyconfigured = True
                        break
                if alreadyconfigured == False:
                    stdin, stdout, stderr = ssh_client.exec_command(f'/ip firewall mangle add chain=prerouting src-address={subnet[subnet_key]} dst-address=!{subnet[subnet_key]} action=mark-routing new-routing-mark=reachlink')
        response = [{"message": f"Successfully configured PBR in Microtek Spoke"}]
    except Exception as e:
        print(f"An error occurred: {e}")
        response = [{"message": f"Error while configuring PBR in Microtek Spoke"}]          
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response

def getconfigurepbr(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        # Execute the command to add rule in mangle for PBR
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip firewall mangle print')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        mangle_info = output.split("\n")[1:-1]
        mangleinfo = []
        data =[]      
        for intfc in mangle_info:
            if intfc.strip():
                mangleinfo.append(intfc)
            else:
                data.append(mangleinfo)
                mangleinfo = []
        collect = []
        for info in data:   
            new_routing_mark = " "  
            src_address = "any"
            dst_address = "any"     
            for pbrinfo in info:
                pbrinfostrip = pbrinfo.strip()
                if "new-routing-mark=" in pbrinfostrip:
                    new_routing_mark = pbrinfostrip.split("new-routing-mark=")[1].split(" ")[0]                   
                if "src-address=" in pbrinfostrip:
                    src_address = pbrinfostrip.split("src-address=")[1].split(" ")[0]   
                if "dst-address=" in pbrinfostrip:
                    dst_address = pbrinfostrip.split("dst-address=")[1].split(" ")[0]                 
            if new_routing_mark != " ":   
                collect.append({"new_routing_mark":new_routing_mark,
                            "src_address": src_address,
                            "dst_address": dst_address})    
        
    except Exception as e:
        print(f"An error occurred: {e}")   
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return collect

def delstaticroute(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:            
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "delete_static_route",
                "exception": str(e)
            }
            )
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip route print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data    
            # Break if timeout is reached
            if time.time() - start_time > timeout:                
                break  
        route_info = output.split("\n") 
        for routes in data["routes_info"]:  
            if "0.0.0.0" in routes["destination"] or "10.8.0.0/24" in routes["destination"]:
                response = [{"message": f"Error: Route {routes['destination']} deletion is prohibited "}]
                break
            for addr in route_info:
                if "dst-address=" in addr and "gateway=" in addr:                    
                    dstaddr = addr.split("dst-address=")[1].split(" ")[0]                   
                    gateway = addr.split("gateway=")[1].split(" ")[0]                                      
                    if dstaddr == routes["destination"] and gateway == routes["gateway"]:                            
                            addrstrip = addr.strip()                            
                            removeitemno = addrstrip.split(" ")[0]                            
                            stdin, stdout, stderr = ssh_client.exec_command(f'/ip route remove {removeitemno}')                            
                            response = [{"message": f"Route: {data['routes_info'][0]['destination']} deleted"}]        
        logger.info(
            f"{response}",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "delete_static_route",
                "exception": " "
            }
            )
    except Exception as e:
        logger.error(
            f"Error while deleting route {data['routes_info']}",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "api_endpoint": "delete_static_route",
                "exception": str(e)
            }
            )
        response = [{"message": f"Error while deleting route {data['routes_info']}. Pl try again!"}]          
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response
def laninfo(data):   
   # Define the router details
    
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
     # Create an SSH client instance
    dhcp_start_addr = False
    dhcp_end_addr = False
    primary_dns = False
    sec_dns = False
    lan_ipaddr = False

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        addresses_info = output.split("\n")   
        for addr in addresses_info:
#            addr = addr.strip()
            if " interface=" in addr:
                    intfcname = addr.split(" interface=")[1].split(" ")[0]   
                    if intfcname == "bridge":
                        print("adderess", addr)
                        lan_ipaddr = addr.split("address=")[1].split(" ")[0]                
                        break
        # Execute the dns info command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip dns print')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        dns_info = output.split("\n")   
        for dnsinfo in dns_info:
            dnsinfo = dnsinfo.strip()
            if "servers:" in dnsinfo:
                    dnsservers = dnsinfo.split("servers:")[1].split(" ")[1]
                    primary_dns = dnsservers.split(",")[0]
                    sec_dns = dnsservers.split(",")[1]
                    break
        if lan_ipaddr:
            # Execute the dhcp server command 
            stdin, stdout, stderr = ssh_client.exec_command(f'/ip dhcp-server print detail')
            # Initialize variables for output collection
            start_time = time.time()
            timeout = 10  # Stop after 10 seconds
        
            # Use a loop to monitor and collect output
            output = ""
            while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
                if stdout.channel.recv_ready():
                    output += stdout.channel.recv(2048).decode()  # Read available data
                
            
                # Break if timeout is reached
                if time.time() - start_time > timeout:
                    print("Timeout reached. Terminating the traceroute command.")
                    break  
            dhcppool_info = output.split("\n")   
            for addr in dhcppool_info:
                if "interface=" in addr:
                    intfcname = addr.split("interface=")[1].split(" ")[0]   
                    if intfcname == "bridge":
                        poolname = addr.split("address-pool=")[1].split(" ")[0]                
                        break
            if poolname:
                # Execute the ip pool command 
                stdin, stdout, stderr = ssh_client.exec_command(f'/ip pool print detail')
                # Initialize variables for output collection
                start_time = time.time()
                timeout = 10  # Stop after 10 seconds
        
                # Use a loop to monitor and collect output
                output = ""
                while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
                    if stdout.channel.recv_ready():
                        output += stdout.channel.recv(2048).decode()  # Read available data
                
            
                    # Break if timeout is reached
                    if time.time() - start_time > timeout:
                        print("Timeout reached. Terminating the traceroute command.")
                        break  
                pool_info = output.split("\n")   
                for addr in pool_info:
                    if "name=" in addr:
                        getpoolname = addr.split("name=")[1].split(" ")[0].split('"')[1]      
                        if poolname == getpoolname:
                            addressrange = addr.split("ranges=")[1].split(" ")[0]  
                            dhcp_start_addr = addressrange.split("-")[0]    
                            dhcp_end_addr = addressrange.split("-")[1]        
                            break
        response = {"dhcp_start_addr":dhcp_start_addr,
                   "dhcp_end_addr":dhcp_end_addr,
                   "primary_dns":primary_dns,
                   "sec_dns":sec_dns,
                   "lan_ipaddr": lan_ipaddr}
        
    except Exception as e:
        print(f"An error occurred: {e}")
        response = {"dhcp_start_addr":dhcp_start_addr,
                   "dhcp_end_addr":dhcp_end_addr,
                   "primary_dns":primary_dns,
                   "sec_dns":sec_dns,
                   "lan_ipaddr": lan_ipaddr}
          
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response

data = {"tunnel_ip":"10.200.202.6/24",
        "router_username":"admin",
        "router_password": "123@abc.com"}   
   
#print(laninfo(data))
def  validateIP(ip_address):
    octet = ip_address.split(".")
    prefix_len = ip_address.split("/")[1]
    if prefix_len == 32:
        return False
    if octet[0] == "10":
        if int(prefix_len) > 7:
            return True
    if octet[0] == "172":
        if 15 < int(octet[1]) < 32:
            if int(prefix_len) > 15:
                return True
    if octet[0] == "192" and octet[1] == "168":
        if int(prefix_len) > 23:
            return True    
    return False

def prefix_len_to_netmask(prefix_len):
    # Validate the prefix length
    print(prefix_len)
    prefix_len = int(prefix_len)
    if not 0 <= prefix_len <= 32:
        raise ValueError("Prefix length must be between 0 and 32")
    # Calculate the netmask using bitwise operations
    netmask = 0xffffffff ^ (1 << (32 - prefix_len)) - 1
    # Format the netmask into IP address format
    netmask_str = ".".join(str((netmask >> i) & 0xff) for i in [24, 16, 8, 0])
    return netmask_str

def get_ip_addresses(ip_address, netmask):
    # Create an IPv4Network object representing the subnet
    subnet = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    # Get the subnet ID and broadcast address
    subnet_id = subnet.network_address
    broadcast_ip = subnet.broadcast_address

    # Extract and return the list of host IPs (excluding subnet ID and broadcast IP)
    #host_ips = [str(ip) for ip in subnet.hosts()]
    
    if subnet.prefixlen == 31:
        # For /31, both IPs can act as hosts (point-to-point links)
        first_host = subnet.network_address
        last_host = subnet.broadcast_address
    else:
        # For other subnets, calculate first and last host IPs
        first_host = subnet.network_address + 1
        last_host = subnet.broadcast_address - 1

   
    host_ips = [first_host, last_host]    
    return {
        "Subnet_ID": str(subnet_id),
        "Broadcast_IP": str(broadcast_ip),
        "Host_IPs": host_ips
    }

def lanconfig(data):   
   # Define the router details
    
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    ip_address = data.get("ipaddress")
    if not (validateIP(ip_address)):
            response = [{"message": "Error: IP should be in private range"}] 
            print(response)  
            return response
    netmask = prefix_len_to_netmask(ip_address.split("/")[1])
    ip_addr = ip_address.split("/")[0]       
    ip_addresses = get_ip_addresses(ip_addr, netmask) 
    if ip_addr == ip_addresses["Subnet_ID"] or ip_addr ==  ip_addresses[ "Broadcast_IP"]:
            response = [{"message": "Error: Either Subnet ID or Broadcast IP is not able to assign"}]  
            print(response) 
            return response
    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        addresses_info = output.split("\n")   
        for addr in addresses_info:
            if " interface=" in addr:
                    intfcname = addr.split(" interface=")[1].split(" ")[0]                    
                    if intfcname == "bridge":
                        addr = addr.strip()
                        removeitemno = addr.split(" ")[0]
                        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address remove {removeitemno}')
        
        # Execute the trace command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        addresses_info = output.split("\n")  
        interface_addresses = [] 
        for addr in addresses_info:
            if "address=" in addr:
                    intfcaddress = addr.split("address=")[1].split(" ")[0]  
                    interface_addresses.append(intfcaddress) 
#        for int_addr in data["new_addresses"]:
        for address in interface_addresses:
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(ip_address.split("/")[0])
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring interface due to address conflict {ip_address}"}]
                    ssh_client.close()            
                    return response
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip address add address={ip_address} interface=bridge')  
        dhcp_start_address = ip_addresses["Host_IPs"][0]
        dhcp_end_address = ip_addresses["Host_IPs"][1]
        # Execute the dhcp server command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip dhcp-server print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        dhcppool_info = output.split("\n")   
        for addr in dhcppool_info:
            if "interface=" in addr:
                intfcname = addr.split("interface=")[1].split(" ")[0]   
                if intfcname == "bridge":
                    poolname = addr.split("address-pool=")[1].split(" ")[0]                
                    break
        if poolname:
            # Execute the ip pool command 
            stdin, stdout, stderr = ssh_client.exec_command(f'/ip pool print detail')
            # Initialize variables for output collection
            start_time = time.time()
            timeout = 10  # Stop after 10 seconds
        
            # Use a loop to monitor and collect output
            output = ""
            while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
                if stdout.channel.recv_ready():
                    output += stdout.channel.recv(2048).decode()  # Read available data
                
            
                # Break if timeout is reached
                if time.time() - start_time > timeout:
                    print("Timeout reached. Terminating the traceroute command.")
                    break  
            pool_info = output.split("\n")   
            for addr in pool_info:
                if "name=" in addr:
                    getpoolname = addr.split("name=")[1].split(" ")[0].split('"')[1]      
                    if poolname == getpoolname:
                        poolnumbers = addr.split(" ")[1]  
                        break
            stdin, stdout, stderr = ssh_client.exec_command(f'/ip pool set numbers={poolnumbers} ranges={dhcp_start_address}-{dhcp_end_address}')
            response = [{"message":"LAN configured successfully"}]
        else:
            response = [{"message":"LAN IP configured but error in DHCP configuration."}]
    except Exception as e:
        print(f"An error occurred: {e}")
        response = [{"message":"Error in LAN configuration"}]        
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response

def dhcpconfig(data):   
   # Define the router details    
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    primary_dns = data.get("primary_dns","8.8.8.8")
    sec_dns = data.get("secondary_dns", "8.8.4.4")
    dhcp_start_address = data.get("dhcp_start_addr", False)
    dhcp_end_address = data.get("dhcp_end_addr", False)
    if dhcp_start_address == False or dhcp_end_address == False:
        reponse = {"message": "Error DHCp start address or end address is not available"}
        return response
    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        # Execute the dhcp server command 
        stdin, stdout, stderr = ssh_client.exec_command(f'/ip dhcp-server print detail')
        # Initialize variables for output collection
        start_time = time.time()
        timeout = 10  # Stop after 10 seconds
        
        # Use a loop to monitor and collect output
        output = ""
        while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(2048).decode()  # Read available data
                
            
            # Break if timeout is reached
            if time.time() - start_time > timeout:
                print("Timeout reached. Terminating the traceroute command.")
                break  
        dhcppool_info = output.split("\n")   
        for addr in dhcppool_info:
            if "interface=" in addr:
                intfcname = addr.split("interface=")[1].split(" ")[0]   
                if intfcname == "bridge":
                    poolname = addr.split("address-pool=")[1].split(" ")[0]                
                    break
        if poolname:
            # Execute the ip pool command 
            stdin, stdout, stderr = ssh_client.exec_command(f'/ip pool print detail')
            # Initialize variables for output collection
            start_time = time.time()
            timeout = 10  # Stop after 10 seconds
        
            # Use a loop to monitor and collect output
            output = ""
            while not stdout.channel.exit_status_ready() or stdout.channel.recv_ready():  # Wait for the command to complete
                if stdout.channel.recv_ready():
                    output += stdout.channel.recv(2048).decode()  # Read available data
                
            
                # Break if timeout is reached
                if time.time() - start_time > timeout:
                    print("Timeout reached. Terminating the traceroute command.")
                    break  
            pool_info = output.split("\n")   
            for addr in pool_info:
                if "name=" in addr:
                    getpoolname = addr.split("name=")[1].split(" ")[0].split('"')[1]      
                    if poolname == getpoolname:
                        poolnumbers = addr.split(" ")[1]  
                        break
            stdin, stdout, stderr = ssh_client.exec_command(f'/ip pool set numbers={poolnumbers} ranges={dhcp_start_address}-{dhcp_end_address}')
            response = [{"message":"LAN configured successfully"}]
            stdin, stdout, stderr = ssh_client.exec_command(f'/ip dns set servers={primary_dns},{sec_dns}')
            response = [{"message": "DHCP configured successfully"}]
        else:
            response = [{"message":"Error in getting DHCP pool name."}]
    except Exception as e:
        print(f"An error occurred: {e}")
        response = [{"message":"Error in DHCP configuration"}]          
    finally:
        # Close the SSH connection
        ssh_client.close()       
        return response
                
