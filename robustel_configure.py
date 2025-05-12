import paramiko
import time
import ipaddress
import re
port_number = 3366
import logging
import os
from decouple import config
openvpn_network = config('OPENVPN_NETWORK')
logger = logging.getLogger('reachlink')
# Function to send a command and wait for the router's prompt
def send_command(shell, command, wait_time=2):
    shell.send(command + '\n')
    time.sleep(wait_time)  # Wait for the command to be processed  
    return 

def send_command_config(shell, command, delay=5):
    shell.send(command + '\n')
    time.sleep(delay)
    output = shell.recv(65535).decode('utf-8')
    print(command, output)
    return output

def send_command_wo(shell, command, delay=1):
    shell.send(command + '\n')
    time.sleep(delay)
    output = shell.recv(65535).decode('utf-8')
    return output


def get_command_output(shell, command, wait_time=1, buffer_size=4096, max_wait=15):
    """
    Sends a command to the shell and retrieves the output, handling paging (`--More--`).
    """
    shell.send(command + '\n')
    time.sleep(wait_time)
    
    full_output = ""
    start_time = time.time()
    
    while True:
        if shell.recv_ready():
            output = shell.recv(buffer_size).decode('utf-8')
            full_output += output
            
            # Handle paging by sending space when `--More--` is detected
            if '--More--' in output:
                shell.send(' ')  # Send space to get the next page
                time.sleep(0.5)
            elif full_output.strip().endswith('#') or full_output.strip().endswith('>'):
                break  # Break if the command prompt is reached
        elif time.time() - start_time > max_wait:
            print("Timeout waiting for command output.")
            break
        else:
            time.sleep(0.5)  # Avoid busy looping
    
    return full_output

def get_routingtable_robustel(data):
    """
    Connects to a Robustel router via SSH and retrieves the output of 'status route'.
    """
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:            
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "get_routing_table",
                "exception": str(e)
            }
            )
            return []    
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, 'status route')
        routes_info = output.split("\n")
        routing_table = []
        destination = ""
        gateway = ""
        distance = "1"
        interface = ""
        for route in routes_info:
            route = re.sub(r'\s+', ' ', route)  # Replace multiple spaces with a single space
            if "id =" in route:  
                if not ("8.8.8.8"  in destination or "8.8.4.4"  in destination):              
                    routing_table.append({"protocol":"default",
                                "destination": destination,
                                "gateway": gateway,
                                "metric":distance,
                                "outgoint_interface_name": interface,
                                "table_id": "main"})
            if "destination =" in route:
                destination = route.split(" ")[3]
            if "netmask =" in route:
                netmask = route.split(" ")[3]
                network = f"{destination}/{netmask}"
                print("net", network)
                # Create an IPv4Network object
                ipintf = ipaddress.IPv4Interface(network)
                destination = ipintf.with_prefixlen
            if "gateway =" in route:
                gateway = route.split(" ")[3]
            if "interface =" in route:
                interface = route.split(" ")[3]
            if "metric =" in route:
                distance = route.split(" ")[3]
        if not ("8.8.8.8"  in destination or "8.8.4.4"  in destination):
            routing_table.append({"protocol":"default",
                                "destination": destination,
                                "gateway": gateway,
                                "metric":distance,
                                "outgoint_interface_name": interface,
                                "table_id": "main"})
        # Send the command and get the output
        output = get_command_output(shell, 'show route all')
        routedetails = output.split("\n")
        staticroutepresent = False
        for intfc in routedetails:
            intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
            if "static_route {" in intfc:
                staticroutepresent =True
            if "id =" in intfc and "v" not in intfc:
                staticroute_no = intfc.split(" ")[3]
            if "destination =" in intfc:
                destination = intfc.split(" ")[3]
            if "netmask =" in intfc:
                dst_netmask = intfc.split(" ")[3]
                network = f"{destination}/{dst_netmask}"
                print("net1", network)
                # Create an IPv4Network object
                ipintf = ipaddress.IPv4Interface(network)
                destination = ipintf.with_prefixlen
            if "interface =" in intfc:
                if not ("8.8.8.8"  in destination or "8.8.4.4"  in destination):
                    routing_table.append({"protocol":"static",
                                "destination": destination,
                                "gateway": gateway,
                                "metric":"-",
                                "outgoint_interface_name": intfc.split(" ")[3],
                                "table_id": "main"})
    except Exception as e:        
        logger.error(
            f"Failed to fetch routing table",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "get_routing_table",
                "exception": str(e)
            }
            )    
        if len(routing_table) > 0:
            return routing_table[1:]
        else:
            return [] 
    finally:
        # Close the SSH connection
        ssh_client.close()
    return routing_table[1:]

def pingspoke(data):
    """
    Connects to a Robustel router via SSH and retrieves the output of 'status route'.
    """
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "pingspoke",
                "exception": str(e)
            }
            )
            response = {"message":f"Connection Timeout. Pl try again!"}
            return response    
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, f'ping {data["subnet"]}')
        ping_info = output.split("\n")
        avg_ms = "-1"
        for pinginfo in ping_info:
            if "100% packet loss" in pinginfo:
                response = {"message":f"Error: Subnet {data['subnet']} Not Reachable"}    
                break
            if "round-trip" in pinginfo:
                avg_ms = pinginfo.split("=")[1].split("/")[1]  
                response = {"message":f"Subnet {data['subnet']} Reachable with RTT: {avg_ms}ms"}
    except Exception as e:
        logger.error(
            f"Ping time out",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "pingspoke",
                "exception": str(e)
            }
            )
        response = {"message":f"Error: Ping Timeout. Pl try again"}     
    finally:
        # Close the SSH connection
        ssh_client.close()
    logger.info(f"Response- Robustel Ping output: {response}")
    return response

def clean_traceroute_output(raw_output):
    # This regex matches ANSI escape sequences
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', raw_output)
    return cleaned_output

def traceroute(data):
    """
    Connects to a Robustel router via SSH and retrieves the output of 'status route'.
    """
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f" SSH Connection Error",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "trace",
                "exception": str(e)
            }
            )
            return "Connection Time out. Pl try again!"      
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, f'traceroute {data["trace_ip"]}')
        cleaned_output = clean_traceroute_output(output)
        
    except Exception as e:
        logger.error(
            f" Failed to fetch trace info",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "trace",
                "exception": str(e)
            }
            )
        cleaned_output = "Error while traceroute"      
    finally:
        # Close the SSH connection
        ssh_client.close()
    return cleaned_output

def get_interface_robustel(data):
    """
    Connects to a Cisco router via SSH and retrieves the output of 'show ip int brief'.
    """
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    intfcdetails = []
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "get_interface_info",
                "exception": str(e)
            }
            )
            return []  
        # Open an interactive shell session
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, 'show lan all')
        interfacedetails = output.split("\n")
        intfc_datas = []
        status = "up"
        virtualaddresses = []
        for intfc in interfacedetails:
            intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
            if "network {" in intfc:
                interfacetype = "ether"
            if "multi_ip {" in intfc:
                interfacetype = "multiple"
            if "vlan {" in intfc:
                interfacetype = "VLAN"
            if "id =" in intfc:
                interfaceid = intfc.split(" ")[3]
            if "interface =" in intfc:
                interface = intfc.split(" ")[3]
                vlanid = "-"
            if "vid = " in intfc:
                vlanid = intfc.split(" ")[3]
                interfacetype = "VLAN"
                interface = "Vlan" + vlanid
            if "ip = " in intfc:
                ipv4addres = intfc.split(" ")[3]
            if "enable = " in intfc:
                enable = intfc.split(" ")[3]
                if enable == "true":
                    status = "up"
                else:
                    status = "down"
            if "netmask = " in intfc:
                netmask = intfc.split(" ")[3]
                network = f"{ipv4addres}/{netmask}"
                # Create an IPv4Network object
                ipintf = ipaddress.IPv4Interface(network)
                if interfacetype != "multiple":
                    intfc_datas.append({"interface_name": interface,
                                 "type": interfacetype,
                                 "Gateway": '-',
                                 "mac_address": "-",
                                 "addresses":[{"IPv4address" :ipintf.with_prefixlen, "primary": True}], 
                                 "status": status,
                                 "protocol": "static",                                 
                                 "vlan_link": vlanid,
                                 "interfaceid":interfaceid
                                })
                else:
                    virtual_intfcname = interface + "_IP_Alias"
                    virtual_interfacelastid = interfaceid 
                    virtualaddresses.append({"IPv4address" :ipintf.with_prefixlen,
                                              "primary": False, 
                                              "interfaceid":interfaceid})
                status = "up"
        if len(virtualaddresses) > 0:
            intfc_datas.append({"interface_name": virtual_intfcname,
                                 "type": "Multiple IPs assigned to lan0",
                                 "Gateway": '-',
                                 "mac_address": "-",
                                 "addresses":virtualaddresses, 
                                 "status": "up",
                                 "protocol": "static",                                 
                                 "vlan_link": "-",
                                 "interfaceid":virtual_interfacelastid
                                })
    except Exception as e:
        logger.error(
            f"Failed to fetch interface info",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "trace",
                "exception": str(e)
            }
            )
    finally:
        # Close the SSH connection
        ssh_client.close()
    intfc_datas.pop(1)
    return intfc_datas

def createvlaninterface(data):
    """
    Connects to a Robustel router via SSH and retrieves the output of 'status route'.
    """
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    vlan_ip = data["addresses"][0].split("/")[0]  
    corrected_subnet = ipaddress.ip_network(openvpn_network, strict=False)
    ip_obj = ipaddress.ip_address(vlan_ip)
    if ip_obj in corrected_subnet:
        response = [{"message": f"Error while creating  VLAN interface due to address conflict {vlan_ip}"}]
        logger.info(
            f"{response}",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "create_vlan_interface",
                "exception": ""
            }
            )
        return response
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "create_vlan_interface",
                "exception": str(e)
            }
            )
            response = [{"message": f"Connection time out. Pl try again!"}]
            return response     
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, 'show lan all')
        interfacedetails = output.split("\n")
        vlanpresent = False  
        vlan_no = 0   
        vlan_ids = []  
        current_addresses = []   
        for intfc in interfacedetails:
            intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
            if "vlan {" in intfc:
                vlanpresent =True
            if "id =" in intfc and "v" not in intfc:
                if vlanpresent:
                    vlan_no = intfc.split(" ")[3]
                    vlan_ids.append(int(vlan_no))
            if "ip = " in intfc:
                ipv4addres = intfc.split(" ")[3]            
            if "netmask = " in intfc:
                netmask = intfc.split(" ")[3]
                currentip = f"{ipv4addres}/{netmask}"
                # Create an IPv4Network object
                ipintf = ipaddress.IPv4Interface(currentip)
                current_addresses.append(ipintf.with_prefixlen)
            if "}" in intfc:
                vlanpresent = False  
        for current_address in current_addresses:
            corrected_subnet = ipaddress.ip_network(current_address, strict=False)
            ip_obj = ipaddress.ip_address(vlan_ip)
            if ip_obj in corrected_subnet:
                response = [{"message": f"Error while creating VLAN interface due to address conflict {vlan_ip}"}]
                logger.info(
                        f"{response}",
                        extra={
                            "device_type": "Robustel",
                            "device_ip": router_ip,
                            "api_endpoint": "create_vlan_interface",
                            "exception": ""
                        }
                )
                ssh_client.close()
                return response     
        if len(vlan_ids) == 10:
            response = [{"message": "Info: This device allows only 10 VLAN interface"}]   
            logger.info(
                    f"{response}",
                    extra={
                        "device_type": "Robustel",
                        "device_ip": router_ip,
                        "api_endpoint": "create_vlan_interface",
                        "exception": ""
                        }
                    )
            ssh_client.close()
            return response 
        vlan_no = [i for i in range(1,11) if i not in vlan_ids][0]            
        output = send_command_wo(shell, f'add lan vlan {vlan_no}')
        response = [{"message": "Error while creating vlan interface"}]
        if "OK" in output:
            output = send_command_wo(shell, f'set lan vlan {vlan_no} enable true')
            if "OK" in output:
                output = send_command_wo(shell, f'set lan vlan {vlan_no} interface lan0')
                if "OK" in output:                    
                    subnet = ipaddress.IPv4Network(data["addresses"][0], strict=False)  # Allow non-network addresses
                    netmask = str(subnet.netmask)
                    output = send_command_wo(shell, f'set lan vlan {vlan_no} vid {data["vlan_id"]}')                    
                    if "OK" in output:
                        output = send_command_wo(shell, f'set lan vlan {vlan_no} ip {vlan_ip}')
                        if "OK" in output:
                            output = send_command_wo(shell, f'set lan vlan {vlan_no} netmask {netmask}')                            
                            if "OK" in output:
                                output = send_command_config(shell, f'config save_and_apply')
                                response = [{"message": f"Interface lan0.{data['vlan_id']} created"}]       
                            else:
                                output = send_command_config(shell, f'config save_and_apply')
                                response = [{"message": f"Vlan interface created lan0.{data['vlan_id']}. Assign IP using Edit configuration"}] 
                        else:
                            output = send_command_config(shell, f'config save_and_apply')
                            response = [{"message": f"Vlan interface created lan0.{data['vlan_id']}. Assign IP using Edit configuration"}] 
                    else:
                        response = [{"message": f"Error in assigning vlan id, pl try again!"}] 
                else:
                    response = [{"message": f"Error in linking physical interface, pl try again!"}] 
            else:
                response = [{"message": f"Connection timeout, pl try again!"}]
        else:
            response = [{"message": f"Error in creation of VLAN, maybe Connection timeout, pl try again!"}]
        logger.info(
            f"{response}",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "create_vlan_interface",
                "exception": ""
            }
            )
    except Exception as e:
        logger.error(
            f"Failed to add Vlan",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "create_vlan_interface",
                "exception": str(e)
            }
            )
    finally:
        # Close the SSH connection
        ssh_client.close()
    return response

def deletevlaninterface(data):
    """
    Connects to a Robustel router via SSH and retrieves the output of 'status route'.
    """
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "delete_vlan_interface",
                "exception": str(e)
            }
            )
            response = [{"message": "Connection timeout. pl try again! "}] 
            return response   
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, 'show lan all')        
        interfacedetails = output.split("\n")
        vlanpresent = False
        for intfc in interfacedetails:
            intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
            if "vlan {" in intfc:
                vlanpresent =True
            if "id =" in intfc and "v" not in intfc:
                vlan_no = intfc.split(" ")[3]
            if "vid =" in intfc:
                vlanid = intfc.split(" ")[3]
                if vlanid == data['intfc_name'].split("Vlan")[1]:
                    break
        logger.info(f"vlan no({data['intfc_name']}): {vlan_no}")
        if vlanpresent:
            output = send_command_wo(shell, f'del lan vlan {vlan_no}')        
        if "OK" in output:            
            response = [{"message": f"Interface {data['intfc_name']} deleted"}]
        else:            
            response = [{"message": f"Error: Interface {data['intfc_name']} may not be deleted"}]
        logger.info(
            f"{response}",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "delete_vlan_interface",
                "exception": ""
            }
            )     
        output = send_command_wo(shell, f'config save_and_apply')                  
    except Exception as e:
        logger.error(
            f"Failed to delete VLAN interafce",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "delete_vlan_interface",
                "exception": str(e)
            }
            )
    finally:
        # Close the SSH connection
        ssh_client.close()
    return response

def addstaticroute(data):
    """
    Connects to a Robustel router via SSH and retrieves the output of 'status route'.
    """
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    response = [{"message": "Error while adding static route"} ]   
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "add_static_route",
                "exception": str(e)
            }
            )
            response = [{"message": "Connection timeout. pl try again! "}]   
            return response    
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, 'show route all')
        routedetails = output.split("\n")
        staticroutepresent = False
        for intfc in routedetails:
            intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
            if "static_route {" in intfc:
                staticroutepresent =True
            if "id =" in intfc and "v" not in intfc:
                staticroute_no = intfc.split(" ")[3]
        if staticroutepresent:
            if int(staticroute_no) == 40:
                response = [{"message": "Info: Robustel device allows upto 40 static route only"}] 
                ssh_client.close()
                logger.error(
                        f"{response}",
                        extra={
                            "device_type": "Robustel",
                            "device_ip": router_ip,
                            "api_endpoint": "add_static_route",
                            "exception": ""
                        }
                )
                return response
            staticroute_no = int(staticroute_no) + 1
        else:
            staticroute_no = 1  
        subnets = data["subnet_info"]  
        for subnet in subnets:        
            subnet_key = "destination" if "destination" in subnet else "subnet" if "subnet" in subnet else None
            if subnet_key:                
                corrected_dst = ipaddress.ip_network(subnet[subnet_key], strict=False)                
                dst_netmask = str(ipaddress.IPv4Network(corrected_dst.netmask)).split("/")[0]              
                corrected_subnet = ipaddress.ip_network(openvpn_network, strict=False)
                destination = str(corrected_dst).split("/")[0]
                ip_obj = ipaddress.ip_address(destination)
                if ip_obj in corrected_subnet:
                    response = [{"message": f"Error while adding route due to address conflict {destination}"}]
                    break                
                output = send_command_wo(shell, f'add route static_route {staticroute_no}')
                response = [{"message": "Error while adding static route"} ]             
                if "OK" in output:
                    output = send_command_wo(shell, f'set route static_route {staticroute_no} destination {destination}')
                    if "OK" in output:
                        output = send_command_wo(shell, f'set route static_route {staticroute_no} netmask {dst_netmask}')
                        if "OK" in output:                   
                            output = send_command_wo(shell, f'set route static_route {staticroute_no} gateway {subnet["gateway"]}')
                            if "OK" in output:   
                                response = [{"message": "Route(s) added"}]
                            else:
                                response = [{"message": "Error in setting gateway. Pl check & try again"}]
                        else:
                            response =[{"message": "Error in setting netmask. Pl check & try again"}]
                    else:
                        response = [{"message": "Error in setting destination. Pl check & try again"}]
                else:
                    response = [{"message": "Error in adding static route. Pl try again"}]
            if staticroute_no == 40:                
                break
            staticroute_no += 1
        logger.info(
            f"{response}",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "add_static_route",
                "exception": ""
            }
            )    
        output = send_command_wo(shell, f'config save_and_apply')                  
    except Exception as e:
        logger.error(
            f"Failed to add route",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "add_static_route",
                "exception": str(e)
            }
            )
    finally:
        # Close the SSH connection
        ssh_client.close()
    return response

def delstaticroute(data):
    """
    Connects to a Robustel router via SSH and retrieves the output of 'status route'.
    """
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:            
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "delete_static_route",
                "exception": str(e)
            }
            )
            response = [{"message": "Connection timeout. pl try again! "}]   
            return response     
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, 'show route all')
        staticroutedetails = output.split("\n")        
        subnets = data["routes_info"]
        for subnet in subnets:
            subnet_ip = subnet["destination"]
            for intfc in staticroutedetails:
                intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
                
                if "id =" in intfc and "v" not in intfc:
                    staticroute_no = intfc.split(" ")[3]
                if "destination =" in intfc:
                    destination = intfc.split(" ")[3]
                if "netmask =" in intfc:
                    dst_netmask = intfc.split(" ")[3]
                    network = f"{destination}/{dst_netmask}"
                    # Create an IPv4Network object
                    ipintf = ipaddress.IPv4Interface(network)
                    destination = str(ipintf.with_prefixlen)
                    if destination == subnet_ip:                 
                        output = send_command_wo(shell, f'del route static_route {staticroute_no}')
                        
                        if "OK" in output:                                        
                            response = [{"message": f"Route {subnet_ip} deleted"}]   
                        else:
                            response = [{"message": "Error while deleting route. Pl try again"}] 
                        logger.info(
                            f"{response}",
                            extra={
                                "device_type": "Robustel",
                                "device_ip": router_ip,
                                "api_endpoint": "delete_static_route",
                                "exception": ""
                                }
                        )  
        output = send_command_wo(shell, f'config save_and_apply')          
    except Exception as e:
        logger.error(
            f"Failed to delete route",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "delete_static_route",
                "exception": str(e)
            }
            )
    finally:
        # Close the SSH connection
        ssh_client.close()
    return response

def interface_config(data):
    """
    Connects to a Robustel router via SSH and retrieves the output of 'status route'.
    """
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "interface_config",
                "exception": str(e)
            }
            )
            response = [{"message": "Connection timeout. pl try again! "}]   
            return response      
        shell = ssh_client.invoke_shell()
        # Send the command and get the output

        output = get_command_output(shell, 'show lan all')
        interfacedetails = output.split("\n")
        if "Vlan" in data['intfc_name']:
            vlan_no = "None"
            current_addresses = []
            vlan_ip = data["new_addresses"][0]["address"].split("/")[0]
            for intfc in interfacedetails:
                intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
                if "id =" in intfc and "v" not in intfc:
                    vlan_no = intfc.split(" ")[3]
                if "vid =" in intfc:
                    vlanidn = intfc.split(" ")[3]
                    if vlanidn == data['intfc_name'].split("Vlan")[1]:
                        vlanid = vlanidn
                if "ip = " in intfc:
                    ipv4addres = intfc.split(" ")[3]            
                if "netmask = " in intfc:
                    netmask = intfc.split(" ")[3]
                    currentip = f"{ipv4addres}/{netmask}"
                    # Create an IPv4Network object
                    ipintf = ipaddress.IPv4Interface(currentip)
                    current_addresses.append(ipintf.with_prefixlen)
            for current_address in current_addresses:
                corrected_subnet = ipaddress.ip_network(current_address, strict=False)
                ip_obj = ipaddress.ip_address(vlan_ip)
                if ip_obj in corrected_subnet:
                    response = [{"message": f"Error while configuring VLAN interface due to address conflict {vlan_ip}"}]
                    logger.info(
                        f"{response}",
                        extra={
                            "device_type": "Robustel",
                            "device_ip": router_ip,
                            "api_endpoint": "interface_config",
                            "exception": ""
                        }
                    )
                    ssh_client.close()
                    return response     
            if vlan_no != "None":                
                subnet = ipaddress.IPv4Network(data["new_addresses"][0]["address"], strict=False)  # Allow non-network addresses
                netmask = str(subnet.netmask)
                corrected_subnet = ipaddress.ip_network(openvpn_network, strict=False)
                ip_obj = ipaddress.ip_address(vlan_ip)
                if ip_obj in corrected_subnet:
                    response = [{"message": f"Error while configuring  VLAN interface due to address conflict {multiple_ip}"}]
                else:     
                    output = send_command_wo(shell, f'set lan vlan {vlan_no} ip {vlan_ip}')
                    if "OK" in output:
                        output = send_command_wo(shell, f'set lan vlan {vlan_no} netmask {netmask}')
                        output = send_command_wo(shell, f'config save_and_apply')
                        if len(data["new_addresses"]) == 1:
                            response = [{"message": f"Interface {data['intfc_name']} updated"}]
                        else:
                            response = [{"message": f"Configured the Primary address on {data['intfc_name']}. It doesn't support secondary address "}]
                    else:
                        response = [{"message": f"Error while updating interface {data['intfc_name']}"}]                
            else:
                response = [{"message": "Error no such vlan available"}]
            
        elif "_IP_Alias" in data['intfc_name']:
            alias_id = []
            multi_ip = False
            for intfc in interfacedetails:
                intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
                if "multi_ip {" in intfc:
                    multi_ip = True                
                if "id =" in intfc and "v" not in intfc:
                    if multi_ip:
                        alias_id.append(intfc.split(" ")[3])
                        multi_ip = False
                if "ip = " in intfc:
                    if multi_ip:
                        multiple_ip = intfc.split(" ")[3]  
                        if multiple_ip.split(".")[0] != "10":
                            if multiple_ip.split(".")[0] == "172":
                                if 15 < int(multiple_ip.split(".")[1]) < 32:
                                    private_ip = True
                                else:
                                    private_ip = False
                            elif multiple_ip.split(".")[0] == "192":
                                if multiple_ip.split(".")[1] == "168":
                                    private_ip = True
                                else:
                                    private_ip = False
                            elif int(multiple_ip.split(".")[0]) > 223: 
                                private_ip = True
                            else:
                                private_ip = False
                        else:
                            private_ip = True

                        if not private_ip:
                            try:
                                os.system(f"sudo iptables -D FORWARD -p icmp -d {multiple_ip} -j ACCEPT")
                                os.system(f"sudo iptables -D FORWARD -p tcp -d {multiple_ip} -j DROP")
                                logger.info(f"Deleted the Ports closed rule {multiple_ip}, since this IP is deleted",
                                        extra={
                                                "device_type": "Robustel",
                                                "device_ip": router_ip,
                                                "api_endpoint": "interface_config",
                                                "exception": ""
                                        }
                                    )
                            except Exception as e:
                                logger.error(f"Error while delete the Ports closed rule {multiple_ip} in iptables",
                                        extra={
                                                "device_type": "Robustel",
                                                "device_ip": router_ip,
                                                "api_endpoint": "interface_config",
                                                "exception": str(e)
                                        }
                                    )
            if len(alias_id) > 0:
                for ipid in alias_id:
                    output = send_command_wo(shell, f'del lan multi_ip {ipid}')
            ipid = 1
            real_ip = []
            for datas in data["new_addresses"]: 
                multiple_ip = datas["address"].split("/")[0]
                subnet = ipaddress.IPv4Network(datas["address"], strict=False)  # Allow non-network addresses
                netmask1 = str(subnet.netmask)
                corrected_subnet = ipaddress.ip_network(openvpn_network, strict=False)
                ip_obj = ipaddress.ip_address(multiple_ip)
                if ip_obj in corrected_subnet:
                    response = [{"message": f"Error while configuring interface due to address conflict {multiple_ip}"}]
                    break                
                output = send_command_wo(shell, f'add lan multi_ip {ipid}')
                if "OK" in output:
                    output = send_command_wo(shell, f'set lan multi_ip {ipid} ip {multiple_ip}')
                    if "OK" in output:
                        output = send_command_wo(shell, f'set lan multi_ip {ipid} netmask {netmask1}')    
                        response = [{"message": f"Interface {data['intfc_name']} updated "}]  
                        
                        if multiple_ip.split(".")[0] != "10":
                            if multiple_ip.split(".")[0] == "172":
                                if 15 < int(multiple_ip.split(".")[1]) < 32:
                                    private_ip = True
                                else:
                                    private_ip = False
                            elif multiple_ip.split(".")[0] == "192":
                                if multiple_ip.split(".")[1] == "168":
                                    private_ip = True
                                else:
                                    private_ip = False
                            elif int(multiple_ip.split(".")[0]) > 223: 
                                private_ip = True
                            else:
                                private_ip = False
                        else:
                            private_ip = True

                        if not private_ip:
                            correctednetwork = str(ipaddress.ip_network(datas["address"], strict=False)).split("/")[0]
                            real_ip.append({"ip":multiple_ip, "netmask":netmask1, "ipprefix":correctednetwork})     
                                            
                    else:
                        response = [{"message": f"Error while updating interface {data['intfc_name']}"}]   
                    ipid = ipid + 1
                else:
                    response = [{"message": "Error while adding Multiple IP "}]   
                    break 
            output = send_command_wo(shell, f'config save_and_apply')
            spokename = data["spokedevice_name"]
            if len(real_ip) > 0:          
                for realip in real_ip:
                    try:
                        os.system(f"sudo iptables -A FORWARD -p icmp -d {realip['ip']} -j ACCEPT")
                        os.system(f"sudo iptables -A FORWARD -p tcp -d {realip['ip']} -j DROP")
                        logger.info(f"Ports closed for {realip['ip']}",
                                        extra={
                                                "device_type": "Robustel",
                                                "device_ip": router_ip,
                                                "api_endpoint": "interface_config",
                                                "exception": ""
                                        }
                                    )  
                        if os.path.exists(f"/etc/openvpn/server/ccd/{spokename}"):
                            with open(f"/etc/openvpn/server/ccd/{spokename}", "a") as f:
                                f.write(f"\niroute {realip['ipprefix']} {realip['netmask']} ")  
                                f.close()   
                        else:
                            with open(f"/etc/openvpn/server/ccd/{spokename}", "w") as f:
                                f.write(f"\niroute {realip['ipprefix']} {realip['netmask']} ")  
                                f.close()   

                        with open(f"/etc/openvpn/server/server.conf", "a") as f:
                            f.write(f"\nroute {realip['ipprefix']} {realip['netmask']} ")  
                            f.close()
                        logger.info(f"Route added for {realip['ip']} in HUB",
                                        extra={
                                                "device_type": "Robustel",
                                                "device_ip": router_ip,
                                                "api_endpoint": "interface_config",
                                                "exception": ""
                                        }
                                    )
                    except Exception as e:
                        logger.error(f"Error while adding ip {realip} in iptables",
                                        extra={
                                                "device_type": "Robustel",
                                                "device_ip": router_ip,
                                                "api_endpoint": "interface_config",
                                                "exception": str(e)
                                        }
                                    )
        logger.info(
            f"{response}",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "interface_config",
                "exception": ""
            }
            )
    except Exception as e:
        logger.error(
            f"Failed to configure interface",
            extra={
                "device_type": "Robustel",
                "device_ip": router_ip,
                "api_endpoint": "interface_config",
                "exception": str(e)
            }
            )
        # Close the SSH connection
        ssh_client.close()
    os.system("systemctl restart openvpn-server@server")  
    return response