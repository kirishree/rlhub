import paramiko
import time
import ipaddress
import re
port_number = 3366
import logging
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
            print(f"SSH Connection Error: {e}")
            # Connect to the router
            try:
                ssh_client.connect(hostname=router_ip, username=username, port=22, password=password, timeout=30, banner_timeout=60)
            except Exception as e:
                print(f"SSH Connection Error: {e}")
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
                routing_table.append({"protocol":"static",
                                "destination": destination,
                                "gateway": gateway,
                                "metric":"-",
                                "outgoint_interface_name": intfc.split(" ")[3],
                                "table_id": "main"})
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
            print(f"SSH Connection Error: {e}")
            # Connect to the router
            try:
                ssh_client.connect(hostname=router_ip, username=username, port=22, password=password, timeout=30, banner_timeout=60)
            except Exception as e:
                print(f"SSH Connection Error: {e}")
                return []      
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, f'ping {data["subnet"]}')
        ping_info = output.split("\n")
        avg_ms = "-1"
        for pinginfo in ping_info:
            if "100% packet loss" in pinginfo:
                break
            if "round-trip" in pinginfo:
                avg_ms = pinginfo.split("=")[1].split("/")[1]  
    except Exception as e:
        print(e)
        avg_ms = "-1"        
    finally:
        # Close the SSH connection
        ssh_client.close()
    return avg_ms

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
            print(f"SSH Connection Error: {e}")
            # Connect to the router
            try:
                ssh_client.connect(hostname=router_ip, username=username, port=22, password=password, timeout=30, banner_timeout=60)
            except Exception as e:
                print(f"SSH Connection Error: {e}")
                return []      
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, f'traceroute {data["trace_ip"]}')
        cleaned_output = clean_traceroute_output(output)
        
    except Exception as e:
        print(e)
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
            print(f"SSH Connection Error: {e}")
            # Connect to the router
            try:
                ssh_client.connect(hostname=router_ip, username=username, port=22, password=password, timeout=30, banner_timeout=60)
            except Exception as e:
                print(f"SSH Connection Error: {e}")
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
        print(e)
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
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            print(f"SSH Connection Error: {e}")
            # Connect to the router
            try:
                ssh_client.connect(hostname=router_ip, username=username, port=22, password=password, timeout=30, banner_timeout=60)
            except Exception as e:
                print(f"SSH Connection Error: {e}")
                return []      
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
        if vlanpresent:
            if int(vlan_no) == 10:
                response = [{"message": "Error: This device allows only 10 VLAN interface"}]   
                ssh_client.close()
                return response 
            vlan_no = int(vlan_no) + 1
        else:
            vlan_no = 1    
        print(vlan_no)
        output = send_command_wo(shell, f'add lan vlan {vlan_no}')
        response = [{"message": "Error while creating vlan interface"}]
        if "OK" in output:
            output = send_command_wo(shell, f'set lan vlan {vlan_no} enable true')
            if "OK" in output:
                output = send_command_wo(shell, f'set lan vlan {vlan_no} interface lan0')
                if "OK" in output:
                    vlan_ip = data["addresses"][0].split("/")[0]
                    subnet = ipaddress.IPv4Network(data["addresses"][0], strict=False)  # Allow non-network addresses
                    netmask = str(subnet.netmask)
                    output = send_command_wo(shell, f'set lan vlan {vlan_no} ip {vlan_ip}')
                    if "OK" in output:
                        output = send_command_wo(shell, f'set lan vlan {vlan_no} netmask {netmask}')
                        if "OK" in output:
                            output = send_command_wo(shell, f'set lan vlan {vlan_no} vid {data["vlan_id"]}')
                            if "OK" in output:
                                output = send_command_config(shell, f'config save_and_apply')
                                response = [{"message": f"Successfully vlan interface created lan0.{data['vlan_id']}"}]                         
    except Exception as e:
        print(e)
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
            print(f"SSH Connection Error: {e}")
            # Connect to the router
            try:
                ssh_client.connect(hostname=router_ip, username=username, port=22, password=password, timeout=30, banner_timeout=60)
            except Exception as e:
                print(f"SSH Connection Error: {e}")
                return []    
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
            if "interface =" in intfc:
                if data["intfc_name"] == intfc.split(" ")[3]:
                    break
        if vlanpresent:
            output = send_command_wo(shell, f'del lan vlan {vlan_no}')
        response = [{"message": f"Error while deleting vlan interface {data['intfc_name']}"}]
        if "OK" in output:            
            response = [{"message": f"Successfully vlan interface {data['intfc_name']} deleted"}]                         
    except Exception as e:
        print(e)
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
    response = {"message": "Error while adding static route"}    
    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, port=port_number, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            print(f"SSH Connection Error: {e}")
            # Connect to the router
            try:
                ssh_client.connect(hostname=router_ip, username=username, port=22, password=password, timeout=30, banner_timeout=60)
            except Exception as e:
                print(f"SSH Connection Error: {e}")
                return []  
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
                response = [{"message": "Error: Robustel device allows upto 40 static route only"}] 
                ssh_client.close()
                return response
            staticroute_no = int(staticroute_no) + 1
        else:
            staticroute_no = 1  
        subnets = data["subnet_info"]  
        for subnet in subnets:        
            subnet_key = "destination" if "destination" in subnet else "subnet" if "subnet" in subnet else None
            if subnet_key:
                destination = subnet[subnet_key].split("/")[0]
                dst_netmask = str(ipaddress.IPv4Network(subnet[subnet_key]).netmask)
                output = send_command_wo(shell, f'add route static_route {staticroute_no}')
                response = {"message": "Error while adding static route"}              
                if "OK" in output:
                    output = send_command_wo(shell, f'set route static_route {staticroute_no} destination {destination}')
                    if "OK" in output:
                        output = send_command_wo(shell, f'set route static_route {staticroute_no} netmask {dst_netmask}')
                        if "OK" in output:                   
                            output = send_command_wo(shell, f'set route static_route {staticroute_no} gateway {subnet["gateway"]}')
                            response = {"message": "Successfully added the route"}
            if staticroute_no == 40:
                break
            staticroute_no += 1                      
    except Exception as e:
        logger.error(f"Error: Adding route in Robustel Spoke:{e}")
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
            print(f"SSH Connection Error: {e}")
            # Connect to the router
            try:
                ssh_client.connect(hostname=router_ip, username=username, port=22, password=password, timeout=30, banner_timeout=60)
            except Exception as e:
                print(f"SSH Connection Error: {e}")
                return []  
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
                        response = [{"message": "Error while deleting route "}]
                        if "OK" in output:            
                            response = [{"message": f"Successfully deleted the route {subnet_ip}"}]                         
    except Exception as e:
        print(e)
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
            print(f"SSH Connection Error: {e}")
            # Connect to the router
            try:
                ssh_client.connect(hostname=router_ip, username=username, port=22, password=password, timeout=30, banner_timeout=60)
            except Exception as e:
                print(f"SSH Connection Error: {e}")
                return []    
        shell = ssh_client.invoke_shell()
        # Send the command and get the output

        output = get_command_output(shell, 'show lan all')
        interfacedetails = output.split("\n")
        if "Vlan" in data['intfc_name']:
            vlan_no = "None"
            for intfc in interfacedetails:
                intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
                if "id =" in intfc and "v" not in intfc:
                    vlan_no = intfc.split(" ")[3]
                if "vid =" in intfc:
                    vlanid = intfc.split(" ")[3]
                    if vlanid == data['intfc_name'].split("Vlan")[1]:
                        break
            print("vlan_no", vlan_no)
            if vlan_no != "None":
                vlan_ip = data["new_addresses"][0]["address"].split("/")[0]
                subnet = ipaddress.IPv4Network(data["new_addresses"][0]["address"], strict=False)  # Allow non-network addresses
                netmask = str(subnet.netmask)
                output = send_command_wo(shell, f'set lan vlan {vlan_no} ip {vlan_ip}')
                if "OK" in output:
                    output = send_command_wo(shell, f'set lan vlan {vlan_no} netmask {netmask}')
                    output = send_command_wo(shell, f'config save_and_apply')
                    response = [{"message": f"Successfully configured the interface {data['intfc_name']} "}]
                else:
                    response = [{"message": "Error while configuring IP address"}]                
            else:
                response = [{"message": "Error no such vlan available"}]
            print(response)
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
            if len(alias_id) > 0:
                for ipid in alias_id:
                    output = send_command_wo(shell, f'del lan multi_ip {ipid}')
            ipid = 1
            for datas in data["new_addresses"]: 
                multiple_ip = datas["address"].split("/")[0]
                subnet = ipaddress.IPv4Network(datas["address"], strict=False)  # Allow non-network addresses
                netmask = str(subnet.netmask)
                output = send_command_wo(shell, f'add lan multi_ip {ipid}')
                if "OK" in output:
                    output = send_command_wo(shell, f'set lan multi_ip {ipid} ip {multiple_ip}')
                    if "OK" in output:
                        output = send_command_wo(shell, f'set lan multi_ip {ipid} netmask {netmask}')    
                        response = [{"message": f"Successfully configured the interface {data['intfc_name']} "}]                    
                    else:
                        response = [{"message": f"Error while configuring IP address {datas['address']}"}]   
                    ipid = ipid + 1
                else:
                    response = [{"message": "Error while adding Multiple IP "}]   
                    break                  
            output = send_command_wo(shell, f'config save_and_apply')
    except Exception as e:
        print(f"Error in interface_config in robutel {e}")
        # Close the SSH connection
        ssh_client.close()
    return response