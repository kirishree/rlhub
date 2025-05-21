import paramiko
import time
import ipaddress
import re
import logging
logger = logging.getLogger('reachlink')
#ansible
routes_protocol_map = {
    "L": "local",
    "C": "connected",
    "S": "static",
    "R": "RIP",
    "M": "mobile",
    "B": "BGP",
    "D": "EIGRP",
    "EX":"EIGRP external",
    "O": "OSPF",
    "IA": "OSPF inter area",
    "N1": "OSPF NSSA external type 1",
    "N2": "OSPF NSSA external type 2",
    "E1": "OSPF external type 1",
    "E2": "OSPF external type 2",
    "i": "IS-IS",
    "su": "IS-IS summary",
    "L1": "IS-IS level-1",
    "L2": "IS-IS level-2",
    "ia": "IS-IS inter area",
    "*": "candidate default",
    "U": "per-user static route",
    "o": "ODR",
    "P": "periodic downloaded static route",
    "H": "NHRP",
    "l": "LISP",
    "a": "application route",
    "+": "replicated route",
    "%": "next hop override",

}

# Function to send a command and wait for the router's prompt
def send_command(shell, command, wait_time=2):
    shell.send(command + '\n')
    time.sleep(wait_time)  # Wait for the command to be processed  
    return 

def send_command_wo(shell, command, delay=1):
    shell.send(command + '\n')
    time.sleep(delay)
    output = shell.recv(65535).decode('utf-8')
    return output

def addroute(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
    except Exception as e:
        logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "add_static_route",
                "exception": str(e)
            }
            )
        return False

    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    # Enter enable mode
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)
        
    send_command(shell, 'configure terminal')
    subnets = data["subnet_info"]
    for subnet in subnets:        
        subnet_key = "destination" if "destination" in subnet else "subnet" if "subnet" in subnet else None
        if subnet_key:
            subnet_ip = subnet[subnet_key].split("/")[0]
            netmask = str(ipaddress.IPv4Network(subnet[subnet_key]).netmask)
            send_command(shell, f'ip route {subnet_ip} {netmask} {subnet["gateway"]}')
    send_command(shell, 'end')
    # Save the configuration
    send_command(shell, 'write memory')    
    # Close the SSH connection
    ssh_client.close()
    return True

def delroute(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
    except Exception as e:
        logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "delete_static_route",
                "exception": str(e)
            }
            )
        return False
    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    # Enter enable mode
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)    
    send_command(shell, 'configure terminal')
    subnets = data["subnet_info"]
    for subnet in subnets:
        subnet_ip = subnet["subnet"].split("/")[0]
        netmask = str(ipaddress.IPv4Network(subnet["subnet"]).netmask)
        send_command(shell, f'no ip route {subnet_ip} {netmask}')
    send_command(shell, 'end')
    # Save the configuration
    send_command(shell, 'write memory')    
    # Close the SSH connection
    ssh_client.close()
    return True

def send_command_ping(shell, command, wait_time=5, buffer_size=4096, timeout=5, end_marker="Success rate"):
    """
    Sends a ping command and captures the full output from the shell.

    Args:
        shell: The shell object connected to the remote device.
        subnet_ip: The IP address to ping.
        wait_time: Initial wait time for command execution.
        buffer_size: The size of the buffer to read from the shell.
        timeout: Timeout value for receiving data from the shell.
        end_marker: A string indicating the end of the command's output.

    Returns:
        The complete output from the ping command.
    """
    # Send the ping command with a specific number of pings
    shell.send(command + '\n')  # Use -c for Linux systems; -n for Windows systems
    time.sleep(wait_time)  # Allow the command some time to start execution
    
    # Initialize an empty string to collect the command's output
    full_output = ""
    shell.settimeout(timeout)  # Set a timeout to avoid blocking indefinitely

    try:
        while True:
            # Read from the shell with a defined buffer size
            output = shell.recv(buffer_size).decode('utf-8')
            full_output += output

            # Check if the end marker (e.g., Success rate) is in the output
            if end_marker in full_output:
                break

    except Exception as e:
        print(f"Timeout or error occurred while reading output: {e}")

    shell.settimeout(None)  # Reset the timeout to blocking after completing the command

    return full_output

def pingspoke(data):   
    
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
    except Exception as e:
        logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "ping",
                "exception": str(e)
            }
            )
        return False
    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    # Enter enable mode
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)

    #data["subnet"] = "10.200.202.2"
    subnet_ip = data["subnet"].split("/")[0]
    status = send_command_ping(shell, f'ping {subnet_ip}', wait_time=5)
    # Close the SSH connection
    ssh_client.close()
    logger.info(
            f"{status}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "pingspoke",
                "exception": ""
            }
            )
    return status

def traceroute(data):    
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
    except Exception as e:
        logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "traceroute",
                "exception": str(e)
            }
            )
        return False

    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    # Enter enable mode
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)
    host_ip = data.get('trace_ip', None) 
    status = send_command_ping(shell, f'trace ip {host_ip}', wait_time=5)
    traceout = status.split("\r")
    final_out = ""
    for traceline in traceout:       
        if "type escape" in traceline.lower():
            continue
        if "tracing the route" in traceline.lower():
            continue
        if "info:" in traceline.lower():
            continue
        if "#" in traceline:
            continue
        final_out += traceline
    # Close the SSH connection
    ssh_client.close()
    return final_out


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

def get_routingtable_cisco(data):
    """
    Connects to a Cisco router via SSH and retrieves the output of 'show ip int brief'.
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
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "get_routing_table",
                "exception": str(e)
            }
            )
            return []        

        # Open an interactive shell session
        shell = ssh_client.invoke_shell()

        # Disable paging
        get_command_output(shell, 'terminal length 0', wait_time=1)

        # Send the command and get the output
        output = get_command_output(shell, 'show ip route')
#        routingdetails = output.split("\n")[12:-1]
        lineno = 0
        for routeline in output.split("\n"):
            lineno = lineno+1
            if "Gateway of last resort" in routeline:
                lineno = lineno+1
                break
        routingdetails = output.split("\n")[lineno:-1]
        routing_table = []
        for routeinfo in routingdetails:
            routeinfo = routeinfo.strip()
            # Clean up extra spaces or non-visible characters using regex
            routeinfo = re.sub(r'\s+', ' ', routeinfo)  # Replace multiple spaces with a single space
            #print(f"After regex cleanup: '{intfcinfo}'")
            if "." not in  routeinfo.split(" ")[0] and "[" not in routeinfo.split(" ")[0]:
                protocol = routeinfo.split(" ")[0]
                destination = routeinfo.split(" ")[1]
                if " is directly" in routeinfo:
                    interfacename = routeinfo.split(" ")[5]
                else:
                    interfacename = "-"
                if "via" in routeinfo:
                    gateway = routeinfo.split(" ")[4]
                    metric = routeinfo.split("[")[1].split("/")[0]
                else:
                    gateway = "-"
                    metric = 0
                routing_table.append({"outgoint_interface_name":interfacename,
                                                    "gateway":gateway,
                                                    "destination":destination,
                                                    "metric":int(metric),
                                                    "protocol":routes_protocol_map.get(protocol, "static"),
                                                    "table_id":"Main Routing Table"
                                                    })
            if "[" in routeinfo.split(" ")[0]:
                routing_table.append({"outgoint_interface_name":interfacename,
                                                    "gateway": routeinfo.split(" ")[2],
                                                    "destination":destination,
                                                    "metric":int(metric),
                                                    "protocol":routes_protocol_map.get(protocol, "static"),
                                                    "table_id":"Main Routing Table"
                                                    })

    finally:
        # Close the SSH connection
        ssh_client.close()
    return routing_table

def delstaticroute(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
    except Exception as e:
        logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "delete_static_route",
                "exception": str(e)
            }
            )
        return False
    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)

    send_command(shell, 'configure terminal')
    subnets = data["routes_info"]
    for subnet in subnets:
        subnet_ip = subnet["destination"].split("/")[0]
        netmask = str(ipaddress.IPv4Network(subnet["destination"]).netmask)
        send_command(shell, f'no ip route {subnet_ip} {netmask}')
    send_command(shell, 'end')
    # Save the configuration
    send_command(shell, 'write memory')    
    # Close the SSH connection
    ssh_client.close()
    return True

def createvlaninterface(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    for intfcname in data['link']:
        if intfcname.lower() == "fastethernet4":
            response = [{"message": "Pl remove  Layer 3 interface from Link interface"}]
            logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createvlan_interface",
                "exception": ""
            }
            )
            return response
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
    except Exception as e:
        logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createvlan_interface",
                "exception": str(e)
            }
            )
        return [{"message": f"Error: {router_ip} refued to connect. Try later"}]
    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    # Enter enable mode
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)

    vlan_ip = data["addresses"][0].split("/")[0]
    subnet = ipaddress.IPv4Network(data["addresses"][0], strict=False)  # Allow non-network addresses
    netmask = str(subnet.netmask)    
    send_command(shell, 'configure terminal')
    send_command(shell, f'vlan {data["vlan_id"]}')
    send_command(shell, f'end')
    send_command(shell, 'configure terminal')
    send_command(shell, f'interface vlan {data["vlan_id"]}')
    ipoutput = get_command_output(shell, f'ip address {vlan_ip} {netmask}')
    if "overlaps" in ipoutput:
        overlap_intfc = ipoutput.split("overlaps with ")[1].split(" ")
        overlapintfc = False                              
        overlapintfc = overlap_intfc[0].split("\r")[0]
        if overlapintfc:
            response = [{"message": f"Error: while configuring vlan due to address conflict with {overlapintfc}"}]
        else:
            response = [{"message": f"Error: while configuring vlan due to address conflict"}]
        send_command(shell, 'end')
        send_command(shell, 'configure terminal')
        send_command(shell, f'no interface vlan {data["vlan_id"]}')
        send_command(shell, 'end')

    else:
        send_command(shell, 'no shutdown')
        send_command(shell, 'end')
        for link_intfc in data["link"]:            
            output = get_command_output(shell, f'sh run | section include interface {link_intfc}')
            interfacedetails = output.split("\n")       
            vlanavailable = False
            vlanmode = f'switchport mode trunk'
            for intfc in interfacedetails: 
                if "allowed vlan" in intfc:
                    vlanavailable = True
                    vlancommand = intfc.split("1002-1005")[0] + f"{data['vlan_id']},1002-1005"
                    break
            if not vlanavailable:
                vlancommand = f"switchport trunk allowed vlan 1,{data['vlan_id']},1002-1005"      
            send_command(shell, 'configure terminal')
            send_command(shell, f'interface {link_intfc}')
            vlanmodeout = get_command_output(shell, f'{vlanmode}')        
            vlanmodeout2 = get_command_output(shell, f'{vlancommand}')   
            if "Vlan can not be added." in vlanmodeout2:                            
                response = [{"message": f"Error: vlan{data['vlan_id']} not linked with {link_intfc} "}]   
                send_command(shell, 'end')
                break
            else:
                response = [{"message": f"Interface vlan{data['vlan_id']} created"}]      
                send_command(shell, 'end')        
        # Save the configuration
    send_command(shell, 'write memory')     
    # Close the SSH connection
    ssh_client.close()
    logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createvlan_interface",
                "exception": ""
            }
            )
    return response

def createvlaninterface1(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    if data['link'].lower() == "fastethernet4":
        response = [{"message": "Error: Don't create a VLAN directly on a Layer 3 interface"}]
        logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createvlan_interface",
                "exception": ""
            }
            )
        return response
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
    except Exception as e:
        logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createvlan_interface",
                "exception": str(e)
            }
            )
        return [{"message": f"Error: {router_ip} refued to connect. Try later"}]
    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    # Enter enable mode
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)

    vlan_ip = data["addresses"][0].split("/")[0]
    subnet = ipaddress.IPv4Network(data["addresses"][0], strict=False)  # Allow non-network addresses
    netmask = str(subnet.netmask)
    # Send the command and get the output
    output = get_command_output(shell, f'sh run | section include interface {data["link"]}')
    interfacedetails = output.split("\n") 
    for intfc in interfacedetails: 
        if "switchport access vlan" in intfc:
            vlan_link = intfc.strip().split("vlan")[1]
            response = [{"message":f"Error: {data['link']} is linked with vlan {vlan_link}. Pl delete it before proceed"}]                
            ssh_client.close()
            logger.info(
                    f"{response}",
                    extra={
                        "device_type": "Cisco",
                        "device_ip": router_ip,
                        "be_api_endpoint": "createvlan_interface",
                        "exception": ""
                    }
            )
            return response
    vlanmode = f'switchport mode access'
    vlancommand = f"switchport access vlan {data['vlan_id']}"
    send_command(shell, 'configure terminal')
    send_command(shell, f'vlan {data["vlan_id"]}')
    send_command(shell, f'end')
    send_command(shell, 'configure terminal')
    send_command(shell, f'interface vlan {data["vlan_id"]}')
    ipoutput = get_command_output(shell, f'ip address {vlan_ip} {netmask}')
    if "overlaps" in ipoutput:        
        response = [{"message": f"Error: while configuring vlan due to address conflict {ipoutput}"}]
    else:
        send_command(shell, 'no shutdown')
        send_command(shell, 'end')
        send_command(shell, 'configure terminal')
        send_command(shell, f'interface {data["link"]}')
        send_command(shell, f'{vlanmode}')        
        vlanmodeout2 = get_command_output(shell, f'{vlancommand}')
        if "Vlan can not be added." in vlanmodeout2:
            send_command(shell, f'end')
            send_command(shell, 'configure terminal')
            send_command(shell, f'no interface vlan{data["vlan_id"]}')
            send_command(shell, f'end')
            if " Maximum number of 8 vlan(s) in the database" in vlanmodeout2:
                response = [{"message": f"Error: Maximum number of 8 vlan(s) only allowed"}] 
            else:
                response = [{"message": f"Error: Interface vlan{data['vlan_id']} not created. Pl try again!"}] 
        else:
            response = [{"message": f"Interface vlan{data['vlan_id']} created"}] 
        send_command(shell, 'end')
        # Save the configuration
        send_command(shell, 'write memory')         
    # Close the SSH connection
    ssh_client.close()
    logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createvlan_interface",
                "exception": ""
            }
            )
    return response

def createsubinterface(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    data['link'] = "FastEthernet4"    
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
    except Exception as e:
        logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createsub_interface",
                "exception": str(e)
            }
            )
        return [{"message": f"Error: {router_ip} refued to connect. Try later"}]

    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    # Enter enable mode
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)
    subinterface_ip = data["addresses"][0].split("/")[0]
    subnetip = ipaddress.IPv4Network(data["addresses"][0], strict=False)  # Allow non-network addresses
    netmask1 = str(subnetip.netmask)
    subinterfacename = data["link"] + "." + str(data["vlan_id"])
    send_command(shell, 'configure terminal')
    send_command(shell, f'interface {subinterfacename}')
    send_command(shell, f'encapsulation dot1Q {data["vlan_id"]}')    
    ipoutput = get_command_output(shell, f'ip address {subinterface_ip} {netmask1}')
    send_command(shell, 'no shutdown')
    send_command(shell, 'end')
    if "overlaps" in ipoutput:   
        overlap_intfc = ipoutput.split("overlaps with ")[1].split(" ")
        overlapintfc = False                              
        overlapintfc = overlap_intfc[0].split("\r")[0]
        if overlapintfc:
            response = [{"message": f"Interface {subinterfacename} created. Address is not assigned due to address conflict with {overlapintfc}"}]
        else:
            response = [{"message": f"Interface {subinterfacename} created. Address is not assigned due to address conflict."}]        
    else:
        response = [{"message": f"Sub-Interface {subinterfacename} created"}]
    # Save the configuration
    send_command(shell, 'write memory')    
    # Close the SSH connection
    ssh_client.close()
    logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createsub_interface",
                "exception": ""
            }
            )
    return response

def createloopbackinterface(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
    except Exception as e:
        logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createloopback_interface",
                "exception": str(e)
            }
            )
        return [{"message": f"Error: {router_ip} refued to connect. Try later"}]
    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    # Enter enable mode
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)

    loopback_ip = data["addresses"][0].split("/")[0]
    subnet = ipaddress.IPv4Network(data["addresses"][0], strict=False)  # Allow non-network addresses
    netmask = str(subnet.netmask)
    response = [{"message": f"Interface {data['loopback_intfc_name']} created"}]
    send_command(shell, 'configure terminal')
    send_command(shell, f'interface {data["loopback_intfc_name"]}')
    ipoutput = get_command_output(shell, f'ip address {loopback_ip} {netmask}')    
    if "overlaps" in ipoutput:
        overlap_intfc = ipoutput.split("overlaps with ")[1].split(" ")
        overlapintfc = False                              
        overlapintfc = overlap_intfc[0].split("\r")[0]
        if overlapintfc:
            response = [{"message": f"{data['loopback_intfc_name']} created. {data['addresses'][0]} is not configured due to address conflict with {overlapintfc}"}]
        else:
            response = [{"message": f"{data['loopback_intfc_name']} created. {data['addresses'][0]} is not configured due to address conflict"}]
    send_command(shell, 'no shutdown')
    send_command(shell, 'end')
    # Save the configuration
    send_command(shell, 'write memory')    
    # Close the SSH connection
    ssh_client.close()
    logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createloopback_interface",
                "exception": ""
            }
            )
    return response
def adduser(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    try:
        # Create an SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "adduser",
                "exception": str(e)
            }
            )
            return False
        
        # Open an interactive shell session
        shell = ssh_client.invoke_shell()
        time.sleep(1)
        
        # Enter enable mode
        output = send_command_wo(shell, 'enable')
        if "Password" in output:  # Prompt for enable password
            send_command_wo(shell, password)
        
        # Enter configuration mode
        send_command_wo(shell, 'configure terminal')
        
        # Add the user
        send_command_wo(shell, f'username {data["username"]} password {data["password"]}')
        
        # Exit configuration mode
        send_command_wo(shell, 'end')
        
        # Save the configuration
        send_command_wo(shell, 'write memory')
        
        # Close the SSH connection
        ssh_client.close()
        return True
    
    except Exception as e:
        logger.error(
            f"Error while adding user(Dialer)",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "adduser",
                "exception": str(e)
            }
            )
        return False

def deletevlaninterface(data):
    try:
        # Define the router details
        if "ether" in data["intfc_name"].lower() and "." not in data["intfc_name"].lower():
            print(data)
            response = [{"message": f"Error: Not able to delete physical interface"}]
            return response        
        router_ip = data["tunnel_ip"].split("/")[0]
        username = data["router_username"]
        password = data['router_password']
        # Create an SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "delete_interface",
                "exception": str(e)
            }
            )
            return [{"message": f"Error: {router_ip} refued to connect. Try later"}]
        # Open an interactive shell session
        shell = ssh_client.invoke_shell()

        # Add a delay to allow the shell to be ready
        time.sleep(1)
        # Enter enable mode
        vlanlinkinfo = []
        output = send_command_wo(shell, 'enable')
        if "Password" in output:  # Prompt for enable password
            send_command_wo(shell, password)
        if "vlan" in data["intfc_name"].lower():
            vlanid = data["intfc_name"].lower().split("vlan")[1]            
            output = get_command_output(shell, f'sh run | section include interface')
            interfacedetails = output.split("\n")       
            for intfc in interfacedetails:                 
                if "interface" in intfc:
                    intfc_name = intfc.strip().split("interface")[1]      
                if "allowed vlan" in intfc:
                    if f",{vlanid}," in intfc:
                        print("allowed vlan", intfc)
                        vlancommand = intfc.split(f",{vlanid},")[0] + ","  + intfc.split(f",{vlanid},")[1]                        
                        vlanlinkinfo.append({"intfc": intfc_name,
                                             "vlancommand": vlancommand})         
                #if "access vlan" in intfc:                    
                 #   if vlanid == intfc.strip().split("vlan")[1]:
                 #       vlancommand = "no" + intfc
                 #       break  
            logger.info(
                    f"{vlanlinkinfo}",
                    extra={
                        "device_type": "Cisco",
                        "device_ip": router_ip,
                        "be_api_endpoint": "delete_interface",
                        "exception": ""
                    }
                )                
        send_command(shell, 'configure terminal')
        send_command(shell, f'no interface {data["intfc_name"]}')
        deleteoutput = send_command_wo(shell, 'end')
        if " not be deleted" in deleteoutput:
            response = [{"message": f"Error: Interface {data['intfc_name']} may not be deleted"}]  
        else:
            for linkvlan in vlanlinkinfo:
                send_command(shell, 'configure terminal')
                send_command(shell, f'interface {linkvlan["intfc"]}')
                send_command(shell, f'{linkvlan["vlancommand"]}')
                send_command_wo(shell, 'end')
            response = [{"message": f"Interface {data['intfc_name']} deleted"}]   
        #Save the configuration
        send_command(shell, 'write memory')    
        # Close the SSH connection
        ssh_client.close()
    except Exception as e:
        logger.error(
            f"Error while deleting Interface",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "delete_interface",
                "exception": str(e)
            }
            )
        response = [{"message": f"Error while deleting interface {data['intfc_name']}. Pl try again!"}]      
    logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "delete_interface",
                "exception": ""
            }
            )
    return response

def createtunnelinterface(data):
    try:
        # Define the router details
        router_ip = data["tunnel_ip"].split("/")[0]
        username = data["router_username"]
        password = data['router_password']
        # Create an SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createtunnel_interface",
                "exception": str(e)
            }
            )
            return [{"message": f"Error: {router_ip} refued to connect. Try later"}]
        # Open an interactive shell session
        shell = ssh_client.invoke_shell()

        # Add a delay to allow the shell to be ready
        time.sleep(1)
        # Enter enable mode
        output = send_command_wo(shell, 'enable')
        if "Password" in output:  # Prompt for enable password
            send_command_wo(shell, password)
        tunnel_ip = data["addresses"][0].split("/")[0]
        subnet = ipaddress.IPv4Network(data["addresses"][0], strict=False)  # Allow non-network addresses
        netmask = str(subnet.netmask)
        response = [{"message": f"Interface {data['tunnel_intfc_name']} created"}]
        send_command(shell, 'configure terminal')
        send_command(shell, f'interface {data["tunnel_intfc_name"]}')
        ipoutput = get_command_output(shell, f'ip address {tunnel_ip} {netmask}')           
        if "overlaps" in ipoutput:
            overlap_intfc = ipoutput.split("overlaps with ")[1].split(" ")
            overlapintfc = False                              
            overlapintfc = overlap_intfc[0].split("\r")[0]
            if overlapintfc:
                response = [{"message": f"{data['tunnel_intfc_name']} created. {data['addresses'][0]} is not configured due to address conflict with {overlapintfc}"}]
            else:
                response = [{"message": f"{data['tunnel_intfc_name']} created. {data['addresses'][0]} is not configured due to address conflict"}]
        send_command(shell, "ip tcp adjust-mss 1450")
        send_command(shell, f"tunnel source {data['link']}")
        send_command(shell, f"tunnel destination {data['destination_ip']}")
        send_command(shell, 'no shutdown')
        send_command(shell, 'end')
        # Save the configuration
        send_command(shell, 'write memory')           
        # Close the SSH connection
        ssh_client.close()
        logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createtunnel_interface",
                "exception": ""
            }
            )
    except Exception as e:
        response = [{"message": f"Error while creating tunnel interface"}]
        logger.error(
            response,
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createtunnel_interface",
                "exception": str(e)
            }
            )    
    return response

def interfaceconfig(data):
    try:
        # Define the router details
        if data["intfc_name"].lower() == "fastethernet4" or data["intfc_name"].lower() == "dialer1":
            response = [{"message": f"Error don't try to modify {data['intfc_name']} interface address"}]
            return response
        if "ether" in data["intfc_name"].lower() and "." not in data["intfc_name"].lower():
            response = [{"message": f"Error Not able to configure IP on layer 2 interface"}]
            return response
        if "virtual-template" in data["intfc_name"].lower():
            response = [{"message": f"Error Not able to configure IP on {data['intfc_name']} interface"}]
            return response
        router_ip = data["tunnel_ip"].split("/")[0]
        username = data["router_username"]
        password = data['router_password']
        # Create an SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "interface_config",
                "exception": str(e)
            }
            )
            return [{"message": f"Error: {router_ip} refued to connect. Try later"}]
        # Open an interactive shell session
        shell = ssh_client.invoke_shell()

        # Add a delay to allow the shell to be ready
        time.sleep(1)
        # Enter enable mode
        output = send_command_wo(shell, 'enable')
        if "Password" in output:  # Prompt for enable password
            send_command_wo(shell, password)
        send_command(shell, "configure terminal")
        send_command(shell, f"interface {data['intfc_name']}")
        send_command(shell, "no ip address")
        send_command(shell, 'end')
        response = [{"message": f"Interface {data['intfc_name']} updated"}]
        send_command(shell, "configure terminal")
        send_command(shell, f"interface {data['intfc_name']}")         
        for newaddr in data["new_addresses"]:
            interface_ip = newaddr['address'].split("/")[0]
            subnet = ipaddress.IPv4Network(newaddr['address'], strict=False)  # Allow non-network addresses
            netmask = str(subnet.netmask)
            if newaddr['primary'].lower() == "true":
                ipoutput = get_command_output(shell, f"ip address {interface_ip} {netmask}") 
                if "overlaps" in ipoutput:   
                    overlap_intfc = ipoutput.split("overlaps with ")[1].split(" ")                    
                    overlapintfc = False                              
                    overlapintfc = overlap_intfc[0].split("\r")[0]
                    if overlapintfc:
                        response = [{"message": f"Error: {newaddr['address']} is not assigned due to address conflict with {overlapintfc}"}]
                    else:
                        response = [{"message": f"Error: {newaddr['address']} is not assigned due to address conflict."}]  
                    break
            else:
               secipoutput = get_command_output(shell, f"ip address {interface_ip} {netmask} sec")        
               if "overlaps" in secipoutput:   
                    overlap_intfc = secipoutput.split("overlaps with ")[1].split(" ")                    
                    overlapintfc = False                    
                    overlapintfc = overlap_intfc[0].split("\r")[0]
                    if overlapintfc:
                        response = [{"message": f"Error: {newaddr['address']} is not assigned due to address conflict with {overlapintfc}"}]
                    else:
                        response = [{"message": f"Error: {newaddr['address']} is not assigned due to address conflict."}]  
                    break          
        send_command(shell, "no shutdown")
        send_command(shell, 'end')
        # Save the configuration
        send_command(shell, 'write memory')    
        # Close the SSH connection
        ssh_client.close()
        logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "interface_config",
                "exception": ""
            }
            )
    except Exception as e:
        response = [{"message": f"Error while updating the interface {data['intfc_name']} "}]
        logger.error(
            f"Error while configuring interface",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createtunnel_interface",
                "exception": str(e)
            }
            )    
    return response

def interfaceconfig1(data):
    try:
        # Define the router details
        if data["intfc_name"].lower() == "fastethernet4" or data["intfc_name"].lower() == "dialer1":
            response = [{"message": f"Error don't try to modify {data['intfc_name']} interface address"}]
            return response
        if "ether" in data["intfc_name"].lower() and "." not in data["intfc_name"].lower():
            response = [{"message": f"Error Not able to configure IP on layer 2 interface"}]
            return response
        router_ip = data["tunnel_ip"].split("/")[0]
        username = data["router_username"]
        password = data['router_password']
        # Create an SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "interface_config",
                "exception": str(e)
            }
            )
            return [{"message": f"Error: {router_ip} refued to connect. Try later"}]
        # Open an interactive shell session
        shell = ssh_client.invoke_shell()

        # Add a delay to allow the shell to be ready
        time.sleep(1)
        # Enter enable mode
        output = send_command_wo(shell, 'enable')
        if "Password" in output:  # Prompt for enable password
            send_command_wo(shell, password)
        send_command(shell, "configure terminal")
        send_command(shell, f"interface {data['intfc_name']}")
        send_command(shell, "no ip address")
        send_command(shell, 'end')
        # Disable paging
        get_command_output(shell, 'terminal length 0', wait_time=1)
        # Send the command and get the output
        output = get_command_output(shell, 'show ip int brief')
        interfacedetails = output.split("\n")[2:-1]
        interface_addresses = [] 
        for intfcinfo in interfacedetails:            
            intfcinfo = intfcinfo.strip()
            # Clean up extra spaces or non-visible characters using regex
            intfcinfo = re.sub(r'\s+', ' ', intfcinfo)  # Replace multiple spaces with a single space
            if intfcinfo.split(" ")[1] != "unassigned":
                interface_addresses.append(intfcinfo.split(" ")[1]) 
        for int_addr in data["new_addresses"]:
            for address in interface_addresses:
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(int_addr["address"].split("/")[0])
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring interface due to address conflict {int_addr}"}]
                    ssh_client.close()            
                    return response
        send_command(shell, "configure terminal")
        send_command(shell, f"interface {data['intfc_name']}") 
        for newaddr in data["new_addresses"]:
            interface_ip = newaddr['address'].split("/")[0]
            subnet = ipaddress.IPv4Network(newaddr['address'], strict=False)  # Allow non-network addresses
            netmask = str(subnet.netmask)
            if newaddr['primary'].lower() == "true":
                send_command(shell, f"ip address {interface_ip} {netmask}") 
            else:
                send_command(shell, f"ip address {interface_ip} {netmask} sec")             
        response = [{"message": f"Interface {data['intfc_name']} updated"}]
        send_command(shell, "no shutdown")
        send_command(shell, 'end')
        # Save the configuration
        send_command(shell, 'write memory')    
        # Close the SSH connection
        ssh_client.close()
    except Exception as e:
        response = [{"message": f"Error while updating the interface {data['intfc_name']} "}]
        logger.error(
            f"Error while configuring interface",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "createtunnel_interface",
                "exception": str(e)
            }
            )
    logger.info(
            f"{response}",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "interface_config",
                "exception": ""
            }
            )
    return response


def get_interface_cisco(data):
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
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "get_interface",
                "exception": str(e)
            }
            )
            return intfcdetails

        # Open an interactive shell session
        shell = ssh_client.invoke_shell()

        # Disable paging
        get_command_output(shell, 'terminal length 0', wait_time=1)

        # Send the command and get the output
        output = get_command_output(shell, 'sh run | section include int')
        #print(output)
        interfacedetails = output.split("\n")[2:]
        
        intfcname = "None"
        cidraddr = "None"
        netmask = "None"
        vlan_link = "None"
        intfcdetails = []
        for intfc in interfacedetails:            
            if "interface" in intfc:
                if intfcname != "None":
                    if "ethernet" in intfcname.lower():
                        intfctype = "ether"
                    elif "vlan" in intfcname.lower():
                        intfctype = "VLAN"                        
                        vlan_link = intfcname.lower().split("vlan")[1]
                    elif "loopback" in intfcname.lower():
                        intfctype = "Loopback"
                    elif "tunnel" in intfcname.lower():
                        intfctype = "Tunnel"
                    elif "dialer" in intfcname.lower():
                        intfctype = "Dialer"
                    elif "bvi" in intfcname.lower():
                        intfctype = "BVI"
                    if "." in intfcname:
                        intfctype = "SubInterface"
                    if "virtual-template" in intfcname.lower():
                        intfctype = "Virtual"
                    intfcdetails.append({"interface_name": intfcname,
                                 "type": intfctype,                                 
                                 "addresses":cidraddr,                                 
                                 "vlan_link": vlan_link,
                                 "gateway": '-'                        
                                })                 
                intfcname = intfc.strip().split(" ")[1]
                cidraddr = []
                netmask = "None"
                if "vlan" in intfcname.lower():
                    vlan_link = intfcname.lower().split("vlan")[1]
                else:
                    vlan_link = "None"                
            else:
                if "no ip address" in intfc:
                    cidraddr.append({"IPv4address" :"unassigned", "primary": True})
                elif "ip address" in intfc:
                    if len(intfc.strip().split("ip address")[1].split(" ")) > 2:
                        addrinfo = intfc.strip().split("ip address")[1].split(" ")
                        ipaddr = addrinfo[1]
                        netmask = addrinfo[2]
                        network = f"{ipaddr}/{netmask}"
                        # Create an IPv4Network object
                        ipintf = ipaddress.IPv4Interface(network)
                        primary= True
                        if "secondary" in intfc:
                            primary = False
                        cidraddr.append({"IPv4address" :ipintf.with_prefixlen, "primary": primary})
                if "vlan" in intfc and "add" not in intfc:
                    if len(intfc.strip().split("vlan")) > 1:                        
                            vlan_link = intfc.strip().split("vlan 1,")[1].split(",1002-1005")[0]
                if "allowed vlan add" in intfc:
                    vlan_link += ","
                    vlan_link += intfc.strip().split("add ")[1].split(",1002-1005")[0]
                if "dot1Q" in intfc:
                    if len(intfc.strip().split(" ")) > 2:
                        vlan_link = intfc.strip().split(" ")[2]   
        intfcdetails.append({"interface_name": intfcname,
                                 "type": intfctype,                                 
                                 "addresses":cidraddr,                                 
                                 "vlan_link": vlan_link,
                                 "gateway": '-'                        
                                })   
        # Disable paging
        get_command_output(shell, 'terminal length 0', wait_time=1)
        # Send the command and get the output
        output = get_command_output(shell, 'show ip int brief')
        interfacedetails = output.split("\n")[2:-1]
        intfcdetailsnew = []
        for intfcinfo in interfacedetails:            
            intfcinfo = intfcinfo.strip()
            # Clean up extra spaces or non-visible characters using regex
            intfcinfo = re.sub(r'\s+', ' ', intfcinfo)  # Replace multiple spaces with a single space
            intfcname = intfcinfo.split(" ")[0]
            intfctype = "-"            
            if "virtual-access" not in intfcname.lower():
                intfcdetailsnew.append({"interface_name": intfcinfo.split(" ")[0],                                                                 
                                 "status": intfcinfo.split(" ")[4],
                                 "protocol": intfcinfo.split(" ")[5],
                                 "method": intfcinfo.split(" ")[3]
                                }) 
        interfaceinfo = []
        for info in intfcdetails:
            for infonew in intfcdetailsnew:
                if info["interface_name"] == infonew["interface_name"]:
                    interfaceinfo.append({"interface_name": info["interface_name"],
                                 "type": info["type"],
                                 "Gateway": '-',
                                 "mac_address": "-",
                                 "addresses":info["addresses"], 
                                 "status": infonew["status"],
                                 "protocol": infonew["protocol"],
                                 "method": infonew["method"],
                                 "vlan_link": info["vlan_link"]
                                })    
    except Exception as e:
        logger.error(
            f"Error while get interface",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "get_interface",
                "exception": str(e)
            }
            )
    finally:
        # Close the SSH connection
        ssh_client.close()
    return interfaceinfo

def removeuser(data):
    try:
        # Define the router details
        router_ip = data["tunnel_ip"].split("/")[0]
        username = data["router_username"]
        password = data['router_password']
        # Create an SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
        except Exception as e:
            logger.error(
            f"SSH Connection Error",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "remove user",
                "exception": str(e)
            }
            )
            return [{"message": f"Error: {router_ip} refued to connect. Try later"}]
        # Open an interactive shell session
        shell = ssh_client.invoke_shell()

        # Add a delay to allow the shell to be ready
        time.sleep(1)
        # Enter enable mode
        output = send_command_wo(shell, 'enable')
        if "Password" in output:  # Prompt for enable password
            send_command_wo(shell, password)
        # Enter configuration mode
        send_command_wo(shell, 'configure terminal')
        
        # Add the user
        nouseroutput = send_command_wo(shell, f'no username {data["username"]}')
        if "This operation will remove all username related configurations with same name.Do you want to continue? [confirm]" in nouseroutput:
            send_command_wo(shell, "")
        # Exit configuration mode
        send_command_wo(shell, 'end')
        
        # Save the configuration
        send_command_wo(shell, 'write memory')
        
        # Close the SSH connection
        ssh_client.close()
        return True
    
    except Exception as e:
        logger.error(
            f"Error while removing user (Dialer) for deactivating",
            extra={
                "device_type": "Cisco",
                "device_ip": router_ip,
                "be_api_endpoint": "remove user",
                "exception": str(e)
            }
            )
        return False
