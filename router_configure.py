import paramiko
import time
import ipaddress
import re
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
        ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
    except Exception as e:
        print(f"SSH Connection Error: {e}")
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
        ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
    except Exception as e:
        print(f"SSH Connection Error: {e}")
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

# Example usage
# Assuming `shell` is an interactive shell object connected to a Cisco router
# shell = some_interactive_shell_session()
# output = send_command_ping(shell, '10.200.202.5', wait_time=5)
# print(output)


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
        ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
    except Exception as e:
        print(f"SSH Connection Error: {e}")
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
    return status

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
            ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            print(f"SSH Connection Error: {e}")
            return intfcdetails

        # Open an interactive shell session
        shell = ssh_client.invoke_shell()

        # Disable paging
        get_command_output(shell, 'terminal length 0', wait_time=1)

        # Send the command and get the output
        output = get_command_output(shell, 'show ip int brief')
        interfacedetails = output.split("\n")[2:-1]
        
        for intfcinfo in interfacedetails:
            
            intfcinfo = intfcinfo.strip()
            # Clean up extra spaces or non-visible characters using regex
            intfcinfo = re.sub(r'\s+', ' ', intfcinfo)  # Replace multiple spaces with a single space
 #           print(f"After regex cleanup: '{intfcinfo}'")
            intfcname = intfcinfo.split(" ")[0]
            intfctype = "-"
            if "ethernet" in intfcname.lower():
                intfctype = "ether"
            elif "vlan" in intfcname.lower():
                intfctype = "VLAN"
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
            if "virtual-access" not in intfcname.lower():
                intfcdetails.append({"interface_name": intfcinfo.split(" ")[0],
                                 "type": intfctype,
                                 "Gateway": '-',
                                 "mac_address": "-",
                                 "addresses":[{"IPv4address": intfcinfo.split(" ")[1]}], 
                                 "status": intfcinfo.split(" ")[4],
                                 "protocol": intfcinfo.split(" ")[5],
                                 "method": intfcinfo.split(" ")[3]
                                })
    finally:
        # Close the SSH connection
        ssh_client.close()
    return intfcdetails

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
            ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            print(f"SSH Connection Error: {e}")
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
        ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
    except Exception as e:
        print(f"SSH Connection Error: {e}")
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
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
    except Exception as e:
        print(f"SSH Connection Error: {e}")
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
    send_command(shell, f'ip address {vlan_ip} {netmask}')
    send_command(shell, 'no shutdown')
    send_command(shell, 'end')
    send_command(shell, 'configure terminal')
    send_command(shell, f'interface {data["link"]}')
    send_command(shell, 'switchport mode access')
    send_command(shell, f'switchport access vlan {data["vlan_id"]}')
    send_command(shell, 'end')
    # Save the configuration
    send_command(shell, 'write memory')    
    # Close the SSH connection
    ssh_client.close()
    return [{"message": "Successfully vlan interface created"}]

def createsubinterface(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
    except Exception as e:
        print(f"SSH Connection Error: {e}")
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
    subnet = ipaddress.IPv4Network(data["addresses"][0], strict=False)  # Allow non-network addresses
    netmask = str(subnet.netmask)
    subinterfacename = data["link"] + "." + str(data["vlan_id"])

    send_command(shell, 'configure terminal')
    send_command(shell, f'interface {subinterfacename}')
    send_command(shell, f'encapsulation dot1Q {data["vlan_id"]}')
    send_command(shell, f'ip address {subinterface_ip} {netmask}')
    send_command(shell, 'no shutdown')
    send_command(shell, 'end')
   
    # Save the configuration
    send_command(shell, 'write memory')    
    # Close the SSH connection
    ssh_client.close()
    return [{"message": "Successfully sub-interface created"}]

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
        ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
    except Exception as e:
        print(f"SSH Connection Error: {e}")
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

    send_command(shell, 'configure terminal')
    send_command(shell, f'interface {data["loopback_intfc_name"]}')
    send_command(shell, f'ip address {loopback_ip} {netmask}')
    send_command(shell, 'no shutdown')
    send_command(shell, 'end')
    # Save the configuration
    send_command(shell, 'write memory')    
    # Close the SSH connection
    ssh_client.close()
    return [{"message": f"Successfully {data['loopback_intfc_name']} interface created"}]

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
            ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            print(f"SSH Connection Error: {e}")
            return False
        
        # Open an interactive shell session
        shell = ssh_client.invoke_shell()
        time.sleep(1)
        
        # Enter enable mode
        output = send_command_wo(shell, 'enable')
        if "Password" in output:  # Prompt for enable password
            send_command_wo(shell, "123@aabid.com")
        
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
        print(f"Error: {e}")
        return False

def deletevlaninterface(data):
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
            ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            print(f"SSH Connection Error: {e}")
            return [{"message": f"Error: {router_ip} refued to connect. Try later"}]
        # Open an interactive shell session
        shell = ssh_client.invoke_shell()

        # Add a delay to allow the shell to be ready
        time.sleep(1)
        # Enter enable mode
        output = send_command_wo(shell, 'enable')
        if "Password" in output:  # Prompt for enable password
            send_command_wo(shell, password)
        send_command(shell, 'configure terminal')
        send_command(shell, f'no interface {data["intfc_name"]}')
        send_command(shell, 'end')
   
        # Save the configuration
        send_command(shell, 'write memory')    
        # Close the SSH connection
        ssh_client.close()
    except Exception as e:
        print(e)
    return [{"message": f"Succesfully interface {data['intfc_name']} deleted"}]

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
            ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            print(f"SSH Connection Error: {e}")
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

        send_command(shell, 'configure terminal')
        send_command(shell, f'interface {data["tunnel_intfc_name"]}')
        send_command(shell, f'ip address {tunnel_ip} {netmask}')
        send_command(shell, "ip tcp adjust-mss 1450")
        send_command(shell, f"tunnel source {data['link']}")
        send_command(shell, f"tunnel destination {data['destination_ip']}")
        send_command(shell, 'no shutdown')
        send_command(shell, 'end')
        # Save the configuration
        send_command(shell, 'write memory')    
        # Disable paging
        get_command_output(shell, 'terminal length 0', wait_time=1)

        # Send the command and get the output
        output1 = get_command_output(shell, 'show ip int brief')
        # Validate Interface Existence
        if data["tunnel_intfc_name"] not in output1:
            return [{"message": f"Error: Tunnel interface {data['tunnel_intfc_name']} not found after creation"}]

        # Close the SSH connection
        ssh_client.close()
    except Exception as e:
        print(e)
    return [{"message": f"Succesfully tunnel interface {data['tunnel_intfc_name']} created"}]