import paramiko
import time
import ipaddress
import re

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
            ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
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
    finally:
        # Close the SSH connection
        ssh_client.close()
    return routing_table[1:]

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
            ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            print(f"SSH Connection Error: {e}")
            return intfcdetails

        # Open an interactive shell session
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        output = get_command_output(shell, 'show lan all')
        interfacedetails = output.split("\n")
        intfc_datas = []
        status = "up"
        for intfc in interfacedetails:
            intfc = re.sub(r'\s+', ' ', intfc)  # Replace multiple spaces with a single space
            if "interface =" in intfc:
                interface = intfc.split(" ")[3]
                interfacetype = "ether"
                vlanid = "None"
            if "vid = " in intfc:
                vlanid = intfc.split(" ")[3]
                interfacetype = "vlan"
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
                intfc_datas.append({"interface_name": interface,
                                 "type": interfacetype,
                                 "Gateway": '-',
                                 "mac_address": "-",
                                 "addresses":[{"IPv4address" :ipintf.with_prefixlen, "primary": True}], 
                                 "status": status,
                                 "protocol": "static",                                 
                                 "vlan_link": vlanid
                                })
                status = "up"
    except Exception as e:
        print(e)
    finally:
        # Close the SSH connection
        ssh_client.close()
    return intfc_datas


#data = {"tunnel_ip":"10.8.0.9",
#       "router_username": "etelriyad",
#       "router_password": "Reachlink@08"}
#print(get_interface_robustel(data))