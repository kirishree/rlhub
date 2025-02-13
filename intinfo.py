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

def get_interface_cisco():
    """
    Connects to a Cisco router via SSH and retrieves the output of 'show ip int brief'.
    """
    router_ip = "78.110.5.90"
    username = "spoke4-compedu"
    password = "4kr5e@3l"

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
        output = get_command_output(shell, 'sh run | section include int')
        #print(output)
        interfacedetails = output.split("\n")[2:]
        print(interfacedetails)
        intfcname = "None"
        cidraddr = "None"
        netmask = "None"
        vlan_link = "None"
        intfcdetails = []
        for intfc in interfacedetails:
            print(intfc)
            if "interface" in intfc:
                if intfcname != "None":
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
                    intfcdetails.append({"interface_name": intfcname,
                                 "type": intfctype,
                                 
                                 "addresses":[{"IPv4address": cidraddr}],
                                 
                                 "vlan_link": vlan_link                             
                                })
                 
                intfcname = intfc.strip().split(" ")[1]
                cidraddr = "None"
                netmask = "None"
                vlan_link = "None"
                
            else:
                if "no ip address" in intfc:
                    cidraddr = "unassigned"
                elif "ip address" in intfc:
                    if len(intfc.strip().split("ip address")) > 1:
                        addrinfo = intfc.strip().split("ip address")[1].split(" ")
                        print(addrinfo)
                        ipaddr = addrinfo[1]
                        netmask = addrinfo[2]
                        network = f"{ipaddr}/{netmask}"
                        # Create an IPv4Network object
                        ipintf = ipaddress.IPv4Interface(network, strict=False)
                        cidraddr = ipintf.with_prefixlen
                if "vlan" in intfc:
                    vlan_link = intfc.strip().split("vlan")[1]
                if "dot1Q" in intfc:
                    vlan_link = intfc.strip().split(" ")[2]        
    except Exception as e:
        print(e)
    finally:
        # Close the SSH connection
        ssh_client.close()
    return intfcdetails

print(get_interface_cisco())