import paramiko
import time
import ipaddress
#ansible

# Function to send a command and wait for the router's prompt
def send_command(shell, command, wait_time=2):
    shell.send(command + '\n')
    time.sleep(wait_time)  # Wait for the command to be processed  
    return 

def send_command_with_confirmation(shell, command, wait_time=1, confirmation_response="\n"):
    """
    Sends a command to the interactive shell and waits for any confirmation prompts.
    Sends the confirmation response if prompted.

    Args:
        shell (paramiko.Channel): The paramiko shell channel to communicate with.
        command (str): The command to execute.
        wait_time (int): Time to wait for command execution and response, in seconds.
        confirmation_response (str): The response to send when confirmation is needed.
    """
    # Send the initial command
    shell.send(command + "\n")
    time.sleep(wait_time)

    # Continuously check for the need for confirmation
    while True:
        # Check for incoming data
        if shell.recv_ready():
            output = shell.recv(1024).decode('utf-8')
            print(output)  # Print the output for debugging (can be removed)

            # Check if the output contains a confirmation prompt
            if "Destination filename" in output or "confirm" in output.lower():
                # Send the confirmation response (Enter key)
                shell.send(confirmation_response)
                time.sleep(wait_time)
                break  # Exit the loop once confirmation is handled

def configure_tunnel(shell, data):
    # Enter configuration mode
    send_command(shell, 'configure terminal')
    # Send configuration commands for tunnel
    send_command(shell, f'ip route {data["hub_ip"]} 255.255.255.255 {data["default_gw"]}')
    send_command(shell, 'interface tunnel1')
    send_command(shell, 'ip vrf forwarding reachlink')
    send_command(shell, f'ip address {data["tunnel_ip"]} 255.255.255.0')
    send_command(shell, f'tunnel source {data["wan_interface"]}')
    send_command(shell, f'tunnel destination {data["hub_ip"]}')
    send_command(shell, 'no shutdown')
    # Exit configuration mode
    send_command(shell, 'end')

def configure_ipsla(shell, data):
    # Enter configuration mode
    send_command(shell, 'configure terminal')
    # Send configuration commands for ip sla
    send_command(shell, 'ip sla 1')
    send_command(shell, f'icmp-echo {data["hub_tunnel_ip"]} source-interface tunnel1')
    send_command(shell, f'vrf reachlink')
    send_command(shell, f'frequency 5')
    send_command(shell, 'end')
    # Enter configuration mode
    send_command(shell, 'configure terminal')
    # Send command to start ip sla
    send_command(shell, 'ip sla schedule 1 life forever start-time now')
    # Send command to enable ip sla aoutodiscovery
    send_command(shell, 'ip sla auto discovery')
    send_comamnd(shell, f'access-list 106 permit ip host 0.0.0.0 host {data["hub_tunnel_ip"]}')
    send_command(shell, 'route-map leakroute-reachlink permit 10')
    send_command(shell, 'match ip address 106')
    send_command(shell, f'set ip vrf reachlink next-hop {data["hub_tunnel_ip"]}')
    send_command(shell, 'end')

def configure_track(shell, data):
    # Enter configuration mode
    send_command(shell, 'configure terminal')
    # Send configuration commands for ip sla
    send_command(shell, 'track 1 ip sla 1 reachability')   
    send_command(shell, 'ip route 10.200.202.0 255.255.255.0 tunnel1')
    send_command(shell, f'ip route vrf reachlink 0.0.0.0 0.0.0.0 {data["hub_tunnel_ip"]}')
    send_command(shell, 'end')

def configure_eem(shell, data):
    send_command_with_confirmation(shell, f"copy ftp://ftpuser:ftpuser23@{data['hub_ip']}/{data['file_name']} flash:{data['file_name']}")
    send_command(shell, 'configure terminal')
    #send_command(shell, 'event manger directory user policy “flash:/”')
    send_command(shell, f'event manager policy {data["file_name"]}')
    send_command(shell, 'end')

def configure_vrf(shell, data):
    send_command(shell, 'configure terminal')
    send_command(shell, f'ip vrf reachlink')
    send_command(shell, 'end')

def configure_lan(shell, data):
    send_command(shell, 'configure terminal')
    send_command(shell, f'int {data["lan_interface"]}')
    send_command(shell, 'ip policy route-map leakroute-reachlink')
    send_command(shell, 'ip vrf receive reachlink')
    send_command(shell, 'end')

def router_config(data):
    # Define the router details
    router_ip = data["router_ip"]
    username = data["device_username"]
    password = data['device_password']
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the router
    ssh_client.connect(hostname=router_ip, username=username, password=password)

    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    configure_vrf(shell, data)
    configure_tunnel(shell, data)
    configure_ipsla(shell, data)
    configure_eem(shell, data)
    configure_track(shell, data)  
    configure_lan(shell, data)  
    # Save the configuration
    send_command(shell, 'write memory')
    # Print the final output for verification
    send_command(shell, 'show ip interface brief', wait_time=2)

    # Close the SSH connection
    ssh_client.close()
    
def create_tunnel(data):
    router_config(data) 

def addroute(data):
    # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data['router_password']
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the router
    ssh_client.connect(hostname=router_ip, username=username, password=password)

    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    
    send_command(shell, 'configure terminal')
    subnets = data["subnet_info"]
    for subnet in subnets:
        subnet_ip = subnet["subnet"].split("/")[0]
        netmask = str(ipaddress.IPv4Network(subnet["subnet"]).netmask)
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

    # Connect to the router
    ssh_client.connect(hostname=router_ip, username=username, password=password)

    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    
    send_command(shell, 'configure terminal')
    subnets = data["subnet_info"]
    for subnet in subnets:
        subnet_ip = subnet["subnet"].split("/")[0]
        netmask = str(ipaddress.IPv4Network(subnet["subnet"]).netmask)
        send_command(shell, f'no ip route vrf reachlink {subnet_ip} {netmask}')
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

    # Connect to the router
    ssh_client.connect(hostname=router_ip, username=username, password=password)

    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    #data["subnet"] = "10.200.202.2"
    subnet_ip = data["subnet"].split("/")[0]
    status = send_command_ping(shell, f'ping vrf reachlink {subnet_ip}', wait_time=5)
    # Close the SSH connection
    ssh_client.close()
    return status
