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

    finally:
        # Close the SSH connection
        ssh_client.close()
    return 
data = {"tunnel_ip":"10.8.0.9",
        "router_username": "etelriyad",
        "router_password": "Reachlink@08"}
get_routingtable_robustel(data)