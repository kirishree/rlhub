import paramiko
import time


def send_command(shell, command, wait_time=2):
    shell.send(command + '\n')
    time.sleep(wait_time)  # Wait for the command to be processed  
    return 

def send_command_wo(shell, command, delay=1):
    shell.send(command + '\n')
    time.sleep(delay)
    output = shell.recv(65535).decode('utf-8')
    return output

def set_openvpn_client(data):
    """
    Connects to a Robustel router via SSH and create OpenVPN tunnel in client mode'.
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
        config_commands = [
                            "add openvpn tunnel 1",
                            "set openvpn tunnel 1 enable true",
                            "set openvpn tunnel 1 desc reachlink",
                            "set openvpn tunnel 1 mode client",
                            "set openvpn tunnel 1 protocol tcp_client",
                            "set openvpn tunnel 1 peer_addr 185.69.209.251",
                            "set openvpn tunnel 1 peer_port 1194",
                            "set openvpn tunnel 1 interface_type tun",
                            "set openvpn tunnel 1 auth_type x509ca",
                            "set openvpn tunnel 1 encryption aes_256",
                            "set openvpn tunnel 2 authentication sha1",
                            "set openvpn tunnel 2 compress_enable false"
                            ]
        for command in config_commands:
            output = send_command_wo(shell, 'status route')
            if "OK" in output:
                print(command, "success")
            else:
                print(command, "failed")
                break
    finally:
        # Close the SSH connection
        ssh_client.close()
    return 
    
# Router details
host = "10.8.0.9"  # Replace with Robustel router IP
port = 22         # Default SSH port
username = "etelriyad"
password = "Reachlink@08"

# File details
local_file = "robustel1.ovpn"  # File to upload
remote_path = "robustel1.ovpn"  # Destination on router

try:
    # Create an SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the router
    ssh.connect(host, port, username, password)
    print("Connected to Robustel router.")

    # Open SFTP session
    sftp = ssh.open_sftp()

    # Upload file
    sftp.put(local_file, remote_path)
    print(f"File uploaded to {remote_path}")

    # Close connections
    sftp.close()
    ssh.close()
    print("Connection closed.")
except Exception as e:
    print(f"Error: {e}")
